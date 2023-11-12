---
title: "Spring Security"
subtitle: "Part 1: Authentication"
date: 2022-03-28T18:14:37+02:00
author: Eric Armbruster
tags: 
- Java
- Spring
- Spring Security
- Authentication
- JWT
- CORS
- XSRF
categories:
- CyberSec
---

# Securing a Spring Boot Web Application

Recently I had the chance to work on the authentication and authorization mechanisms for a simple Delivery application that we had to build in the Advanced Topics of Software Engineering class at TUM. This post is intended merely as a write-up of the most important steps that were required to fulfill the task. As a consequence, not everything here will be according to best practices.

## Authentication

To securely authenticate users after login we use JWTs (JSON Web Tokens). These tokens consist of three parts. The *header*, the *payload* and the *signature*. The header stores
### Creating the Authentication Controller

In a first step, create a controller class such as the `AuthController` below that defines a login, a logout and an endpoint for retrieving a CSRF token (we will see later why this last one is required).

```Java
@RestController
@RequestMapping("/api/v1/authentication/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(
        @RequestBody Credentials credentials, 
        HttpServletResponse response) {
        
        return authService.authenticateUser(credentials, response);
    }

    @PostMapping("/logout")
    public void logout(HttpServletResponse response) {
        authService.logout(response);
    }

}
```

The structure of the controller is quite simple, we only have to forward the request data to the respective methods in `AuthService`. The `HttpServletResponse` object is required to have access to HTTP header data in the `AuthService`. 

Also note that we use POST requests for both login and logout requests. A login POST request is more secure than a login GET request, as we avoid sending the login credentials in the URL, which could be stored **unencrypted** in the browser history [1]. POST is also recommended for logout, as the browser might prefetch links with GET and log users out inadvertently [2].

### The Authentication Service

Next, we create the `AuthService`, which is responsible for performing the actual authentication. 

```Java
@Service
public class AuthService {

    public static final String JWT_COOKIE_KEY = "jwt";

    private final AuthenticationManager authManager;
    private final MongoUserDetailsService mongoUserDetailsService;
    private final JwtUtils jwtUtils;
    private final CookieConfig cookieConfig;

    @Autowired
    public AuthService(
            AuthenticationManager authManager,
            MongoUserDetailsService mongoUserDetailsService,
            JwtUtils jwtUtils,
            CookieConfig cookieConfig) {
        this.authManager = authManager;
        this.mongoUserDetailsService = mongoUserDetailsService;
        this.jwtUtils = jwtUtils;
        this.cookieConfig = cookieConfig;
    }

    public ResponseEntity<String> authenticateUser(Credentials credentials, HttpServletResponse response) {
        String username = credentials.getEmail();
        String password = credentials.getPassword();

        AuthenticatedUser authenticatedUser = mongoUserDetailsService.loadUserByUsername(username);

        UsernamePasswordAuthenticationToken upat =
                new UsernamePasswordAuthenticationToken(authenticatedUser, password);

        try {
            var auth = authManager.authenticate(upat);
            SecurityContextHolder.getContext().setAuthentication(auth);

            final String jwt = jwtUtils.generateToken(authenticatedUser);
            var cookie = cookieConfig.createCookie(JWT_COOKIE_KEY, jwt);

            response.addCookie(cookie);
            return ResponseEntity.ok(jwt);
        } catch (BadCredentialsException badCredentialsException) {
            return new ResponseEntity<>(
                    "Email or password is incorrect",
                    HttpStatus.BAD_REQUEST
            );
        }
    }

    public void logout(HttpServletResponse response) {
        Cookie removeCookie = new Cookie(JWT_COOKIE_KEY, "");
        removeCookie.setPath("/");
        response.addCookie(removeCookie);
    }
}
```

Let's break down `authenticateUser(...)` line by line. First we extract, `username` and `password` from the `Credentials` object (a POJO). 

```Java
String username = credentials.getEmail();
String password = credentials.getPassword();
```

Next, we use our Mongo database service `MongoUserDetailsService` to load the `UserDetails` (essentially password, username and authorities, i.e. granted access rights).

```
AuthenticatedUser authenticatedUser = mongoUserDetailsService.loadUserByUsername(username);
```

Here is also the code for the `MongoUserDetailsService`:

```Java
@Component
public class MongoUserDetailsService implements UserDetailsService {


    private final UserRepository userRepository;

    @Autowired
    public MongoUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public AuthenticatedUser loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            throw new UsernameNotFoundException(email);
        }

        User user = userOpt.get();
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));

        return new AuthenticatedUser(user.getId(), user.getEmail(), user.getPassword(), authorities);
    }
}
```

This service first retrieves the user from the repository. Afterwards, we check whether the user exists. If not, we return an error, otherwise, we store the retrieved data in the `AuthenticatedUser` object.

Next, Spring requires a token object that stores the authentication principal 
we wish to authenticate (essentially another word for the user) and the password we got **from the request**.

```Java
UsernamePasswordAuthenticationToken upat =
    new UsernamePasswordAuthenticationToken(authenticatedUser, password);
```

Then, we perform the actual authentication by calling `authenticate` on the Spring `AuthenticationManager` object.
This method hashes the password from the request and compares it against the one we retrieved from the database (currently stored in `authenticatedUser`). As this might fail when the user entered a wrong password, we need to surround it with a `try-catch` statement and return an error message.

```Java
try {
   var auth = authManager.authenticate(upat);
   ...
} catch (BadCredentialsException badCredentialsException) {
    return new ResponseEntity<>(
        "Email or password is incorrect",
        HttpStatus.BAD_REQUEST
    );
}
```

With this we tell Spring to actually use the authenticated principal in the context of the current request.

```Java
SecurityContextHolder.getContext().setAuthentication(auth);
```

Finally, we create a JWT for the authenticated user, which is stored as a session cookie in the 
user's browser by adding it to the header of the response.

```Java
final String jwt = jwtUtils.generateToken(authenticatedUser);
var cookie = cookieConfig.createCookie(JWT_COOKIE_KEY, jwt);

response.addCookie(cookie);
return ResponseEntity.ok(jwt);
```

The `JwtUtils` class will be shown below when discussing the authentication for subsequent requests after login. 

The `CookieConfig` is a small helper that lets us create Cookies. Cookies have a `MaxAge` after which the cookie will be deleted by the browser and the user needs to log in again. The `HTTPOnly` flag is set to reduce the risk of a XSS vulnerability, as it prevents leaking the cookie to third parties [3]. However, please note this does not prevent `XSRF`. The `Path` attribute of a cookie defines on which paths the browser should include the cookie in the request. For instance, when you set `Path=/users` only requests to `/users` or subdirectories like `/users/stuff` will include the cookie. In our case we set it to `Path=/` as every path under the domain belongs to our application, and we thus always want to send the cookie.

TODO secure attribute

```Java
@Configuration
public class CookieConfig {

    public Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);

        cookie.setMaxAge((int) Duration.ofHours(5).toMillis());

        cookie.setSecure(false);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        return cookie;
    }
}
```

The logout method, which is also part of the `AuthService`, is much simpler. 
We only need to remove the value of the cookie by returning a cookie with an empty cookie value in the HTTP response header.
Also, name **and path** must exactly match with those set earlier in the `CookieConfig`. 

```Java
public void logout(HttpServletResponse response) {
    Cookie removeCookie = new Cookie(JWT_COOKIE_KEY, "");
    removeCookie.setPath("/");
    response.addCookie(removeCookie);
}
```

### JWTFilter

Subsequent requests are authenticated with JWT. To implement this authentication mechanism we create a `JwtFilter` class. This filter is executed every time before entering any methods in controllers.

```Java
@Component
public class JwtFilter extends OncePerRequestFilter {

    public static final String JWT_COOKIE_KEY = "jwt";

    private final JwtUtils jwtUtils;

    @Autowired
    public JwtFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        if (request.getCookies() != null) {
            Optional<Cookie> optCookie = Arrays.stream(request.getCookies())
                    .filter(c -> c.getName().equals(JWT_COOKIE_KEY))
                    .findAny();
            if (optCookie.isPresent()) {
                Cookie cookie = optCookie.get();

                String token = cookie.getValue();

                // Always first validate the token, then use the content
                if (jwtUtils.validateToken(token)) {
                    String userName = jwtUtils.extractUsername(token);
                    String userId = jwtUtils.extractUserId(token);

                    if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                        var authorities = jwtUtils.extractRole(token);
                        AuthenticatedUser authenticatedUser = new AuthenticatedUser(userId, userName, "", authorities);

                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                new UsernamePasswordAuthenticationToken(authenticatedUser, null, authorities);
                        usernamePasswordAuthenticationToken
                                .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    }
                }
            }
        }
        filterChain.doFilter(request, response);
    }

}
```

The filter first extracts the JWT from the cookie, then validates the token. Validating a token means checking whether the token has been signed with our secret signing key and whether the token is expired or not. 
Afterwards, the user data is extracted from the JWT and the user is set as authenticated for this request.

**Important:** Always validate the token first before extracting and using unauthenticated data, as this could lead to serious vulnerabilities

Finally, we also discuss the `JwtUtils` service. This class offers convenience methods for extracting claims, validating tokens, and generating tokens. The secret is injected here via a `@Value` annotation, i.e. either via an environment variable or the `application.yml` file. More appropriately it should be brought in via a more secure method e.g. Docker secrets [4]. Such environment variables and config files are problematic as they leave secrets unencrypted on disk, or might even be the cause of an accidental check-in of a secret into a VCS.

```Java
@Service
public class JwtUtils {

    private static final String ISSUER = "ase33project";
    private static final String ROLES = "roles";
    private static final String USER_ID = "user-id";

    @Value("${ase.jwt.token.secret}")
    private String secret;

    public String extractUserId(String token) {
        return extractClaim(token, c -> (String) c.get(USER_ID));
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Collection<? extends SimpleGrantedAuthority> extractRole(String token) {
        return ((Collection<LinkedHashMap<String, String>>) extractAllClaims(token).get(ROLES)).stream()
                .flatMap(l -> l.values().stream()).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return loadJwtParser()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            return true;
        }
    }

    public String generateToken(AuthenticatedUser user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(ROLES, user.getAuthorities());
        claims.put(USER_ID, user.getUserId());

        return createToken(claims, user.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuer(ISSUER)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + Duration.ofHours(5).toMillis()))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private JwtParser loadJwtParser() {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build();
    }

    public Boolean validateToken(String token) {
        return verifyJwtSignature(token);
    }

    public boolean verifyJwtSignature(String token) {
        return loadJwtParser().isSigned(token) && !isTokenExpired(token);
    }

    private Key getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
```

### Security Configuration

A few more steps are required to finish implementing authentication for a Spring application. We need to create our own security config, which is essentially the place where you can find security related configurations in your Spring application.

In the `configure(...)` method we define which URL paths require authentication. 
We use an allow list (formerly known as whitelist) to enable authentication for all endpoints except those listed. In this case we require authentication for this service for all endpoints except those listed under `/api/v1/authentication/**`, as calls to these endpoints naturally need to be possible from an unauthenticated user.

Furthermore, the config registers the `JwtFilter` from above, 
informs Spring of the `UserDetailsService` we use, exposes the `AuthenticationManager` and the password encoder that is 
used to hash passwords (e.g. when the user is authenticated).

In this case the `BCryptPasswordEncoder` is exposed, which means bcrypt hashing function is used, but Spring also supports other 
password encoders such as the `Argon2PasswordEncoder`, which should be preferred as it uses the more secure argon2 password hasing function.

```Java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final MongoUserDetailsService mongoUserDetailsService;
    private final JwtFilter jwtFilter;

    @Autowired
    public SecurityConfig(MongoUserDetailsService mongoUserDetailsService, JwtFilter jwtFilter) {
        this.mongoUserDetailsService = mongoUserDetailsService;
        this.jwtFilter = jwtFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.cors()
                .and()
                .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .authorizeRequests()
                    .antMatchers("/api/v1/authentication/auth/**").permitAll()
                    .anyRequest().authenticated() // Require authentication on all endpoints except those listed above
                .and()
                .sessionManagement().disable()
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        // @formatter:on
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.userDetailsService(mongoUserDetailsService);
    }

}
```

#### Cross-Origin Resource Sharing

Cross-Origin Resource Sharing

```Java
@Configuration
@EnableWebMvc
public class CorsConfig implements WebMvcConfigurer {

    @Value("${ase.cors.allowed-origin}")
    private String allowedOrigin;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowCredentials(true)
                .allowedOriginPatterns(allowedOrigin)
                .allowedMethods("*")
                .allowedHeaders("*")
                .exposedHeaders("Set-Cookie");
    }

}
```

#### CSRF Tokens


```Java
@GetMapping("/csrf")
public String csrf() {
    return "Please read the CSRF token from the response header";
}
```

## References

- [1] [Auth: Why HTTP POST?](https://medium.com/@brockmrohloff_12324/auth-why-http-post-7c4da662cfa2)
- [2] [Should Logging Out Be a GET or POST?](https://www.baeldung.com/logout-get-vs-post)
- [3] [HttpOnly](https://owasp.org/www-community/HttpOnly)
- [4] [Introducing Docker Secrets Management](https://www.docker.com/blog/docker-secrets-management/)
