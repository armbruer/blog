---
title: "Spring Security"
subtitle: "Part 2: Fine-Grained Authorization"
author: Eric Armbruster
date: 2022-03-29T14:56:13+02:00
tags: 
- Java
- Spring
- Spring Security
- Authorization
categories:
- Security Engineering
---

# Fine-Grained Authorization with Spring Boot

Spring offers many methods for checking authorization. In this short blog post I will focus on 
checking authorization at method-level and at the level of individual users.

## Method-Level Authorization

First, we need to enable `@PreAuthorize` and `@PostAuthorize` 
annotations which are required for checking method-level security, by adding `@EnableGlobalMethodSecurity(prePostEnabled = true)` to a `@Configuration` bean that extends `GlobalMethodSecurityConfiguration`.

```Java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
}
```

### Role checking with @PreAuthorize

Now we can make use of Spring Security's DSL to check whether the roles are fulfilled at individual methods:

```Java
@PreAuthorize("hasRole('DISPATCHER')")
@DeleteMapping("{id}")
public void deleteUser(@PathVariable String id) {
    ...
}
```

### Creating our own annotations for each role

If we do not like having to type at each method `hasRole('ROLENAME')` we could also create our own annotation like this:

```Java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('DISPATCHER')")
public @interface IsDispatcher {
}
```

With this version typos can only occur where we define the annotation. The only downside is that potentially a lot of annotation classes need to be created.

### Multirole checking

Checking multiple roles works very similar to checking a single role. Just use `hasAnyRole`:

```Java
@PreAuthorize("hasAnyRole('DELIVERER, DISPATCHER')")
@GetMapping("{id}")
public Delivery findDeliveryById(@PathVariable String id) {
    ...
}
```

### What about @PostAuthorize?

I would generally recommend avoiding this annotation altogether, as it only checks authorization **after** the execution of the method body.

## Checking authorization at the level of individual users using JWT

In the previous blog post JWT authentication was shown without explaining the need for including a user ID in the JWT token. We will show these parts now again and explain how we can use them to check whether individual users are authorized to access certain endpoints.

### Extend JWT authentication by user id

This is an extract of the `JWTUtils` that shows how we can put the user id into the token.

```Java
public String generateToken(AuthenticatedUser user) {
    Map<String, Object> claims = new HashMap<>();
    claims.put(ROLES, user.getAuthorities());
    claims.put(USER_ID, user.getUserId());

    return createToken(claims, user.getUsername());
}
```

Of course, we also need to extract it then again in the filter:

```Java
@Override
protected void doFilterInternal(HttpServletRequest request,
                                HttpServletResponse response,
                                FilterChain filterChain)
        throws ServletException, IOException {
    ...

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
    
    ...
}
```

The result is stored in a `AuthenticatedUser` object that is a simple subclass of Spring's `UserDetails` class.
The `AuthenticatedUser` object is then stored in the `UsernamePasswordAuthenticationToken` which in turn is used to 
set the authentication with the `SecurityContextHolder`.


```Java
@Getter
public class AuthenticatedUser extends org.springframework.security.core.userdetails.User {

    private final String userId;

    public AuthenticatedUser(String userId, String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.userId = userId;
    }

}
```

### Implement user-level authorization checks

Now we can check the authorization at user level as follows. First, we create some static helper methods:

```Java
public class AuthUtils {

    public static AuthenticatedUser getAuthenticatedUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AuthenticatedUser) {
            return (AuthenticatedUser) auth.getPrincipal();
        }

        // auth must be non-null and the authenticated user must be set due to the filter
        throw new InternalServerError("Is the JwtFilter enabled?");
    }


    public static boolean isAuthenticatedAs(UserRole role) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            return auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_" + role.name()));
        }

        // auth must be non-null due to the filter
        throw new InternalServerError("Is the JwtFilter enabled?");
    }

}
```

In these methods we can safely assume that the `Authentication` object retrieved from the security context must be non-null as it is set in our filter. If it is not set, we throw an `InternalServerError` as this indicates that we forgot to enable the `JwtFilter`.
Also, due to the same assumption, we can cast to `AuthenticatedUser`.

Finally, we can perform the actual authorization check as follows:

```Java
@GetMapping("{id}")
public Delivery findDeliveryById(@PathVariable String id) {
    var delivery = deliveryService.findDeliveryByIdOrElseThrow(id);
    var authenticatedUser = getAuthenticatedUser();

    if (isAuthenticatedAs(UserRole.USER) && authenticatedUser.getUserId().equals(delivery.getTargetCustomer())) {
        return delivery;
    } else if (isAuthenticatedAs(UserRole.DELIVERER) && authenticatedUser.getUserId().equals(delivery.getDeliverer())) {
        return delivery;
    } else if (isAuthenticatedAs(UserRole.DISPATCHER)) {
        return delivery;
    }

    throw new AccessDeniedException("User is not allowed to view this delivery");
}
```

## Discussion