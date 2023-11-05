---
title: "ETFOptimizer: A Portfolio Optimization Tool for ETFs"
date: 2023-11-05T13:38:23+01:00
draft: false
---

## Motivation and Goals

For the interdisciplinary project (IDP), Ruben and I worked on a portfolio optimization tool for the Chair of Financial Management and Capital Markets at TUM. 
Our motivation for creating an [EtfOptimizer](https://github.com/armbruer/etfoptimizer) tool was as follows:

- ETFs are a low cost and comparatively low risk investment option with good returns
- Abundance of ETFs on the market: complicates investment decisions
- An optimization can:
    - Take investor preferences into account
    - Asset categories
    - Investment amount
    - Risk tolerance
    - Preferred return

We had the following goals in mind while designing and implementing the etfoptimizer tool:

- Improve portfolio diversification
- Help make an informed decision
- Simplify the investment process for the average investor 

## Background

The core idea is that the tool calculates *efficient portfolios*. A portfolio is called efficient when it either has the maximum return for a set level of risk or the minimum risk for a set level of return. This efficient frontier of portfolios is also shown in the figure below [1]. 
For the portfolio optimization theory, the reader is referred to [2-5] and to our [documentation](https://github.com/armbruer/etfoptimizer/blob/main/docs/report.pdf), which contains a very short summary of the most important bits. In general these problems are formulated as convex optimization problems to work well with optimizers like [Gurobi](https://www.gurobi.com/).

[Efficient Frontier](/images/etfoptimizer/efficient_frontier_white.png)

## Implementation

We scraped the static etf data mostly from [justetf.com](https://www.justetf.com) and stored it in a PostgreSQL database. For the dynamic price data we had access to [Refinitiv](https://www.refinitiv.com/en) and also stored the data in our PostgreSQL database.

After some data data cleansing and mangling, we brought the data into a format that works well with PyPortfolioOpt, which conveniently already has implemented many of the optimization methods mentioned in [2-5].

## Results

The images below give you an impression of how the tool works. First, the user needs to select which categories he or she is interested in.

[etf optimizer categories selection](/images/etfoptimizer/categories.png)

and choose what kind of optimization the user is interested in minimize risk for a set level of return of maximize return for a set level of risk and of course the amount of the investment.

The tool then outputs several core performance measures of the resulting optimized portfolio and the weighted allocation suggestion of the optimizer:

[portfolio_performance](/images/etfoptimizer/results.png)

Finally we also show how the portfolio would have performed on the historic data of the past seven years by comparing the optimized portfolio against the MSCI worlds index.

[optimized_portfolio](/images/etfoptimizer/evaluation.png)

## References

- [1] https://raw.githubusercontent.com/robertmartin8/PyPortfolioOpt/master/media/efficient_frontier_white.png
- [2] H. Markowitz, “Portfolio selection,” 1952.
- [3] J. Estrada, “Mean-semivariance optimization: A heuristic approach,” Journal of
Applied Finance (Formerly Financial Practice and Education), vol. 18, no. 1, 2008.
- [4] O. Ledoit and M. Wolf, “Improved estimation of the covariance matrix of stock
returns with an application to portfolio selection,” Journal of empirical finance,
vol. 10, no. 5, pp. 603–621, 2003.
- [5] O. Ledoit and M. Wolf, “Honey, i shrunk the sample covariance matrix,” The
Journal of Portfolio Management, vol. 30, no. 4, pp. 110–119, 2004.
