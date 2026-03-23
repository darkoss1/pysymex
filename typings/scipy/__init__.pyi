"""Type stubs for SciPy — Scientific computing library.

SciPy provides algorithms for optimization, integration, interpolation,
linear algebra, statistics, and more. These stubs cover the modules
used in pysymex and common statistical operations.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Generic, Literal, Protocol, TypeVar, overload

import numpy as np
import numpy.typing as npt

# ── Type Variables and Aliases ─────────────────────────────────────

_T = TypeVar("_T")
_T_co = TypeVar("_T_co", covariant=True)
_ScalarType = TypeVar("_ScalarType", bound=np.generic)
_FloatType = TypeVar("_FloatType", bound=np.floating[npt.NBitBase])
_IntType = TypeVar("_IntType", bound=np.integer[npt.NBitBase])

# Array-like types
_ArrayLikeFloat = float | Sequence[float] | npt.NDArray[np.floating[npt.NBitBase]]
_ArrayLikeInt = int | Sequence[int] | npt.NDArray[np.integer[npt.NBitBase]]
_ArrayLike = int | float | complex | Sequence[int | float | complex] | npt.NDArray[np.generic]

# Result array types
_FloatArray = npt.NDArray[np.floating[npt.NBitBase]]
_IntArray = npt.NDArray[np.integer[npt.NBitBase]]
_Float = np.floating[npt.NBitBase]
_Int = np.integer[npt.NBitBase]

# Common parameter types
_NanPolicy = Literal["propagate", "raise", "omit"]
_Alternative = Literal["two-sided", "less", "greater"]
_RandomState = int | np.random.Generator | np.random.RandomState | None

# ══════════════════════════════════════════════════════════════════════════════
# scipy.stats — Statistical distributions and functions
# ══════════════════════════════════════════════════════════════════════════════

class stats:
    """Statistical distributions and functions."""

    # ── Continuous distributions base ──────────────────────────────────────

    class rv_continuous:
        """Base class for continuous random variables."""

        def pdf(
            self,
            x: _ArrayLikeFloat,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> _FloatArray | _Float: ...

        def logpdf(
            self,
            x: _ArrayLikeFloat,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> _FloatArray | _Float: ...

        def cdf(
            self,
            x: _ArrayLikeFloat,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> _FloatArray | _Float: ...

        def logcdf(
            self,
            x: _ArrayLikeFloat,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> _FloatArray | _Float: ...

        def sf(
            self,
            x: _ArrayLikeFloat,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> _FloatArray | _Float: ...

        def logsf(
            self,
            x: _ArrayLikeFloat,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> _FloatArray | _Float: ...

        def ppf(
            self,
            q: _ArrayLikeFloat,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> _FloatArray | _Float: ...

        def isf(
            self,
            q: _ArrayLikeFloat,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> _FloatArray | _Float: ...

        def rvs(
            self,
            *args: float,
            loc: float = 0,
            scale: float = 1,
            size: int | tuple[int, ...] | None = None,
            random_state: _RandomState = None,
        ) -> _FloatArray | _Float: ...

        def moment(
            self,
            order: int,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> float: ...

        def stats(
            self,
            *args: float,
            loc: float = 0,
            scale: float = 1,
            moments: str = "mv",
        ) -> tuple[float, ...]: ...

        def entropy(self, *args: float, loc: float = 0, scale: float = 1) -> float: ...
        def mean(self, *args: float, loc: float = 0, scale: float = 1) -> float: ...
        def median(self, *args: float, loc: float = 0, scale: float = 1) -> float: ...
        def var(self, *args: float, loc: float = 0, scale: float = 1) -> float: ...
        def std(self, *args: float, loc: float = 0, scale: float = 1) -> float: ...

        def interval(
            self,
            confidence: float,
            *args: float,
            loc: float = 0,
            scale: float = 1,
        ) -> tuple[float, float]: ...

        def support(self, *args: float, loc: float = 0, scale: float = 1) -> tuple[float, float]: ...

        def fit(
            self,
            data: _ArrayLikeFloat,
            *args: float,
            floc: float | None = None,
            fscale: float | None = None,
            **kwargs: float,
        ) -> tuple[float, ...]: ...

        def fit_loc_scale(self, data: _ArrayLikeFloat, *args: float) -> tuple[float, float]: ...

        def expect(
            self,
            func: Callable[[_ArrayLikeFloat], _ArrayLikeFloat] | None = None,
            args: tuple[float, ...] = (),
            loc: float = 0,
            scale: float = 1,
            lb: float | None = None,
            ub: float | None = None,
            conditional: bool = False,
        ) -> float: ...

        def freeze(self, *args: float, **kwargs: float) -> rv_continuous: ...

    # ── Beta distribution ──────────────────────────────────────────────────

    class beta_gen(rv_continuous):
        """Beta distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, a: float, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def logpdf(x: _ArrayLikeFloat, a: float, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, a: float, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def logcdf(x: _ArrayLikeFloat, a: float, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def sf(x: _ArrayLikeFloat, a: float, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, a: float, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def isf(q: _ArrayLikeFloat, a: float, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(a: float, b: float, loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...
        @staticmethod
        def stats(a: float, b: float, loc: float = 0, scale: float = 1, moments: str = "mv") -> tuple[float, ...]: ...
        @staticmethod
        def entropy(a: float, b: float, loc: float = 0, scale: float = 1) -> float: ...
        @staticmethod
        def mean(a: float, b: float, loc: float = 0, scale: float = 1) -> float: ...
        @staticmethod
        def var(a: float, b: float, loc: float = 0, scale: float = 1) -> float: ...
        @staticmethod
        def std(a: float, b: float, loc: float = 0, scale: float = 1) -> float: ...
        @staticmethod
        def interval(confidence: float, a: float, b: float, loc: float = 0, scale: float = 1) -> tuple[float, float]: ...
        @staticmethod
        def fit(data: _ArrayLikeFloat, *args: float, floc: float | None = None, fscale: float | None = None, **kwargs: float) -> tuple[float, float, float, float]: ...

    beta: beta_gen

    # ── Normal distribution ────────────────────────────────────────────────

    class norm_gen(rv_continuous):
        """Normal (Gaussian) distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def logpdf(x: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def sf(x: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def isf(q: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...
        @staticmethod
        def fit(data: _ArrayLikeFloat, **kwargs: float) -> tuple[float, float]: ...

    norm: norm_gen

    # ── Uniform distribution ───────────────────────────────────────────────

    class uniform_gen(rv_continuous):
        """Uniform distribution on [loc, loc + scale]."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...

    uniform: uniform_gen

    # ── Exponential distribution ───────────────────────────────────────────

    class expon_gen(rv_continuous):
        """Exponential distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...

    expon: expon_gen

    # ── Gamma distribution ─────────────────────────────────────────────────

    class gamma_gen(rv_continuous):
        """Gamma distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, a: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, a: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, a: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(a: float, loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...

    gamma: gamma_gen

    # ── Chi-squared distribution ───────────────────────────────────────────

    class chi2_gen(rv_continuous):
        """Chi-squared distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, df: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, df: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, df: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(df: float, loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...

    chi2: chi2_gen

    # ── Student's t distribution ───────────────────────────────────────────

    class t_gen(rv_continuous):
        """Student's t distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, df: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, df: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, df: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(df: float, loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...

    t: t_gen

    # ── F distribution ─────────────────────────────────────────────────────

    class f_gen(rv_continuous):
        """F distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, dfn: float, dfd: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, dfn: float, dfd: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, dfn: float, dfd: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(dfn: float, dfd: float, loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...

    f: f_gen

    # ── Log-normal distribution ────────────────────────────────────────────

    class lognorm_gen(rv_continuous):
        """Log-normal distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, s: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, s: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, s: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(s: float, loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...

    lognorm: lognorm_gen

    # ── Weibull distribution ───────────────────────────────────────────────

    class weibull_min_gen(rv_continuous):
        """Weibull minimum distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, c: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, c: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, c: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(c: float, loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...

    weibull_min: weibull_min_gen

    # ── Pareto distribution ────────────────────────────────────────────────

    class pareto_gen(rv_continuous):
        """Pareto distribution."""

        @staticmethod
        def pdf(x: _ArrayLikeFloat, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(x: _ArrayLikeFloat, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, b: float, loc: float = 0, scale: float = 1) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(b: float, loc: float = 0, scale: float = 1, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _FloatArray | _Float: ...

    pareto: pareto_gen

    # ── Discrete distributions ─────────────────────────────────────────────

    class rv_discrete:
        """Base class for discrete random variables."""

        def pmf(self, k: _ArrayLikeInt, *args: float, loc: int = 0) -> _FloatArray | _Float: ...
        def logpmf(self, k: _ArrayLikeInt, *args: float, loc: int = 0) -> _FloatArray | _Float: ...
        def cdf(self, k: _ArrayLikeInt, *args: float, loc: int = 0) -> _FloatArray | _Float: ...
        def sf(self, k: _ArrayLikeInt, *args: float, loc: int = 0) -> _FloatArray | _Float: ...
        def ppf(self, q: _ArrayLikeFloat, *args: float, loc: int = 0) -> _IntArray | _Int: ...
        def isf(self, q: _ArrayLikeFloat, *args: float, loc: int = 0) -> _IntArray | _Int: ...
        def rvs(self, *args: float, loc: int = 0, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _IntArray | _Int: ...
        def mean(self, *args: float, loc: int = 0) -> float: ...
        def var(self, *args: float, loc: int = 0) -> float: ...
        def std(self, *args: float, loc: int = 0) -> float: ...
        def entropy(self, *args: float, loc: int = 0) -> float: ...
        def stats(self, *args: float, loc: int = 0, moments: str = "mv") -> tuple[float, ...]: ...

    # ── Binomial distribution ──────────────────────────────────────────────

    class binom_gen(rv_discrete):
        """Binomial distribution."""

        @staticmethod
        def pmf(k: _ArrayLikeInt, n: int, p: float, loc: int = 0) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(k: _ArrayLikeInt, n: int, p: float, loc: int = 0) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, n: int, p: float, loc: int = 0) -> _IntArray | _Int: ...
        @staticmethod
        def rvs(n: int, p: float, loc: int = 0, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _IntArray | _Int: ...

    binom: binom_gen

    # ── Poisson distribution ───────────────────────────────────────────────

    class poisson_gen(rv_discrete):
        """Poisson distribution."""

        @staticmethod
        def pmf(k: _ArrayLikeInt, mu: float, loc: int = 0) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(k: _ArrayLikeInt, mu: float, loc: int = 0) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, mu: float, loc: int = 0) -> _IntArray | _Int: ...
        @staticmethod
        def rvs(mu: float, loc: int = 0, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _IntArray | _Int: ...

    poisson: poisson_gen

    # ── Geometric distribution ─────────────────────────────────────────────

    class geom_gen(rv_discrete):
        """Geometric distribution."""

        @staticmethod
        def pmf(k: _ArrayLikeInt, p: float, loc: int = 0) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(k: _ArrayLikeInt, p: float, loc: int = 0) -> _FloatArray | _Float: ...
        @staticmethod
        def ppf(q: _ArrayLikeFloat, p: float, loc: int = 0) -> _IntArray | _Int: ...
        @staticmethod
        def rvs(p: float, loc: int = 0, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _IntArray | _Int: ...

    geom: geom_gen

    # ── Bernoulli distribution ─────────────────────────────────────────────

    class bernoulli_gen(rv_discrete):
        """Bernoulli distribution."""

        @staticmethod
        def pmf(k: _ArrayLikeInt, p: float, loc: int = 0) -> _FloatArray | _Float: ...
        @staticmethod
        def cdf(k: _ArrayLikeInt, p: float, loc: int = 0) -> _FloatArray | _Float: ...
        @staticmethod
        def rvs(p: float, loc: int = 0, size: int | tuple[int, ...] | None = None, random_state: _RandomState = None) -> _IntArray | _Int: ...

    bernoulli: bernoulli_gen

    # ── Statistical test results ───────────────────────────────────────────

    class _TtestResult:
        statistic: float | _FloatArray
        pvalue: float | _FloatArray

    class _ChisquareResult:
        statistic: float | _FloatArray
        pvalue: float | _FloatArray

    class _KsResult:
        statistic: float
        pvalue: float

    class _PearsonrResult:
        statistic: float
        pvalue: float

    class _SpearmanrResult:
        correlation: float
        pvalue: float

    class _MannwhitneyuResult:
        statistic: float
        pvalue: float

    class _NormaltestResult:
        statistic: float | _FloatArray
        pvalue: float | _FloatArray

    # ── Statistical tests ──────────────────────────────────────────────────

    @staticmethod
    def ttest_ind(
        a: _ArrayLikeFloat,
        b: _ArrayLikeFloat,
        axis: int | None = 0,
        equal_var: bool = True,
        nan_policy: _NanPolicy = "propagate",
        permutations: int | None = None,
        random_state: _RandomState = None,
        alternative: _Alternative = "two-sided",
        trim: float = 0,
    ) -> _TtestResult: ...

    @staticmethod
    def ttest_rel(
        a: _ArrayLikeFloat,
        b: _ArrayLikeFloat,
        axis: int | None = 0,
        nan_policy: _NanPolicy = "propagate",
        alternative: _Alternative = "two-sided",
    ) -> _TtestResult: ...

    @staticmethod
    def ttest_1samp(
        a: _ArrayLikeFloat,
        popmean: float | _ArrayLikeFloat,
        axis: int | None = 0,
        nan_policy: _NanPolicy = "propagate",
        alternative: _Alternative = "two-sided",
    ) -> _TtestResult: ...

    @staticmethod
    def chisquare(
        f_obs: _ArrayLikeFloat,
        f_exp: _ArrayLikeFloat | None = None,
        ddof: int = 0,
        axis: int | None = 0,
    ) -> _ChisquareResult: ...

    @staticmethod
    def chi2_contingency(
        observed: _ArrayLikeFloat,
        correction: bool = True,
        lambda_: float | None = None,
    ) -> tuple[float, float, int, _FloatArray]: ...

    @staticmethod
    def kstest(
        rvs: _ArrayLikeFloat | str | Callable[..., _FloatArray],
        cdf: str | Callable[[_ArrayLikeFloat], _FloatArray] | _ArrayLikeFloat,
        args: tuple[float, ...] = (),
        N: int = 20,
        alternative: _Alternative = "two-sided",
        method: Literal["auto", "exact", "approx", "asymp"] = "auto",
    ) -> _KsResult: ...

    @staticmethod
    def ks_2samp(
        data1: _ArrayLikeFloat,
        data2: _ArrayLikeFloat,
        alternative: _Alternative = "two-sided",
        method: Literal["auto", "exact", "asymp"] = "auto",
    ) -> _KsResult: ...

    @staticmethod
    def pearsonr(x: _ArrayLikeFloat, y: _ArrayLikeFloat) -> _PearsonrResult: ...

    @staticmethod
    def spearmanr(
        a: _ArrayLikeFloat,
        b: _ArrayLikeFloat | None = None,
        axis: int | None = 0,
        nan_policy: _NanPolicy = "propagate",
        alternative: _Alternative = "two-sided",
    ) -> _SpearmanrResult: ...

    @staticmethod
    def kendalltau(
        x: _ArrayLikeFloat,
        y: _ArrayLikeFloat,
        initial_lexsort: bool = True,
        nan_policy: _NanPolicy = "propagate",
        method: Literal["auto", "asymptotic", "exact"] = "auto",
        variant: Literal["b", "c"] = "b",
        alternative: _Alternative = "two-sided",
    ) -> tuple[float, float]: ...

    @staticmethod
    def mannwhitneyu(
        x: _ArrayLikeFloat,
        y: _ArrayLikeFloat,
        use_continuity: bool = True,
        alternative: _Alternative = "two-sided",
        axis: int = 0,
        method: Literal["auto", "exact", "asymptotic"] = "auto",
    ) -> _MannwhitneyuResult: ...

    @staticmethod
    def normaltest(
        a: _ArrayLikeFloat,
        axis: int | None = 0,
        nan_policy: _NanPolicy = "propagate",
    ) -> _NormaltestResult: ...

    @staticmethod
    def shapiro(x: _ArrayLikeFloat) -> tuple[float, float]: ...

    # ── Descriptive statistics ─────────────────────────────────────────────

    class _DescribeResult:
        nobs: int
        minmax: tuple[float, float]
        mean: float
        variance: float
        skewness: float
        kurtosis: float

    @staticmethod
    def describe(
        a: _ArrayLikeFloat,
        axis: int | None = 0,
        ddof: int = 1,
        bias: bool = True,
        nan_policy: _NanPolicy = "propagate",
    ) -> _DescribeResult: ...

    @staticmethod
    def skew(
        a: _ArrayLikeFloat,
        axis: int | None = 0,
        bias: bool = True,
        nan_policy: _NanPolicy = "propagate",
    ) -> float | _FloatArray: ...

    @staticmethod
    def kurtosis(
        a: _ArrayLikeFloat,
        axis: int | None = 0,
        fisher: bool = True,
        bias: bool = True,
        nan_policy: _NanPolicy = "propagate",
    ) -> float | _FloatArray: ...

    class _ModeResult:
        mode: _FloatArray
        count: _IntArray

    @staticmethod
    def mode(
        a: _ArrayLikeFloat,
        axis: int | None = 0,
        nan_policy: _NanPolicy = "propagate",
        keepdims: bool = False,
    ) -> _ModeResult: ...

    @staticmethod
    def zscore(
        a: _ArrayLikeFloat,
        axis: int | None = 0,
        ddof: int = 0,
        nan_policy: _NanPolicy = "propagate",
    ) -> _FloatArray: ...

    @staticmethod
    def sem(
        a: _ArrayLikeFloat,
        axis: int | None = 0,
        ddof: int = 1,
        nan_policy: _NanPolicy = "propagate",
    ) -> float | _FloatArray: ...

    @staticmethod
    def iqr(
        x: _ArrayLikeFloat,
        axis: int | tuple[int, ...] | None = None,
        rng: tuple[float, float] = (25, 75),
        scale: float | str = 1.0,
        nan_policy: _NanPolicy = "propagate",
        interpolation: str = "linear",
        keepdims: bool = False,
    ) -> float | _FloatArray: ...

    @staticmethod
    def entropy(
        pk: _ArrayLikeFloat,
        qk: _ArrayLikeFloat | None = None,
        base: float | None = None,
        axis: int = 0,
    ) -> float | _FloatArray: ...

    @staticmethod
    def gmean(
        a: _ArrayLikeFloat,
        axis: int | None = 0,
        dtype: type[np.floating[npt.NBitBase]] | np.dtype[np.floating[npt.NBitBase]] | None = None,
        weights: _ArrayLikeFloat | None = None,
        nan_policy: _NanPolicy = "propagate",
    ) -> float | _FloatArray: ...

    @staticmethod
    def hmean(
        a: _ArrayLikeFloat,
        axis: int | None = 0,
        dtype: type[np.floating[npt.NBitBase]] | np.dtype[np.floating[npt.NBitBase]] | None = None,
        nan_policy: _NanPolicy = "propagate",
    ) -> float | _FloatArray: ...

    @staticmethod
    def trim_mean(
        a: _ArrayLikeFloat,
        proportiontocut: float,
        axis: int | None = 0,
    ) -> float | _FloatArray: ...


# ══════════════════════════════════════════════════════════════════════════════
# scipy.special — Special mathematical functions
# ══════════════════════════════════════════════════════════════════════════════

class special:
    """Special mathematical functions."""

    @staticmethod
    def gamma(z: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def gammaln(x: _ArrayLikeFloat) -> _FloatArray | _Float: ...

    @overload
    @staticmethod
    def factorial(n: int, exact: Literal[True]) -> int: ...
    @overload
    @staticmethod
    def factorial(n: _ArrayLikeInt, exact: Literal[False] = False) -> _FloatArray | _Float: ...

    @overload
    @staticmethod
    def comb(N: int, k: int, exact: Literal[True], repetition: bool = False) -> int: ...
    @overload
    @staticmethod
    def comb(N: _ArrayLikeInt, k: _ArrayLikeInt, exact: Literal[False] = False, repetition: bool = False) -> _FloatArray | _Float: ...

    @overload
    @staticmethod
    def perm(N: int, k: int, exact: Literal[True]) -> int: ...
    @overload
    @staticmethod
    def perm(N: _ArrayLikeInt, k: _ArrayLikeInt, exact: Literal[False] = False) -> _FloatArray | _Float: ...

    @staticmethod
    def beta(a: _ArrayLikeFloat, b: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def betaln(a: _ArrayLikeFloat, b: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def betainc(a: _ArrayLikeFloat, b: _ArrayLikeFloat, x: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def betaincinv(a: _ArrayLikeFloat, b: _ArrayLikeFloat, y: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def erf(z: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def erfc(x: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def erfinv(y: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def erfcinv(y: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def digamma(z: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def polygamma(n: int, x: _ArrayLikeFloat) -> _FloatArray | _Float: ...

    @overload
    @staticmethod
    def logsumexp(
        a: _ArrayLikeFloat,
        axis: int | tuple[int, ...] | None = None,
        b: _ArrayLikeFloat | None = None,
        keepdims: bool = False,
        return_sign: Literal[False] = False,
    ) -> _FloatArray | _Float: ...
    @overload
    @staticmethod
    def logsumexp(
        a: _ArrayLikeFloat,
        axis: int | tuple[int, ...] | None = None,
        b: _ArrayLikeFloat | None = None,
        keepdims: bool = False,
        return_sign: Literal[True] = ...,
    ) -> tuple[_FloatArray, _FloatArray]: ...

    @staticmethod
    def softmax(x: _ArrayLikeFloat, axis: int | None = None) -> _FloatArray: ...
    @staticmethod
    def log_softmax(x: _ArrayLikeFloat, axis: int | None = None) -> _FloatArray: ...
    @staticmethod
    def expit(x: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def logit(p: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def xlogy(x: _ArrayLikeFloat, y: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def xlog1py(x: _ArrayLikeFloat, y: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def rel_entr(x: _ArrayLikeFloat, y: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def entr(x: _ArrayLikeFloat) -> _FloatArray | _Float: ...
    @staticmethod
    def kl_div(x: _ArrayLikeFloat, y: _ArrayLikeFloat) -> _FloatArray | _Float: ...


# ══════════════════════════════════════════════════════════════════════════════
# scipy.sparse — Sparse matrices
# ══════════════════════════════════════════════════════════════════════════════

class sparse:
    """Sparse matrix classes and functions."""

    _SparseFormat = Literal["csr", "csc", "coo", "lil", "dia", "bsr", "dok"]

    class spmatrix(Generic[_ScalarType]):
        """Base class for sparse matrices."""

        @property
        def shape(self) -> tuple[int, int]: ...
        @property
        def dtype(self) -> np.dtype[_ScalarType]: ...
        @property
        def ndim(self) -> Literal[2]: ...
        @property
        def nnz(self) -> int: ...

        def toarray(self) -> npt.NDArray[_ScalarType]: ...
        def tocsr(self) -> csr_matrix[_ScalarType]: ...
        def tocsc(self) -> csc_matrix[_ScalarType]: ...
        def tocoo(self) -> coo_matrix[_ScalarType]: ...
        def todense(self) -> np.matrix[tuple[int, int], np.dtype[_ScalarType]]: ...
        def tolil(self) -> lil_matrix[_ScalarType]: ...
        def todia(self) -> dia_matrix[_ScalarType]: ...
        def tobsr(self) -> bsr_matrix[_ScalarType]: ...
        def todok(self) -> dok_matrix[_ScalarType]: ...

        def transpose(self, axes: tuple[int, int] | None = None, copy: bool = False) -> spmatrix[_ScalarType]: ...
        def conj(self, copy: bool = True) -> spmatrix[_ScalarType]: ...
        def conjugate(self, copy: bool = True) -> spmatrix[_ScalarType]: ...
        def copy(self) -> spmatrix[_ScalarType]: ...

        def dot(self, other: npt.NDArray[np.generic] | spmatrix[np.generic]) -> npt.NDArray[np.generic] | spmatrix[np.generic]: ...
        def multiply(self, other: npt.NDArray[np.generic] | spmatrix[np.generic] | float) -> spmatrix[np.generic]: ...
        def power(self, n: int, dtype: np.dtype[_ScalarType] | None = None) -> spmatrix[_ScalarType]: ...

        def sum(self, axis: int | None = None, dtype: np.dtype[_ScalarType] | None = None, out: npt.NDArray[_ScalarType] | None = None) -> npt.NDArray[_ScalarType] | _ScalarType: ...
        def mean(self, axis: int | None = None, dtype: np.dtype[np.floating[npt.NBitBase]] | None = None, out: _FloatArray | None = None) -> _FloatArray | _Float: ...
        def diagonal(self, k: int = 0) -> npt.NDArray[_ScalarType]: ...
        def trace(self, offset: int = 0) -> _ScalarType: ...
        def nonzero(self) -> tuple[npt.NDArray[np.intp], npt.NDArray[np.intp]]: ...

        def __add__(self, other: spmatrix[np.generic] | npt.NDArray[np.generic] | float) -> spmatrix[np.generic]: ...
        def __radd__(self, other: spmatrix[np.generic] | npt.NDArray[np.generic] | float) -> spmatrix[np.generic]: ...
        def __sub__(self, other: spmatrix[np.generic] | npt.NDArray[np.generic] | float) -> spmatrix[np.generic]: ...
        def __rsub__(self, other: spmatrix[np.generic] | npt.NDArray[np.generic] | float) -> spmatrix[np.generic]: ...
        def __mul__(self, other: float | npt.NDArray[np.generic]) -> spmatrix[np.generic] | npt.NDArray[np.generic]: ...
        def __rmul__(self, other: float | npt.NDArray[np.generic]) -> spmatrix[np.generic] | npt.NDArray[np.generic]: ...
        def __matmul__(self, other: npt.NDArray[np.generic] | spmatrix[np.generic]) -> npt.NDArray[np.generic] | spmatrix[np.generic]: ...
        def __rmatmul__(self, other: npt.NDArray[np.generic] | spmatrix[np.generic]) -> npt.NDArray[np.generic] | spmatrix[np.generic]: ...
        def __truediv__(self, other: float) -> spmatrix[np.floating[npt.NBitBase]]: ...
        def __neg__(self) -> spmatrix[_ScalarType]: ...
        def __pow__(self, other: int) -> spmatrix[_ScalarType]: ...
        def __getitem__(self, key: tuple[int, int] | tuple[slice, slice] | tuple[int, slice] | tuple[slice, int]) -> _ScalarType | spmatrix[_ScalarType]: ...
        def __setitem__(self, key: tuple[int, int], value: _ScalarType | float) -> None: ...

        @property
        def T(self) -> spmatrix[_ScalarType]: ...
        @property
        def H(self) -> spmatrix[_ScalarType]: ...

    class csr_matrix(spmatrix[_ScalarType]):
        """Compressed Sparse Row matrix."""

        data: npt.NDArray[_ScalarType]
        indices: npt.NDArray[np.intp]
        indptr: npt.NDArray[np.intp]

        def __init__(
            self,
            arg1: npt.NDArray[_ScalarType] | spmatrix[_ScalarType] | tuple[npt.NDArray[_ScalarType], tuple[npt.NDArray[np.intp], npt.NDArray[np.intp]]] | tuple[npt.NDArray[_ScalarType], npt.NDArray[np.intp], npt.NDArray[np.intp]],
            shape: tuple[int, int] | None = None,
            dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None,
            copy: bool = False,
        ) -> None: ...

    class csc_matrix(spmatrix[_ScalarType]):
        """Compressed Sparse Column matrix."""

        data: npt.NDArray[_ScalarType]
        indices: npt.NDArray[np.intp]
        indptr: npt.NDArray[np.intp]

        def __init__(
            self,
            arg1: npt.NDArray[_ScalarType] | spmatrix[_ScalarType] | tuple[npt.NDArray[_ScalarType], tuple[npt.NDArray[np.intp], npt.NDArray[np.intp]]] | tuple[npt.NDArray[_ScalarType], npt.NDArray[np.intp], npt.NDArray[np.intp]],
            shape: tuple[int, int] | None = None,
            dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None,
            copy: bool = False,
        ) -> None: ...

    class coo_matrix(spmatrix[_ScalarType]):
        """Coordinate format sparse matrix."""

        data: npt.NDArray[_ScalarType]
        row: npt.NDArray[np.intp]
        col: npt.NDArray[np.intp]

        def __init__(
            self,
            arg1: npt.NDArray[_ScalarType] | spmatrix[_ScalarType] | tuple[npt.NDArray[_ScalarType], tuple[npt.NDArray[np.intp], npt.NDArray[np.intp]]],
            shape: tuple[int, int] | None = None,
            dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None,
            copy: bool = False,
        ) -> None: ...

    class lil_matrix(spmatrix[_ScalarType]):
        """List of Lists sparse matrix."""

        def __init__(
            self,
            arg1: npt.NDArray[_ScalarType] | spmatrix[_ScalarType] | tuple[int, int],
            shape: tuple[int, int] | None = None,
            dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None,
            copy: bool = False,
        ) -> None: ...

    class dia_matrix(spmatrix[_ScalarType]):
        """Diagonal storage sparse matrix."""

        data: npt.NDArray[_ScalarType]
        offsets: npt.NDArray[np.intp]

        def __init__(
            self,
            arg1: npt.NDArray[_ScalarType] | spmatrix[_ScalarType] | tuple[npt.NDArray[_ScalarType], npt.NDArray[np.intp]],
            shape: tuple[int, int] | None = None,
            dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None,
            copy: bool = False,
        ) -> None: ...

    class bsr_matrix(spmatrix[_ScalarType]):
        """Block Sparse Row matrix."""

        def __init__(
            self,
            arg1: npt.NDArray[_ScalarType] | spmatrix[_ScalarType] | tuple[npt.NDArray[_ScalarType], tuple[npt.NDArray[np.intp], npt.NDArray[np.intp]]],
            shape: tuple[int, int] | None = None,
            dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None,
            copy: bool = False,
            blocksize: tuple[int, int] | None = None,
        ) -> None: ...

    class dok_matrix(spmatrix[_ScalarType]):
        """Dictionary Of Keys sparse matrix."""

        def __init__(
            self,
            arg1: npt.NDArray[_ScalarType] | spmatrix[_ScalarType] | tuple[int, int],
            shape: tuple[int, int] | None = None,
            dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None,
            copy: bool = False,
        ) -> None: ...

    @staticmethod
    def issparse(x: object) -> bool: ...
    @staticmethod
    def isspmatrix(x: object) -> bool: ...
    @staticmethod
    def isspmatrix_csr(x: object) -> bool: ...
    @staticmethod
    def isspmatrix_csc(x: object) -> bool: ...
    @staticmethod
    def isspmatrix_coo(x: object) -> bool: ...
    @staticmethod
    def isspmatrix_lil(x: object) -> bool: ...
    @staticmethod
    def isspmatrix_dia(x: object) -> bool: ...
    @staticmethod
    def isspmatrix_bsr(x: object) -> bool: ...
    @staticmethod
    def isspmatrix_dok(x: object) -> bool: ...

    @staticmethod
    def eye(
        m: int,
        n: int | None = None,
        k: int = 0,
        dtype: np.dtype[_ScalarType] | type[_ScalarType] = ...,
        format: _SparseFormat | None = None,
    ) -> spmatrix[_ScalarType]: ...

    @staticmethod
    def diags(
        diagonals: Sequence[_ArrayLikeFloat],
        offsets: int | Sequence[int] = 0,
        shape: tuple[int, int] | None = None,
        format: _SparseFormat | None = None,
        dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None,
    ) -> spmatrix[_ScalarType]: ...

    @staticmethod
    def hstack(blocks: Sequence[spmatrix[_ScalarType]], format: str | None = None, dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None) -> spmatrix[_ScalarType]: ...
    @staticmethod
    def vstack(blocks: Sequence[spmatrix[_ScalarType]], format: str | None = None, dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None) -> spmatrix[_ScalarType]: ...
    @staticmethod
    def block_diag(mats: Sequence[spmatrix[_ScalarType] | npt.NDArray[_ScalarType]], format: str | None = None, dtype: np.dtype[_ScalarType] | type[_ScalarType] | None = None) -> spmatrix[_ScalarType]: ...
    @staticmethod
    def kron(A: spmatrix[_ScalarType] | npt.NDArray[_ScalarType], B: spmatrix[_ScalarType] | npt.NDArray[_ScalarType], format: str | None = None) -> spmatrix[_ScalarType]: ...

    @staticmethod
    def save_npz(file: str, matrix: spmatrix[np.generic], compressed: bool = True) -> None: ...
    @staticmethod
    def load_npz(file: str) -> spmatrix[np.generic]: ...


# ══════════════════════════════════════════════════════════════════════════════
# scipy.linalg — Linear algebra
# ══════════════════════════════════════════════════════════════════════════════

class linalg:
    """Linear algebra functions."""

    @staticmethod
    def inv(a: _ArrayLikeFloat, overwrite_a: bool = False, check_finite: bool = True) -> _FloatArray: ...

    @overload
    @staticmethod
    def pinv(a: _ArrayLikeFloat, atol: float | None = None, rtol: float | None = None, return_rank: Literal[False] = False, check_finite: bool = True) -> _FloatArray: ...
    @overload
    @staticmethod
    def pinv(a: _ArrayLikeFloat, atol: float | None = None, rtol: float | None = None, return_rank: Literal[True] = ..., check_finite: bool = True) -> tuple[_FloatArray, int]: ...

    @staticmethod
    def det(a: _ArrayLikeFloat, overwrite_a: bool = False, check_finite: bool = True) -> float: ...

    @staticmethod
    def norm(a: _ArrayLikeFloat, ord: int | float | str | None = None, axis: int | tuple[int, ...] | None = None, keepdims: bool = False, check_finite: bool = True) -> float | _FloatArray: ...

    @staticmethod
    def eig(a: _ArrayLikeFloat, b: _ArrayLikeFloat | None = None, left: bool = False, right: bool = True, overwrite_a: bool = False, overwrite_b: bool = False, check_finite: bool = True) -> tuple[_FloatArray, ...]: ...

    @overload
    @staticmethod
    def eigh(a: _ArrayLikeFloat, b: _ArrayLikeFloat | None = None, lower: bool = True, eigvals_only: Literal[False] = False, overwrite_a: bool = False, overwrite_b: bool = False, turbo: bool = True, eigvals: tuple[int, int] | None = None, type: int = 1, check_finite: bool = True, subset_by_index: tuple[int, int] | None = None, subset_by_value: tuple[float, float] | None = None, driver: str | None = None) -> tuple[_FloatArray, _FloatArray]: ...
    @overload
    @staticmethod
    def eigh(a: _ArrayLikeFloat, b: _ArrayLikeFloat | None = None, lower: bool = True, eigvals_only: Literal[True] = ..., overwrite_a: bool = False, overwrite_b: bool = False, turbo: bool = True, eigvals: tuple[int, int] | None = None, type: int = 1, check_finite: bool = True, subset_by_index: tuple[int, int] | None = None, subset_by_value: tuple[float, float] | None = None, driver: str | None = None) -> _FloatArray: ...

    @staticmethod
    def eigvals(a: _ArrayLikeFloat, b: _ArrayLikeFloat | None = None, overwrite_a: bool = False, check_finite: bool = True) -> _FloatArray: ...

    @overload
    @staticmethod
    def svd(a: _ArrayLikeFloat, full_matrices: bool = True, compute_uv: Literal[True] = True, overwrite_a: bool = False, check_finite: bool = True, lapack_driver: str = "gesdd") -> tuple[_FloatArray, _FloatArray, _FloatArray]: ...
    @overload
    @staticmethod
    def svd(a: _ArrayLikeFloat, full_matrices: bool = True, compute_uv: Literal[False] = ..., overwrite_a: bool = False, check_finite: bool = True, lapack_driver: str = "gesdd") -> _FloatArray: ...

    @staticmethod
    def svdvals(a: _ArrayLikeFloat, overwrite_a: bool = False, check_finite: bool = True) -> _FloatArray: ...

    @staticmethod
    def lu(a: _ArrayLikeFloat, permute_l: bool = False, overwrite_a: bool = False, check_finite: bool = True) -> tuple[_FloatArray, ...]: ...

    @staticmethod
    def qr(a: _ArrayLikeFloat, overwrite_a: bool = False, lwork: int | None = None, mode: Literal["full", "r", "economic", "raw"] = "full", pivoting: bool = False, check_finite: bool = True) -> tuple[_FloatArray, ...] | _FloatArray: ...

    @staticmethod
    def cholesky(a: _ArrayLikeFloat, lower: bool = False, overwrite_a: bool = False, check_finite: bool = True) -> _FloatArray: ...

    @staticmethod
    def solve(a: _ArrayLikeFloat, b: _ArrayLikeFloat, sym_pos: bool = False, lower: bool = False, overwrite_a: bool = False, overwrite_b: bool = False, check_finite: bool = True, assume_a: Literal["gen", "sym", "her", "pos"] = "gen", transposed: bool = False) -> _FloatArray: ...

    @staticmethod
    def lstsq(a: _ArrayLikeFloat, b: _ArrayLikeFloat, cond: float | None = None, overwrite_a: bool = False, overwrite_b: bool = False, check_finite: bool = True, lapack_driver: str | None = None) -> tuple[_FloatArray, _FloatArray | float, int, _FloatArray]: ...

    @staticmethod
    def expm(A: _ArrayLikeFloat) -> _FloatArray: ...

    @overload
    @staticmethod
    def logm(A: _ArrayLikeFloat, disp: Literal[True] = True) -> _FloatArray: ...
    @overload
    @staticmethod
    def logm(A: _ArrayLikeFloat, disp: Literal[False]) -> tuple[_FloatArray, float]: ...

    @overload
    @staticmethod
    def sqrtm(A: _ArrayLikeFloat, disp: Literal[True] = True, blocksize: int = 64) -> _FloatArray: ...
    @overload
    @staticmethod
    def sqrtm(A: _ArrayLikeFloat, disp: Literal[False], blocksize: int = 64) -> tuple[_FloatArray, float]: ...


# ══════════════════════════════════════════════════════════════════════════════
# scipy.optimize — Optimization
# ══════════════════════════════════════════════════════════════════════════════

class optimize:
    """Optimization functions."""

    class OptimizeResult:
        """Result of optimization."""

        x: _FloatArray
        success: bool
        status: int
        message: str
        fun: float
        nfev: int
        njev: int | None
        nhev: int | None
        nit: int
        jac: _FloatArray | None
        hess: _FloatArray | None
        hess_inv: _FloatArray | sparse.spmatrix[np.floating[npt.NBitBase]] | None

    @staticmethod
    def minimize(
        fun: Callable[[_FloatArray], float],
        x0: _ArrayLikeFloat,
        args: tuple[float | _ArrayLikeFloat, ...] = (),
        method: str | None = None,
        jac: Callable[[_FloatArray], _ArrayLikeFloat] | str | bool | None = None,
        hess: Callable[[_FloatArray], _ArrayLikeFloat] | str | None = None,
        hessp: Callable[[_FloatArray, _FloatArray], _ArrayLikeFloat] | None = None,
        bounds: Sequence[tuple[float | None, float | None]] | None = None,
        constraints: dict[str, Callable[[_FloatArray], float | _ArrayLikeFloat] | str] | Sequence[dict[str, Callable[[_FloatArray], float | _ArrayLikeFloat] | str]] = (),
        tol: float | None = None,
        callback: Callable[[_FloatArray], None] | None = None,
        options: dict[str, int | float | bool | str] | None = None,
    ) -> OptimizeResult: ...

    @staticmethod
    def minimize_scalar(
        fun: Callable[[float], float],
        bracket: tuple[float, float] | tuple[float, float, float] | None = None,
        bounds: tuple[float, float] | None = None,
        args: tuple[float, ...] = (),
        method: Literal["brent", "bounded", "golden"] | None = None,
        tol: float | None = None,
        options: dict[str, int | float | bool] | None = None,
    ) -> OptimizeResult: ...

    class RootResult:
        """Result of root finding."""

        x: _FloatArray
        success: bool
        message: str
        fun: _FloatArray

    @staticmethod
    def root(
        fun: Callable[[_FloatArray], _ArrayLikeFloat],
        x0: _ArrayLikeFloat,
        args: tuple[float | _ArrayLikeFloat, ...] = (),
        method: str = "hybr",
        jac: Callable[[_FloatArray], _ArrayLikeFloat] | str | bool | None = None,
        tol: float | None = None,
        callback: Callable[[_FloatArray, _FloatArray], None] | None = None,
        options: dict[str, int | float | bool | str] | None = None,
    ) -> RootResult: ...

    @staticmethod
    def root_scalar(
        f: Callable[[float], float],
        args: tuple[float, ...] = (),
        method: str | None = None,
        bracket: tuple[float, float] | None = None,
        fprime: Callable[[float], float] | bool | None = None,
        fprime2: Callable[[float], float] | bool | None = None,
        x0: float | None = None,
        x1: float | None = None,
        xtol: float | None = None,
        rtol: float | None = None,
        maxiter: int | None = None,
        options: dict[str, int | float | bool] | None = None,
    ) -> RootResult: ...

    @overload
    @staticmethod
    def brentq(
        f: Callable[[float], float],
        a: float,
        b: float,
        args: tuple[float, ...] = (),
        xtol: float = 2e-12,
        rtol: float = ...,
        maxiter: int = 100,
        full_output: Literal[False] = False,
        disp: bool = True,
    ) -> float: ...
    @overload
    @staticmethod
    def brentq(
        f: Callable[[float], float],
        a: float,
        b: float,
        args: tuple[float, ...] = (),
        xtol: float = 2e-12,
        rtol: float = ...,
        maxiter: int = 100,
        full_output: Literal[True] = ...,
        disp: bool = True,
    ) -> tuple[float, RootResult]: ...

    @overload
    @staticmethod
    def newton(
        func: Callable[[float], float],
        x0: float,
        fprime: Callable[[float], float] | None = None,
        args: tuple[float, ...] = (),
        tol: float = 1.48e-8,
        maxiter: int = 50,
        fprime2: Callable[[float], float] | None = None,
        x1: float | None = None,
        rtol: float = 0.0,
        full_output: Literal[False] = False,
        disp: bool = True,
    ) -> float: ...
    @overload
    @staticmethod
    def newton(
        func: Callable[[float], float],
        x0: float,
        fprime: Callable[[float], float] | None = None,
        args: tuple[float, ...] = (),
        tol: float = 1.48e-8,
        maxiter: int = 50,
        fprime2: Callable[[float], float] | None = None,
        x1: float | None = None,
        rtol: float = 0.0,
        full_output: Literal[True] = ...,
        disp: bool = True,
    ) -> tuple[float, RootResult]: ...

    @overload
    @staticmethod
    def fsolve(
        func: Callable[[_FloatArray], _ArrayLikeFloat],
        x0: _ArrayLikeFloat,
        args: tuple[float | _ArrayLikeFloat, ...] = (),
        fprime: Callable[[_FloatArray], _ArrayLikeFloat] | None = None,
        full_output: Literal[False] = False,
        col_deriv: int = 0,
        xtol: float = 1.49012e-8,
        maxfev: int = 0,
        band: tuple[int, int] | None = None,
        epsfcn: float | None = None,
        factor: float = 100,
        diag: _ArrayLikeFloat | None = None,
    ) -> _FloatArray: ...
    @overload
    @staticmethod
    def fsolve(
        func: Callable[[_FloatArray], _ArrayLikeFloat],
        x0: _ArrayLikeFloat,
        args: tuple[float | _ArrayLikeFloat, ...] = (),
        fprime: Callable[[_FloatArray], _ArrayLikeFloat] | None = None,
        full_output: Literal[True] = ...,
        col_deriv: int = 0,
        xtol: float = 1.49012e-8,
        maxfev: int = 0,
        band: tuple[int, int] | None = None,
        epsfcn: float | None = None,
        factor: float = 100,
        diag: _ArrayLikeFloat | None = None,
    ) -> tuple[_FloatArray, dict[str, _FloatArray | int], int, str]: ...

    @overload
    @staticmethod
    def curve_fit(
        f: Callable[..., _ArrayLikeFloat],
        xdata: _ArrayLikeFloat,
        ydata: _ArrayLikeFloat,
        p0: _ArrayLikeFloat | None = None,
        sigma: _ArrayLikeFloat | None = None,
        absolute_sigma: bool = False,
        check_finite: bool = True,
        bounds: tuple[_ArrayLikeFloat, _ArrayLikeFloat] = ...,
        method: Literal["lm", "trf", "dogbox"] | None = None,
        jac: Callable[..., _ArrayLikeFloat] | str | None = None,
        full_output: Literal[False] = False,
        **kwargs: float | int | bool,
    ) -> tuple[_FloatArray, _FloatArray]: ...
    @overload
    @staticmethod
    def curve_fit(
        f: Callable[..., _ArrayLikeFloat],
        xdata: _ArrayLikeFloat,
        ydata: _ArrayLikeFloat,
        p0: _ArrayLikeFloat | None = None,
        sigma: _ArrayLikeFloat | None = None,
        absolute_sigma: bool = False,
        check_finite: bool = True,
        bounds: tuple[_ArrayLikeFloat, _ArrayLikeFloat] = ...,
        method: Literal["lm", "trf", "dogbox"] | None = None,
        jac: Callable[..., _ArrayLikeFloat] | str | None = None,
        full_output: Literal[True] = ...,
        **kwargs: float | int | bool,
    ) -> tuple[_FloatArray, _FloatArray, dict[str, _FloatArray], str, int]: ...

    @staticmethod
    def linear_sum_assignment(
        cost_matrix: _ArrayLikeFloat,
        maximize: bool = False,
    ) -> tuple[npt.NDArray[np.intp], npt.NDArray[np.intp]]: ...


# ══════════════════════════════════════════════════════════════════════════════
# scipy.integrate — Numerical integration
# ══════════════════════════════════════════════════════════════════════════════

class integrate:
    """Numerical integration functions."""

    @overload
    @staticmethod
    def quad(
        func: Callable[[float], float],
        a: float,
        b: float,
        args: tuple[float, ...] = (),
        full_output: Literal[0] = 0,
        epsabs: float = 1.49e-8,
        epsrel: float = 1.49e-8,
        limit: int = 50,
        points: Sequence[float] | None = None,
        weight: str | None = None,
        wvar: float | tuple[float, float] | None = None,
        wopts: tuple[int, _ArrayLikeFloat] | None = None,
        maxp1: int = 50,
        limlst: int = 50,
    ) -> tuple[float, float]: ...
    @overload
    @staticmethod
    def quad(
        func: Callable[[float], float],
        a: float,
        b: float,
        args: tuple[float, ...] = (),
        full_output: Literal[1] = ...,
        epsabs: float = 1.49e-8,
        epsrel: float = 1.49e-8,
        limit: int = 50,
        points: Sequence[float] | None = None,
        weight: str | None = None,
        wvar: float | tuple[float, float] | None = None,
        wopts: tuple[int, _ArrayLikeFloat] | None = None,
        maxp1: int = 50,
        limlst: int = 50,
    ) -> tuple[float, float, dict[str, _FloatArray | float]]: ...

    @staticmethod
    def dblquad(
        func: Callable[[float, float], float],
        a: float,
        b: float,
        gfun: Callable[[float], float] | float,
        hfun: Callable[[float], float] | float,
        args: tuple[float, ...] = (),
        epsabs: float = 1.49e-8,
        epsrel: float = 1.49e-8,
    ) -> tuple[float, float]: ...

    @staticmethod
    def tplquad(
        func: Callable[[float, float, float], float],
        a: float,
        b: float,
        gfun: Callable[[float], float] | float,
        hfun: Callable[[float], float] | float,
        qfun: Callable[[float, float], float] | float,
        rfun: Callable[[float, float], float] | float,
        args: tuple[float, ...] = (),
        epsabs: float = 1.49e-8,
        epsrel: float = 1.49e-8,
    ) -> tuple[float, float]: ...

    @overload
    @staticmethod
    def nquad(
        func: Callable[..., float],
        ranges: Sequence[tuple[float, float] | Callable[..., tuple[float, float]]],
        args: tuple[float, ...] | None = None,
        opts: dict[str, float | int | bool] | Sequence[dict[str, float | int | bool]] | None = None,
        full_output: Literal[False] = False,
    ) -> tuple[float, float]: ...
    @overload
    @staticmethod
    def nquad(
        func: Callable[..., float],
        ranges: Sequence[tuple[float, float] | Callable[..., tuple[float, float]]],
        args: tuple[float, ...] | None = None,
        opts: dict[str, float | int | bool] | Sequence[dict[str, float | int | bool]] | None = None,
        full_output: Literal[True] = ...,
    ) -> tuple[float, float, dict[str, int]]: ...

    @staticmethod
    def trapezoid(
        y: _ArrayLikeFloat,
        x: _ArrayLikeFloat | None = None,
        dx: float = 1.0,
        axis: int = -1,
    ) -> float | _FloatArray: ...

    @staticmethod
    def cumulative_trapezoid(
        y: _ArrayLikeFloat,
        x: _ArrayLikeFloat | None = None,
        dx: float = 1.0,
        axis: int = -1,
        initial: float | None = None,
    ) -> _FloatArray: ...

    @staticmethod
    def simpson(
        y: _ArrayLikeFloat,
        x: _ArrayLikeFloat | None = None,
        dx: float = 1.0,
        axis: int = -1,
        even: Literal["avg", "first", "last"] = "avg",
    ) -> float | _FloatArray: ...

    class OdeResult:
        """Result of ODE integration."""

        t: _FloatArray
        y: _FloatArray
        sol: Callable[[float], _FloatArray] | None
        t_events: list[_FloatArray] | None
        y_events: list[_FloatArray] | None
        nfev: int
        njev: int
        nlu: int
        status: int
        message: str
        success: bool

    @staticmethod
    def solve_ivp(
        fun: Callable[[float, _FloatArray], _ArrayLikeFloat],
        t_span: tuple[float, float],
        y0: _ArrayLikeFloat,
        method: Literal["RK45", "RK23", "DOP853", "Radau", "BDF", "LSODA"] = "RK45",
        t_eval: _ArrayLikeFloat | None = None,
        dense_output: bool = False,
        events: Callable[[float, _FloatArray], float] | Sequence[Callable[[float, _FloatArray], float]] | None = None,
        vectorized: bool = False,
        args: tuple[float | _ArrayLikeFloat, ...] | None = None,
        **options: float | int | bool | _ArrayLikeFloat,
    ) -> OdeResult: ...


# ══════════════════════════════════════════════════════════════════════════════
# scipy.ndimage — N-dimensional image processing
# ══════════════════════════════════════════════════════════════════════════════

_BoundaryMode = Literal["reflect", "constant", "nearest", "mirror", "wrap"]

class ndimage:
    """N-dimensional image processing."""

    @staticmethod
    def convolve(
        input: _ArrayLikeFloat,
        weights: _ArrayLikeFloat,
        output: npt.NDArray[np.floating[npt.NBitBase]] | np.dtype[np.floating[npt.NBitBase]] | None = None,
        mode: _BoundaryMode = "reflect",
        cval: float = 0.0,
        origin: int | Sequence[int] = 0,
    ) -> _FloatArray: ...

    @staticmethod
    def correlate(
        input: _ArrayLikeFloat,
        weights: _ArrayLikeFloat,
        output: npt.NDArray[np.floating[npt.NBitBase]] | np.dtype[np.floating[npt.NBitBase]] | None = None,
        mode: _BoundaryMode = "reflect",
        cval: float = 0.0,
        origin: int | Sequence[int] = 0,
    ) -> _FloatArray: ...

    @staticmethod
    def gaussian_filter(
        input: _ArrayLikeFloat,
        sigma: float | Sequence[float],
        order: int | Sequence[int] = 0,
        output: npt.NDArray[np.floating[npt.NBitBase]] | np.dtype[np.floating[npt.NBitBase]] | None = None,
        mode: _BoundaryMode | Sequence[_BoundaryMode] = "reflect",
        cval: float = 0.0,
        truncate: float = 4.0,
        radius: int | Sequence[int] | None = None,
    ) -> _FloatArray: ...

    @staticmethod
    def sobel(
        input: _ArrayLikeFloat,
        axis: int = -1,
        output: npt.NDArray[np.floating[npt.NBitBase]] | np.dtype[np.floating[npt.NBitBase]] | None = None,
        mode: _BoundaryMode = "reflect",
        cval: float = 0.0,
    ) -> _FloatArray: ...

    @staticmethod
    def label(
        input: npt.NDArray[np.bool_] | npt.NDArray[np.integer[npt.NBitBase]],
        structure: npt.NDArray[np.bool_] | npt.NDArray[np.integer[npt.NBitBase]] | None = None,
        output: npt.NDArray[np.intp] | None = None,
    ) -> tuple[npt.NDArray[np.intp], int]: ...

    @staticmethod
    def binary_dilation(
        input: npt.NDArray[np.bool_],
        structure: npt.NDArray[np.bool_] | None = None,
        iterations: int = 1,
        mask: npt.NDArray[np.bool_] | None = None,
        output: npt.NDArray[np.bool_] | None = None,
        border_value: int = 0,
        origin: int | Sequence[int] = 0,
        brute_force: bool = False,
    ) -> npt.NDArray[np.bool_]: ...

    @staticmethod
    def binary_erosion(
        input: npt.NDArray[np.bool_],
        structure: npt.NDArray[np.bool_] | None = None,
        iterations: int = 1,
        mask: npt.NDArray[np.bool_] | None = None,
        output: npt.NDArray[np.bool_] | None = None,
        border_value: int = 0,
        origin: int | Sequence[int] = 0,
        brute_force: bool = False,
    ) -> npt.NDArray[np.bool_]: ...


# ══════════════════════════════════════════════════════════════════════════════
# Version
# ══════════════════════════════════════════════════════════════════════════════

__version__: str
