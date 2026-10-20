"""Cost checks that hold on any machine: how the time of some work grows with its input, not how
many seconds it takes on the Mac. A slower CPU (the CI runner, a busy VM) makes the work slower
at every size alike; a quadratic pattern makes it slower the larger the input. So the check
times the work on an input and on one ``growth`` times larger: linear work takes about
``growth`` times longer, quadratic work ``growth ** 2`` times. The bound sits halfway between,
``growth ** 1.5``, which leaves the same margin (``growth ** 0.5``) on either side.

- Work that stays under ``floor`` on the large input is cheap whatever its shape: not measured.
- A ratio over the bound is measured again, the best of a few runs, before it fails: a pause
  of the machine during one run is not a quadratic pattern.
- ``cap`` is only a backstop, far above what any machine needs, for work so slow it would
  hang the test.
"""

import time
from collections.abc import Callable


def best_time(work: Callable[[], object], repeats: int = 1) -> float:
    """The least time of ``repeats`` runs of ``work``, in seconds."""
    best = float("inf")
    for _ in range(repeats):
        start = time.perf_counter()
        work()
        best = min(best, time.perf_counter() - start)
    return best


def assert_linear[T](
    work: Callable[[T], object],
    small: T,
    large: T,
    growth: float,
    *,
    floor: float,
    cap: float,
    label: str,
) -> float:
    """Fail if ``work(large)`` takes more than ``cap`` seconds or, when it takes more than
    ``floor``, grows faster than linearly from ``work(small)``; ``large`` is ``growth`` times
    the size of ``small``. Returns the time of ``work(large)``."""
    bound = growth**1.5
    took = best_time(lambda: work(large))
    assert took < cap, f"{label} took {took:.3f}s, over the {cap}s backstop"
    if took < floor:
        return took
    took_small = best_time(lambda: work(small))
    if took > took_small * bound:
        took = best_time(lambda: work(large), 3)
        took_small = best_time(lambda: work(small), 3)
    assert took <= took_small * bound, (
        f"{label} is not linear: {took_small:.4f}s, then {took:.4f}s on {growth:g} times the "
        f"input ({took / took_small:.1f} times, the bound is {bound:.1f})"
    )
    return took
