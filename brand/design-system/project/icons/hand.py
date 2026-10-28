"""Steady hand-drawn SVG paths for the backtide icons: the hand shows, the line stays clean.

Every stroke is a few smooth curves, never many noisy points:
- a straight stroke is one cubic with a faint, even bow, the way a careful pen draws it;
- circles and ellipses always close, with a slow, low-frequency wobble (almost round);
- the wobble that remains is TREMOR (about a third) of the old one.
Fixed seeds, so the output is the same on every run.
"""

# The seeded random numbers only add a wobble to the drawings; nothing here is security.
# ruff: noqa: S311

import math
import random

TREMOR = 0.3


def f(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def smooth(pts, closed=False):
    """Catmull-Rom through the points, written as cubic Béziers."""
    n = len(pts)
    if n < 2:
        return ""

    def p(i):
        return pts[i % n] if closed else pts[max(0, min(n - 1, i))]

    d = [f"M{f(pts[0][0])} {f(pts[0][1])}"]
    for i in range(n if closed else n - 1):
        p0, p1, p2, p3 = p(i - 1), p(i), p(i + 1), p(i + 2)
        c1 = (p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6)
        d.append(f"C{f(c1[0])} {f(c1[1])} {f(c2[0])} {f(c2[1])} {f(p2[0])} {f(p2[1])}")
    if closed:
        d.append("Z")
    return "".join(d)


def line(points, seed, amp=1.2, step=14, curve=False):
    """A polyline drawn by hand. Each segment is one cubic with a faint bow; corners
    stay where they are, so closed outlines close exactly. curve=True draws one smooth
    curve through the points instead (for page edges and the like)."""
    if curve:
        return smooth(points)
    rng = random.Random(seed)
    d = [f"M{f(points[0][0])} {f(points[0][1])}"]
    for (x0, y0), (x1, y1) in zip(points, points[1:], strict=False):
        dx, dy = x1 - x0, y1 - y0
        length = math.hypot(dx, dy) or 1.0
        nx, ny = -dy / length, dx / length
        bow = rng.choice((-1, 1)) * (0.004 * length + amp * TREMOR * 0.25) * rng.uniform(0.6, 1.0)
        lean = rng.uniform(-0.08, 0.08)  # the bow sits a little off-centre, as a hand does
        c1 = (x0 + dx * (1 / 3 + lean) + nx * bow, y0 + dy * (1 / 3 + lean) + ny * bow)
        c2 = (x0 + dx * (2 / 3 + lean) + nx * bow, y0 + dy * (2 / 3 + lean) + ny * bow)
        d.append(f"C{f(c1[0])} {f(c1[1])} {f(c2[0])} {f(c2[1])} {f(x1)} {f(y1)}")
    return "".join(d)


def _slow(rng, amp):
    """A slow wobble: two low harmonics, never more."""
    a2, a3 = amp * rng.uniform(0.6, 1.0), amp * rng.uniform(0.2, 0.45)
    p2, p3 = rng.uniform(0, 2 * math.pi), rng.uniform(0, 2 * math.pi)
    return lambda t: a2 * math.sin(2 * t + p2) + a3 * math.sin(3 * t + p3)


def circle(cx, cy, r, seed, amp=1.6, ry=None, closed=True, n=16, **_ignored):
    """An almost round circle or ellipse that always closes cleanly."""
    rng = random.Random(seed)
    ry = r if ry is None else ry
    wob = _slow(rng, amp * TREMOR)
    a0 = rng.uniform(0, 2 * math.pi)
    pts = []
    for i in range(n):
        t = a0 + 2 * math.pi * i / n
        e = wob(t)
        pts.append((cx + (r + e) * math.cos(t), cy + (ry + e * ry / max(r, 0.01)) * math.sin(t)))
    return smooth(pts, closed=True)


def wave(x0, x1, y, amp, length, seed, jitter=1.0, step=10, fade=None, phase=0.0):
    """A sine, eight points to a wavelength, with a slow drift instead of noise."""
    rng = random.Random(seed)
    drift = _slow(rng, jitter * TREMOR)
    n = max(4, round((x1 - x0) / length * 8))
    pts = []
    for i in range(n + 1):
        t = i / n
        x = x0 + (x1 - x0) * t
        a = amp * (fade(t) if fade else 1)
        pts.append(
            (x, y + a * math.sin(2 * math.pi * (x - x0) / length + phase) + drift(t * math.pi))
        )
    return smooth(pts)


def spiral(cx, cy, r0, r1, turns, seed, amp=0.6, n_per_turn=14, a0=0.0):
    rng = random.Random(seed)
    wob = _slow(rng, amp * TREMOR)
    n = max(8, int(turns * n_per_turn))
    pts = []
    for i in range(n + 1):
        t = i / n
        th = a0 + 2 * math.pi * turns * t
        r = r0 + (r1 - r0) * t + wob(th) * t
        pts.append((cx + r * math.cos(th), cy + r * math.sin(th)))
    return smooth(pts)


def crescent(cx, cy, r, seed, amp=0.5):
    """A crescent opening to the right: two clean arcs that meet at the horns."""
    rng = random.Random(seed)
    wob = _slow(rng, amp * TREMOR)
    pts = []
    for i in range(11):
        th = math.radians(55 + 250 * i / 10)
        pts.append((cx + (r + wob(th)) * math.cos(th), cy + (r + wob(th)) * math.sin(th)))
    ox, rin = r * 0.45, r * 0.82
    for i in range(1, 8):
        th = math.radians(290 - 220 * i / 8)
        pts.append((cx + ox + rin * math.cos(th), cy + rin * math.sin(th)))
    return smooth(pts, closed=True)
