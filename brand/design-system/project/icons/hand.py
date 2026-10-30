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


# ---------------------------------------------------------------- the field hand (2026-10-30)
# A field notebook's hand, for the drawings redrawn in the first round of the redesign. Where the
# steady hand above draws clean curves with a faint bow, this one shows the pen:
# - the line bows and wanders a little along its length, slowly, more on a long stroke than on a
#   short one, never as noise;
# - a corner is two strokes that cross or fall just short of each other; a ring starts and ends
#   a little apart; a stroke may run on past where it was aimed;
# - a long stroke is inked twice: a second, shorter pass runs back over its middle, a hair to one
#   side, so the line swells there and thins towards its ends, as pressure does. Both passes sit
#   in one path, so the drawing still draws itself with pathLength="1" (the pen goes back over);
# - every shape (the clay dot too) can be drawn again as a frame of its "boil": the same drawing
#   with only its tremor changed (`frame(k)`), cycled by motion/boil.js on the public site.
# The shape of a drawing (where it overshoots, which side it presses) comes from its seed only;
# the tremor comes from its seed and the frame. Seeds may be numbers or strings.

FRAMES = 3  # boil frames: 0 is the still drawing, 1 and 2 only tremble differently
_FRAME = 0


def frame(k):
    """Draw the next shapes as boil frame k (0 is the still drawing)."""
    global _FRAME
    _FRAME = k


def _shape(seed):
    return random.Random(f"field/{seed}")


def _tremble(seed):
    return random.Random(f"field/{seed}/boil/{_FRAME}")


def _length(pts):
    return sum(math.dist(a, b) for a, b in zip(pts, pts[1:], strict=False))


def _resample(pts, step):
    """Points every `step` units along the polyline (its ends kept)."""
    out = [pts[0]]
    carry = 0.0
    for (x0, y0), (x1, y1) in zip(pts, pts[1:], strict=False):
        seg = math.hypot(x1 - x0, y1 - y0)
        if seg == 0:
            continue
        s = step - carry
        while s < seg:
            t = s / seg
            out.append((x0 + (x1 - x0) * t, y0 + (y1 - y0) * t))
            s += step
        carry = seg - (s - step)
    if math.dist(out[-1], pts[-1]) > step * 0.3:
        out.append(pts[-1])
    else:
        out[-1] = pts[-1]
    return out


def _normals(pts):
    ns = []
    n = len(pts)
    for i in range(n):
        a, b = pts[max(0, i - 1)], pts[min(n - 1, i + 1)]
        dx, dy = b[0] - a[0], b[1] - a[1]
        d = math.hypot(dx, dy) or 1.0
        ns.append((-dy / d, dx / d))
    return ns


def _catmull(pts, per=8):
    """Dense points on a Catmull-Rom curve through `pts` (to bend a few points into a curve)."""
    out = []
    n = len(pts)
    for i in range(n - 1):
        p0, p1, p2, p3 = pts[max(0, i - 1)], pts[i], pts[i + 1], pts[min(n - 1, i + 2)]
        for j in range(per):
            t = j / per
            t2, t3 = t * t, t * t * t
            out.append(
                tuple(
                    0.5
                    * (
                        2 * p1[k]
                        + (-p0[k] + p2[k]) * t
                        + (2 * p0[k] - 5 * p1[k] + 4 * p2[k] - p3[k]) * t2
                        + (-p0[k] + 3 * p1[k] - 3 * p2[k] + p3[k]) * t3
                    )
                    for k in (0, 1)
                )
            )
    out.append(pts[-1])
    return out


def _simplify(pts):
    """A smooth path through every few points (about every 3 units; small shapes keep more)."""
    if len(pts) <= 3:
        return smooth(pts)
    k = max(1, min(4, len(pts) // 12))
    keep = pts[::k]
    if keep[-1] != pts[-1]:
        if math.dist(keep[-1], pts[-1]) < 1.2 and len(keep) > 2:
            keep[-1] = pts[-1]
        else:
            keep.append(pts[-1])
    return smooth(keep)


class Ink:
    """One drawn line: its points, a slow tremor along it, maybe a second pass. `d` is its path."""

    def __init__(self, pts, seed, amp=1.0, press=True):
        self.seed, self.amp, self.press = seed, amp, press
        self.pts = _resample(pts, 0.75)

    def _wobble(self, pts, tag, amp):
        """The line wanders slowly: a bow and a gentler wave from its shape, and a second bow
        from its frame, so a boil redraws the line rather than shaking it."""
        shape, tremble = _shape(f"{self.seed}/{tag}"), _tremble(f"{self.seed}/{tag}")
        length = _length(pts) or 1.0
        reach = min(1.0, length / 14) * amp
        waves = [
            (0.3 * reach, length * shape.uniform(0.8, 1.4), shape.uniform(0, 2 * math.pi)),
            (0.1 * reach, shape.uniform(9, 14), shape.uniform(0, 2 * math.pi)),
            (0.32 * reach, length * tremble.uniform(0.6, 1.1), tremble.uniform(0, 2 * math.pi)),
        ]
        drift = (tremble.uniform(-0.22, 0.22) * reach, tremble.uniform(-0.22, 0.22) * reach)
        out, s = [], 0.0
        for i, ((x, y), (nx, ny)) in enumerate(zip(pts, _normals(pts), strict=True)):
            if i:
                s += math.dist(pts[i - 1], pts[i])
            e = sum(a * math.sin(2 * math.pi * s / lam + ph) for a, lam, ph in waves)
            out.append((x + nx * e + drift[0], y + ny * e + drift[1]))
        return out

    def subpaths(self):
        line = self._wobble(self.pts, "line", self.amp)
        paths = [_simplify(line)]
        length = _length(line)
        if self.press and length > 13:
            shape = _shape(f"{self.seed}/press")
            a, b = shape.uniform(0.16, 0.32), shape.uniform(0.6, 0.82)
            side = shape.choice((-1, 1))
            ia, ib = int(len(line) * a), int(len(line) * b)
            part = line[ib:ia:-1]  # the pen goes back over the middle
            k = len(part) - 1 or 1
            lean = 0.34 * min(1.0, length / 22)
            part = [
                (
                    x + nx * side * lean * math.sin(math.pi * i / k),
                    y + ny * side * lean * math.sin(math.pi * i / k),
                )
                for i, ((x, y), (nx, ny)) in enumerate(zip(part, _normals(part), strict=True))
            ]
            paths.append(_simplify(self._wobble(part, "pass", self.amp * 0.4)))
        return paths

    @property
    def d(self):
        return "".join(self.subpaths())


def drawn(*inks):
    """Several lines in one path (one class, one draw): their subpaths, in order."""
    return "".join(ink.d for ink in inks)


def stroke(points, seed, amp=1.0, press=True, run=(0.2, 0.9), curve=False):
    """A freehand stroke through `points`. curve=True bends it through them; otherwise it is
    straight between them and its corners are drawn in one go. It runs on past its last point by
    a little (`run`, in units)."""
    shape = _shape(seed)
    pts = _catmull(points) if curve else list(points)
    (x0, y0), (x1, y1) = pts[-2], pts[-1]
    d = math.hypot(x1 - x0, y1 - y0) or 1.0
    on = shape.uniform(*run)
    pts[-1] = (x1 + (x1 - x0) / d * on, y1 + (y1 - y0) / d * on)
    return Ink(pts, seed, amp=amp, press=press)


def outline(points, seed, amp=1.0, press=True, over=(-0.5, 1.4), closed=True):
    """A polygon drawn side by side: each side its own stroke, starting a little before or after
    its corner and running on past the next one, so corners cross or fall just short."""
    shape = _shape(seed)
    pts = list(points) + ([points[0]] if closed and points[0] != points[-1] else [])
    inks = []
    for i, ((x0, y0), (x1, y1)) in enumerate(zip(pts, pts[1:], strict=False)):
        d = math.hypot(x1 - x0, y1 - y0) or 1.0
        ux, uy = (x1 - x0) / d, (y1 - y0) / d
        a, b = shape.uniform(*over) * 0.6, shape.uniform(*over)
        start = (x0 - ux * a, y0 - uy * a)
        end = (x1 + ux * b, y1 + uy * b)
        inks.append(Ink([start, end], f"{seed}/{i}", amp=amp, press=press and d > 14))
    return inks


def ring(cx, cy, rx, seed, ry=None, amp=1.0, press=True, tilt=0.0, over=(0.25, 0.5), a0=None):
    """A ring drawn in one go: it starts and ends a little apart (overlapping by `over` of a
    radian) and its radius drifts as it goes round, the way a hand closes a circle."""
    shape = _shape(seed)
    ry = rx if ry is None else ry
    a0 = shape.uniform(0, 2 * math.pi) if a0 is None else math.radians(a0)
    sweep = 2 * math.pi + shape.uniform(*over)
    drift = shape.choice((-1, 1)) * shape.uniform(0.04, 0.08)
    ct, st = math.cos(math.radians(tilt)), math.sin(math.radians(tilt))
    n = max(16, int(sweep * max(rx, ry) / 0.9))
    pts = []
    for i in range(n + 1):
        t = i / n
        a = a0 + sweep * t
        k = 1 + drift * (t - 0.5)
        x, y = rx * k * math.cos(a), ry * k * math.sin(a)
        pts.append((cx + x * ct - y * st, cy + x * st + y * ct))
    return Ink(pts, seed, amp=amp * min(1.0, max(rx, ry) / 9), press=press)


def coil(cx, cy, r0, r1, turns, seed, a0=0.0, amp=1.0, press=True):
    """A spiral from r0 out to r1, by the same hand."""
    n = max(24, int(turns * 40))
    pts = []
    for i in range(n + 1):
        t = i / n
        a = math.radians(a0) + 2 * math.pi * turns * t
        r = r0 + (r1 - r0) * t
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return Ink(pts, seed, amp=amp, press=press)


def ripple(x0, x1, y, amp, length, seed, fade=None, phase=0.0, press=True, tremor=1.0):
    """A wave, drawn: its height may fade along it (`fade(t)`, 0 to 1)."""
    n = max(12, int((x1 - x0) / 0.8))
    pts = []
    for i in range(n + 1):
        t = i / n
        x = x0 + (x1 - x0) * t
        a = amp * (fade(t) if fade else 1)
        pts.append((x, y + a * math.sin(2 * math.pi * (x - x0) / length + phase)))
    return Ink(pts, seed, amp=tremor, press=press)


def blot(cx, cy, r, seed, ry=None, rough=0.07, tilt=0.0):
    """A filled shape set down by hand: the clay dot (a little rough) or a wash (rougher)."""
    shape, tremble = _shape(seed), _tremble(seed)
    ry = r if ry is None else ry
    a0 = shape.uniform(0, 2 * math.pi)
    lobes = [(shape.uniform(0.5, 1) * rough, shape.uniform(0, 2 * math.pi)) for _ in (2, 3)]
    quiver = (tremble.uniform(0.25, 0.5) * rough, tremble.uniform(0, 2 * math.pi))
    ct, st = math.cos(math.radians(tilt)), math.sin(math.radians(tilt))
    pts = []
    for i in range(12):
        a = a0 + 2 * math.pi * i / 12
        k = 1 + lobes[0][0] * math.sin(2 * a + lobes[0][1])
        k += lobes[1][0] * math.sin(3 * a + lobes[1][1]) + quiver[0] * math.sin(4 * a + quiver[1])
        x, y = r * k * math.cos(a), ry * k * math.sin(a)
        pts.append((cx + x * ct - y * st, cy + x * st + y * ct))
    return smooth(pts, closed=True)


DOT = 2.6  # the clay dot's radius, the same in every drawing by this hand


def clay_dot(cx, cy, seed):
    """The clay dot: set down last, never touching the ink (icons/README.md, "The clay dot")."""
    return blot(cx, cy, DOT, seed, rough=0.03)


def wash(cx, cy, rx, ry, seed, tilt=-8.0):
    """The pale clay wash behind a drawing, a little off it, like watercolour."""
    return blot(cx, cy, rx, seed, ry=ry, rough=0.11, tilt=tilt)
