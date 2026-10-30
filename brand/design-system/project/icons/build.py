"""The backtide icons: hand-drawn, one regular stroke, one touch of clay.

Every icon is drawn here with hand.py (fixed seeds, so the output never changes between
runs) on a 48 x 48 grid, and written three ways:

- svg/<name>.svg: one file per icon, with its colours as presentation attributes, for slides,
  documents and anything that shows an SVG file as it is;
- icons.js: the same paths as data, plus a tiny builder (createElementNS, never markup), for
  pages that draw rows from JavaScript;
- icon_svg(name): the inline markup, for pages built by a script (build.py next door).

The rule for drawing a new icon is in README.md, in this folder.

Run: python3 brand/design-system/project/icons/build.py
"""

# The seeded random numbers only add a wobble to the drawings; nothing here is security.
# ruff: noqa: S311

import json
import math
import pathlib
import random
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hand  # noqa: E402
from hand import (  # noqa: E402
    TREMOR,
    circle,
    clay_dot,
    coil,
    drawn,
    f,
    line,
    outline,
    ring,
    ripple,
    smooth,
    stroke,
)

TOKENS = HERE.parent / "tokens.json"
DRAWN = ("ink", "clay", "faint")  # stroked classes, drawn on with pathLength="1"

# ---------------------------------------------------------------- helpers


def arc(cx, cy, r, a0, a1, seed, amp=0.35, n=None):
    """A clean arc from angle a0 to a1 (degrees, y down), with the same slow wobble."""
    rng = random.Random(seed)
    wob_a, wob_p = amp * TREMOR, rng.uniform(0, 2 * math.pi)
    n = n or max(6, round(abs(a1 - a0) / 30))
    pts = []
    for i in range(n + 1):
        a = math.radians(a0 + (a1 - a0) * i / n)
        rr = r + wob_a * math.sin(2 * a + wob_p)
        pts.append((cx + rr * math.cos(a), cy + rr * math.sin(a)))
    return smooth(pts)


def arrowhead(cx, cy, r, a_end, seed, size=5.0, spread=34, direction=-1):
    """Two short wings at the end of an arc, pointing the way the arc travels."""
    a = math.radians(a_end)
    tip = (cx + r * math.cos(a), cy + r * math.sin(a))
    tx, ty = (math.sin(a), -math.cos(a)) if direction < 0 else (-math.sin(a), math.cos(a))
    bx, by = -tx * size, -ty * size
    wings = []
    for sgn in (1, -1):
        s = math.radians(spread * sgn)
        wings.append(
            (
                tip[0] + bx * math.cos(s) - by * math.sin(s),
                tip[1] + bx * math.sin(s) + by * math.cos(s),
            )
        )
    return line([wings[0], tip, wings[1]], seed, amp=0.15, step=3)


def bezier(segments, seed, amp=0.9):
    """Cubic Bezier segments [(p0, c1, c2, p3), ...], drawn as they are: only the control
    points move a little, so the curve stays smooth and its joints stay where they are."""
    rng = random.Random(seed)
    k = amp * TREMOR

    def nudge(p):
        return (p[0] + rng.uniform(-k, k), p[1] + rng.uniform(-k, k))

    d = [f"M{f(segments[0][0][0])} {f(segments[0][0][1])}"]
    for _p0, c1, c2, p3 in segments:
        c1, c2 = nudge(c1), nudge(c2)
        d.append(f"C{f(c1[0])} {f(c1[1])} {f(c2[0])} {f(c2[1])} {f(p3[0])} {f(p3[1])}")
    return "".join(d)


def dot(cx, cy, r, seed):
    """The clay dot: an almost perfect circle, filled."""
    return circle(cx, cy, r, seed, amp=0.1, closed=True)


# ---------------------------------------------------------------- the icons
# Each icon is a list of parts; each part is (gesture group, class, path).
# Classes: ink (drawn stroke), clay (drawn clay stroke), faint (drawn light stroke),
# fill (the clay shape that appears after the strokes), soft (pale clay fill under a stroke).
# Seeds: each icon owns a block of ten (progress 10-19, preview 20-29, ...), never shared.

ICONS: dict[str, list[tuple[str, str, str]]] = {}
MEANING: dict[str, str] = {}
# The boil (motion/boil.js): for a drawing by the field hand, its parts drawn again as frames
# 1 and 2 (only the tremor changes). The steady hand ignores the frame, so its drawings have none.
BOIL: dict[str, list[list[str]]] = {}


def icon(name, meaning):
    def register(fn):
        ICONS[name] = fn()
        MEANING[name] = meaning
        frames = []
        for k in range(1, hand.FRAMES):
            hand.frame(k)
            frames.append([d for _g, _c, d in fn()])
        hand.frame(0)
        if any(fd != d for fr in frames for fd, (_g, _c, d) in zip(fr, ICONS[name], strict=True)):
            BOIL[name] = [list(ds) for ds in zip(*frames, strict=True)]
        return fn

    return register


# ---- drawn by the field hand (hand.py), the first round of the redesign (2026-10-30) ------
# The drawings shown on backtide labs. One clay dot each, of radius hand.DOT, set down last and
# never touching the ink (README.md, "The clay dot"). Group names and pivots are the old ones,
# so motion.css and idle.css move them as before.


@icon("progress", "In progress: a spiral still being drawn out from its dot.")
def _progress():
    # The dot sits at the centre, where the spiral starts; the spiral starts far enough out
    # that the two never touch (about 1.5 units of paper at 24 px).
    return [
        ("spin", "ink", drawn(coil(24, 24, 5.8, 16, 1.6, 11, a0=200))),
        ("spin", "fill", clay_dot(24, 24, 12)),
    ]


@icon("preview", "Preview: a cairn that stands up on its own, a pebble set on top.")
def _preview():
    return [
        ("ground", "faint", drawn(*outline([(5, 43.6), (24, 43), (43.2, 43.8)], 21, closed=False))),
        ("stones", "ink", drawn(ring(24, 37.2, 14.6, 22, ry=5.2, tilt=-2))),
        ("stones", "ink", drawn(ring(23.2, 27, 10.6, 23, ry=4.6, tilt=3))),
        ("stones", "ink", drawn(ring(24.4, 18.6, 7, 24, ry=3.6, tilt=-4))),
        ("stones", "fill", clay_dot(24.6, 10.8, 25)),
    ]


def _moon(cx, cy, r, seed):
    """A crescent opening to the right: the outer arc and the inner one, two strokes whose ends
    cross at the horns."""
    top, bot = math.radians(-58), math.radians(58)
    outer = [
        (cx + r * math.cos(a), cy + r * math.sin(a))
        for a in (bot + (2 * math.pi - (bot - top)) * i / 40 for i in range(41))
    ]
    ox = r * 0.5
    h_top, h_bot = outer[-1], outer[0]
    rin = math.dist(h_top, (cx + ox, cy))
    at = math.atan2(h_top[1] - cy, h_top[0] - cx - ox) % (2 * math.pi)
    ab = math.atan2(h_bot[1] - cy, h_bot[0] - cx - ox) % (2 * math.pi)
    inner = [
        (cx + ox + rin * math.cos(a), cy + rin * math.sin(a))
        for a in (at + (ab - at) * i / 30 for i in range(31))
    ]
    return drawn(
        stroke(outer, f"{seed}/out", run=(0.6, 1.2)), stroke(inner, f"{seed}/in", run=(0.4, 1.0))
    )


@icon("done", "Done: a moon over still water, its light on the water.")
def _done():
    return [
        ("moon", "ink", _moon(21, 16.5, 10.4, 31)),
        ("water", "ink", drawn(*outline([(4.6, 31.6), (24, 31), (43.4, 31.8)], 32, closed=False))),
        ("water", "faint", drawn(stroke([(9, 37.6), (17.4, 37.3)], 33, press=False))),
        ("water", "faint", drawn(stroke([(27.4, 37.4), (38.6, 37.1)], 34, press=False))),
        ("water", "faint", drawn(stroke([(14, 42.6), (32, 42.3)], 35, press=False))),
        ("water", "fill", clay_dot(22.4, 37.4, 36)),
    ]


@icon("tape", "backtide itself: a cassette whose reels turn back.")
def _tape():
    # No clay dot: backtide's own object; the mark beside its name carries the dot.
    lx, rx, cy = 17.5, 30.5, 21.8  # the reels' pivots, as in motion.css
    return [
        ("tape", "ink", drawn(*outline([(5, 11), (43, 10.6), (43.3, 37), (4.7, 37.3)], 41))),
        (
            "tape",
            "faint",
            drawn(
                *outline([(11.4, 15), (36.6, 14.8), (36.8, 28.6), (11.2, 28.8)], 42, press=False)
            ),
        ),
        (
            "tape",
            "ink",
            drawn(
                *outline(
                    [(13.2, 37.2), (15.6, 32.4), (32.4, 32.2), (34.8, 37)],
                    43,
                    closed=False,
                    press=False,
                )
            ),
        ),
        ("reelL", "ink", drawn(coil(lx, cy, 1.1, 4.4, 1.5, 44, a0=200))),
        ("reelR", "ink", drawn(coil(rx, cy, 1.1, 4.4, 1.5, 47, a0=20))),
    ]


@icon("notebook", "The logbook, the history: an open notebook, its last line and full stop.")
def _notebook():
    return [
        ("book", "ink", drawn(stroke([(5, 14.6), (15, 11), (24, 15.2)], 51, curve=True))),
        ("book", "ink", drawn(stroke([(24, 15.2), (33, 11), (43, 14.6)], 52, curve=True))),
        ("book", "ink", drawn(stroke([(5, 14.6), (5.4, 37.4)], 53))),
        ("book", "ink", drawn(stroke([(43, 14.6), (42.6, 37.4)], 54))),
        (
            "book",
            "ink",
            drawn(
                stroke(
                    [(5.4, 37.4), (15, 33.8), (24, 38), (33, 33.8), (42.6, 37.4)], 55, curve=True
                )
            ),
        ),
        ("book", "faint", drawn(stroke([(28.6, 22.4), (35.4, 21)], 59, press=False))),
        ("book", "fill", clay_dot(37.8, 26.1, 50)),
        ("book", "faint", drawn(stroke([(28.6, 27.6), (33.8, 26.6)], "59/2", press=False))),
        ("page", "ink", drawn(stroke([(24, 15.2), (24, 38)], 56))),
        ("page", "faint", drawn(stroke([(10, 21.4), (19.4, 19.6)], 57, press=False))),
        ("page", "faint", drawn(stroke([(10, 26.6), (18.4, 25)], 58, press=False))),
    ]


@icon("pencil", "How it was made, writing, editing: a sharpened pencil, its point on the paper.")
def _pencil():
    # Drawn with a calmer hand than the rest (amp 0.35, crisp corners): a well-made tool.
    tx, ty = 11.2, 37.8  # the point
    ux, uy, vx, vy = 0.7071, -0.7071, 0.7071, 0.7071  # along the pencil, across it

    def at(s, t):
        return (tx + ux * s + vx * t, ty + uy * s + vy * t)

    w, cone, body, ferrule, end = 3.4, 8.2, 29.6, 33.2, 36.4
    calm = {"amp": 0.35, "run": (0.0, 0.25)}
    return [
        ("pencil", "ink", drawn(stroke([at(cone, w), at(body, w)], 61, **calm))),
        ("pencil", "ink", drawn(stroke([at(cone, -w), at(body, -w)], 62, **calm))),
        (
            "pencil",
            "ink",
            drawn(stroke([at(cone, w), at(0, 0), at(cone, -w)], 64, press=False, **calm)),
        ),
        ("pencil", "ink", drawn(stroke([at(2.9, 1.25), at(2.9, -1.25)], 65, press=False, **calm))),
        ("pencil", "faint", drawn(stroke([at(cone, w), at(cone, -w)], 63, press=False, **calm))),
        (
            "pencil",
            "ink",
            drawn(
                *outline(
                    [at(body, w), at(ferrule, w), at(ferrule, -w), at(body, -w)],
                    67,
                    press=False,
                    amp=0.35,
                    over=(-0.2, 0.5),
                )
            ),
        ),
        (
            "pencil",
            "ink",
            drawn(
                stroke(
                    [
                        at(ferrule, w),
                        at(end, w * 0.8),
                        at(end + 0.9, 0),
                        at(end, -w * 0.8),
                        at(ferrule, -w),
                    ],
                    68,
                    curve=True,
                    press=False,
                    **calm,
                )
            ),
        ),
        ("trail", "faint", drawn(ripple(14.6, 41, 42.8, 0.9, 8, 66, press=False, tremor=0.3))),
        ("trail", "fill", clay_dot(*at(-4.4, 0), 69)),
    ]


@icon("scale", "Legal, rules, weighing a decision: a balance, its pivot in clay.")
def _scale():
    # The same calm hand as the pencil: a well-made instrument. The clay dot is the pivot's
    # finial, above the beam, never touching it.
    calm = {"amp": 0.35, "run": (0.0, 0.2)}
    parts = [
        ("post", "ink", drawn(stroke([(24, 14.6), (24.1, 40.4)], 71, **calm))),
        ("post", "ink", drawn(stroke([(15.4, 40.8), (32.8, 40.6)], 72, press=False, **calm))),
        (
            "beam",
            "ink",
            drawn(stroke([(8.4, 13.9), (24, 13.5), (39.6, 13.8)], 73, curve=True, **calm)),
        ),
        ("beam", "fill", clay_dot(24, 7.8, 74)),
    ]
    for x, seed in ((8.4, 75), (39.6, 79)):
        y = 13.9 if x < 24 else 13.8
        parts += [
            ("beam", "ink", drawn(stroke([(x, y), (x - 4.4, 26.4)], seed, press=False, **calm))),
            (
                "beam",
                "ink",
                drawn(stroke([(x, y), (x + 4.4, 26.4)], seed + 1, press=False, **calm)),
            ),
            (
                "beam",
                "ink",
                drawn(
                    stroke(
                        [
                            (x - 5.2, 26.4),
                            (x - 3.4, 29.4),
                            (x, 30.6),
                            (x + 3.4, 29.4),
                            (x + 5.2, 26.4),
                        ],
                        seed + 2,
                        curve=True,
                        press=False,
                        **calm,
                    )
                ),
            ),
        ]
    return parts


@icon("records", "It records: a dot that leaves a line behind it.")
def _records():
    return [
        (
            "trace",
            "ink",
            drawn(
                ripple(
                    4.6, 31.4, 24, 5.4, 11.5, 81, fade=lambda t: (1 - t) ** 0.85 + 0.1, tremor=0.6
                )
            ),
        ),
        ("trace", "faint", drawn(stroke([(6, 35.4), (30, 35)], 83, press=False))),
        ("dot", "fill", clay_dot(36.8, 23.6, 82)),
    ]


@icon("rewinds", "It rewinds: a loop that turns back on itself.")
def _rewinds():
    r, a_end = 14.4, -312
    tip = (24 + r * math.cos(math.radians(a_end)), 24 + r * math.sin(math.radians(a_end)))
    a = math.radians(a_end)
    tx, ty = math.sin(a), -math.cos(a)  # the way the loop travels at its end
    wings = []
    for sgn in (1, -1):
        s = math.radians(36 * sgn)
        bx, by = -tx * 5.6, -ty * 5.6
        wings.append(
            (
                tip[0] + bx * math.cos(s) - by * math.sin(s),
                tip[1] + bx * math.sin(s) + by * math.cos(s),
            )
        )
    arc_pts = [
        (24 + r * math.cos(math.radians(d)), 24 + r * math.sin(math.radians(d)))
        for d in (-36 + (a_end + 36) * i / 48 for i in range(49))
    ]
    return [
        ("loop", "ink", drawn(stroke(arc_pts, 91, run=(0.0, 0.2)))),
        (
            "loop",
            "ink",
            drawn(
                stroke([wings[0], tip], 92, press=False, run=(0.3, 0.6)),
                stroke([wings[1], tip], 94, press=False, run=(0.2, 0.5)),
            ),
        ),
        ("loop", "fill", clay_dot(24, 24, 93)),
    ]


@icon("holds", "It holds, a held request: a padlock.")
def _holds():
    shackle = (
        [(16.8, 23.4)]
        + [
            (24 + 7.2 * math.cos(math.radians(a)), 15.4 + 7.2 * math.sin(math.radians(a)))
            for a in range(180, 361, 15)
        ]
        + [(31.2, 21.6)]
    )
    return [
        ("shackle", "ink", drawn(stroke(shackle, 104, run=(0.0, 0.3)))),
        (
            "body",
            "ink",
            drawn(*outline([(11.2, 22.4), (36.8, 21.9), (37.2, 41.6), (10.8, 42)], 101)),
        ),
        ("body", "fill", clay_dot(24, 29.6, 102)),
        ("body", "ink", drawn(stroke([(24, 34), (24.2, 37.4)], 103, press=False))),
    ]


# ---- added for the product web (phase 3) and for notices --------------------------------


@icon("approve", "Approve, done by you: a tick on a pale disc.")
def _approve():
    return [
        ("disc", "soft", circle(24, 24, 17, 111, amp=0.5, closed=True)),
        ("tick", "ink", line([(14.5, 24.5), (21, 31.4), (34, 16.4)], 112, amp=0.35, step=4)),
    ]


@icon("reject", "Reject, not allowed: a cross in a faint ring.")
def _reject():
    return [
        ("ring", "faint", circle(24, 24, 17, 121, amp=0.5)),
        ("cross", "ink", line([(17, 17), (31, 31.2)], 122, amp=0.3, step=4)),
        ("cross", "ink", line([(31.2, 16.8), (16.8, 31)], 123, amp=0.3, step=4)),
    ]


@icon("info", "Information: a ring with an i, its dot in clay.")
def _info():
    return [
        ("ring", "ink", circle(24, 24, 17.5, 131, amp=0.5)),
        ("stem", "ink", line([(24, 22), (24.2, 33.6)], 132, amp=0.2, step=3)),
        ("mark", "fill", dot(24, 15.6, 2.3, 133)),
    ]


@icon("warning", "Something to look at: a triangle with its mark.")
def _warning():
    return [
        (
            "sign",
            "ink",
            line([(24, 6.5), (42.4, 39.2), (5.6, 39.6), (24, 6.5)], 141, amp=0.4, step=6),
        ),
        ("sign", "ink", line([(24, 17.6), (24.1, 28)], 142, amp=0.2, step=3)),
        ("sign", "fill", dot(24.1, 33.2, 2.1, 143)),
    ]


@icon("key", "Keys and settings: an old key.")
def _key():
    return [
        ("key", "ink", circle(14.5, 24, 7.5, 151, amp=0.3)),
        ("key", "fill", dot(14.5, 24, 2.3, 152)),
        ("key", "ink", line([(22, 24), (42, 23.6)], 153, amp=0.3, step=5)),
        ("key", "ink", line([(35, 23.8), (35.2, 30.4)], 154, amp=0.15, step=2)),
        ("key", "ink", line([(40.4, 23.7), (40.5, 28.6)], 155, amp=0.15, step=2)),
    ]


@icon("bell", "Alerts on your phone: a bell and its clapper.")
def _bell():
    dome = smooth(
        [
            (10.5, 35),
            (14.2, 30.5),
            (15, 22),
            (18.6, 14.4),
            (24, 12),
            (29.4, 14.4),
            (33, 22),
            (33.8, 30.5),
            (37.5, 35),
        ]
    )
    return [
        ("bell", "ink", dome),
        ("bell", "ink", line([(10.5, 35), (37.5, 34.6)], 161, amp=0.3, step=5)),
        ("bell", "ink", line([(24, 12), (24, 8.2)], 162, amp=0.1, step=2)),
        ("bell", "fill", dot(24, 39.2, 2.6, 163)),
    ]


@icon("flag", "A snapshot, a point to go back to: a flag on its pole.")
def _flag():
    return [
        ("ground", "faint", line([(6, 42.6), (26, 42.2)], 171, amp=0.3, step=5)),
        ("pole", "ink", line([(14, 9), (14.3, 42.4)], 172, amp=0.3, step=6)),
        (
            "cloth",
            "ink",
            line(
                [(14, 10), (37.4, 12.4), (29.6, 18.4), (38, 25), (14.2, 23.4)], 173, amp=0.3, step=5
            ),
        ),
        ("pole", "fill", dot(14, 7, 2.2, 174)),
    ]


@icon("eye", "Now, watching: an eye that blinks.")
def _eye():
    return [
        (
            "eye",
            "ink",
            bezier([((4.5, 24), (13, 12.5), (35, 12.5), (43.5, 24))], 181, amp=0.6),
        ),
        (
            "eye",
            "ink",
            bezier([((4.5, 24), (13, 35.5), (35, 35.5), (43.5, 24))], 182, amp=0.6),
        ),
        ("eye", "ink", circle(24, 24, 6.4, 183, amp=0.25)),
        ("eye", "fill", dot(24, 24, 2.6, 184)),
    ]


@icon("still", "Nothing here yet, all calm: still water and a low sun.")
def _still():
    return [
        ("sun", "fill", dot(33, 15, 3.6, 191)),
        ("water", "ink", line([(4, 30), (24, 29.5), (44, 30)], 192, amp=0.4, step=6)),
        ("water", "faint", line([(10, 36), (32, 35.7)], 193, amp=0.3, step=6)),
        ("water", "faint", line([(18, 41.4), (38, 41.1)], 194, amp=0.3, step=6)),
    ]


@icon("ask", "Ask the agent: a speech bubble.")
def _ask():
    return [
        (
            "bubble",
            "ink",
            line(
                [
                    (7, 10),
                    (41, 9.6),
                    (41.4, 31.6),
                    (22.4, 32),
                    (13.6, 39.8),
                    (14.6, 32.2),
                    (6.8, 32.4),
                    (7, 10),
                ],
                201,
                amp=0.4,
                step=6,
            ),
        ),
        ("bubble", "faint", line([(13, 17.4), (34, 17)], 202, amp=0.2, step=4)),
        ("bubble", "faint", line([(13, 23.6), (26, 23.3)], 203, amp=0.2, step=4)),
        ("bubble", "fill", dot(31.6, 23.6, 2.1, 204)),
    ]


# ---- controls: the film's player on the site ---------------------------------------------
# Glyphs for a player's bar, by the same hand, in ink only: they stand in a row of buttons,
# each with its word as a label, and the one clay thing of a player is its play dot or its
# playhead. They have no gesture: they change into one another instead (play and pause).


def _speaker(seed):
    """The speaker shared by sound and sound-off: a small box and its cone."""
    return line(
        [(7, 19.2), (14, 19), (23.6, 10.6), (24, 37.4), (14.2, 29.2), (6.8, 29), (7, 19.2)],
        seed,
        amp=0.35,
        step=5,
    )


def _corner(points, seed):
    return line(points, seed, amp=0.25, step=4)


@icon("play", "Play: a triangle pointing on.")
def _play():
    # The one control by the field hand (the founder's decision of 2026-10-30): in the film's
    # dot it boils like a drawing. Calm and crisp, so it stays a plain play triangle.
    return [
        (
            "play",
            "ink",
            drawn(
                *outline(
                    [(17.4, 11), (38.4, 23.8), (17.6, 37)],
                    211,
                    amp=0.3,
                    press=False,
                    over=(-0.2, 0.5),
                )
            ),
        ),
    ]


@icon("pause", "Pause: two upright strokes.")
def _pause():
    return [
        ("bars", "ink", line([(18, 12), (18.3, 36)], 221, amp=0.3, step=5)),
        ("bars", "ink", line([(30.2, 12), (29.9, 36)], 222, amp=0.3, step=5)),
    ]


@icon("sound", "Sound on: a speaker and two waves.")
def _sound():
    return [
        ("speaker", "ink", _speaker(231)),
        ("waves", "ink", arc(24, 24, 7.6, -42, 42, 232, amp=0.25, n=6)),
        ("waves", "ink", arc(24, 24, 14.4, -46, 46, 233, amp=0.3, n=8)),
    ]


@icon("sound-off", "Sound off: the speaker with a small cross.")
def _sound_off():
    return [
        ("speaker", "ink", _speaker(241)),
        ("cross", "ink", line([(31.4, 19.4), (40.6, 28.6)], 242, amp=0.2, step=3)),
        ("cross", "ink", line([(40.6, 19.4), (31.4, 28.6)], 243, amp=0.2, step=3)),
    ]


@icon("captions", "Captions: a screen with two lines of words.")
def _captions():
    return [
        (
            "screen",
            "ink",
            line([(5.4, 11), (42.6, 10.6), (43, 37.2), (5, 37.4), (5.4, 11)], 251, amp=0.4, step=6),
        ),
        ("words", "ink", line([(12, 25.4), (22, 25.2)], 252, amp=0.2, step=3)),
        ("words", "ink", line([(26.4, 25.2), (36, 25.1)], 253, amp=0.2, step=3)),
        ("words", "ink", line([(12, 31), (30.6, 30.8)], 254, amp=0.2, step=4)),
    ]


@icon("full-screen", "Full screen: four corners opening out.")
def _full_screen():
    return [
        ("corners", "ink", _corner([(6.6, 17), (6.4, 6.6), (17, 6.4)], 261)),
        ("corners", "ink", _corner([(31, 6.4), (41.4, 6.6), (41.6, 17)], 262)),
        ("corners", "ink", _corner([(41.6, 31), (41.4, 41.4), (31, 41.6)], 263)),
        ("corners", "ink", _corner([(17, 41.6), (6.6, 41.4), (6.4, 31)], 264)),
    ]


@icon("full-screen-exit", "Leave full screen: four corners folding in.")
def _full_screen_exit():
    return [
        ("corners", "ink", _corner([(17.2, 6.4), (17, 17), (6.4, 17.2)], 271)),
        ("corners", "ink", _corner([(30.8, 6.4), (31, 17), (41.6, 17.2)], 272)),
        ("corners", "ink", _corner([(41.6, 30.8), (31, 31), (30.8, 41.6)], 273)),
        ("corners", "ink", _corner([(6.4, 30.8), (17, 31), (17.2, 41.6)], 274)),
    ]


# ---------------------------------------------------------------- output


def groups_of(name):
    groups: dict[str, list[tuple[str, str]]] = {}
    for g, cls, d in ICONS[name]:
        groups.setdefault(g, []).append((cls, d))
    return groups


def icon_svg(name, extra=""):
    """The inline markup: classes only, coloured and animated by the CSS."""
    body = []
    for g, items in groups_of(name).items():
        paths = []
        for cls, d in items:
            length = ' pathLength="1"' if cls in DRAWN else ""
            paths.append(f'<path class="ic-{cls}"{length} d="{d}"/>')
        body.append(f'<g class="ic-g ic-g-{g}">{"".join(paths)}</g>')
    cls = f"ic ic-{name}" + (f" {extra}" if extra else "")
    return (
        f'<svg class="{cls}" viewBox="0 0 48 48" aria-hidden="true" focusable="false">'
        f"{''.join(body)}</svg>"
    )


def light_colours():
    """The light theme's ink, clay mark, line and clay soft, read from tokens.json."""
    tokens = json.loads(TOKENS.read_text())
    values = {t["name"]: t["value"] for t in tokens["color"]["tokens"]}
    pick = {"ink": "ink", "clay": "clay-mark", "faint": "line", "fill": "clay-mark"}
    colours = {cls: values[name]["light"] for cls, name in pick.items()}
    colours["soft"] = values["clay-soft"]["light"]
    return colours


def file_svg(name, colours):
    """A standalone file: the same paths, its colours as attributes, 1.75 px at any size."""
    body = []
    for g, items in groups_of(name).items():
        paths = []
        for cls, d in items:
            if cls in DRAWN:
                paint = (
                    f'fill="none" stroke="{colours[cls]}" stroke-width="1.75" '
                    'stroke-linecap="round" stroke-linejoin="round" '
                    'vector-effect="non-scaling-stroke"'
                )
            else:
                paint = f'fill="{colours[cls]}"'
            paths.append(f'<path class="ic-{cls}" {paint} d="{d}"/>')
        body.append(f'<g class="ic-g ic-g-{g}">{"".join(paths)}</g>')
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="48" height="48">'
        f"<title>{name}</title>{''.join(body)}</svg>\n"
    )


JS_HEAD = """/* backtide · the hand-drawn icons, generated by icons/build.py. Do not edit by hand.
   Use: BacktideIcons.make("holds", "extra classes") returns an <svg> built node by node with
   createElementNS (never markup), aria-hidden, ready for a page under a strict CSP.
   Colours and motion come from bundle.css and motion.css (.ic, .ic-ink, .ic-g-...).
   BacktideIcons.frames("tape") gives the boil frames of a drawing by the field hand. */
(function () {
  "use strict";
  var SVG = "http://www.w3.org/2000/svg";
  var DRAWN = ["ink", "clay", "faint"];
  var DATA = """

JS_TAIL = """;
  function make(name, extra) {
    var svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("class", "ic ic-" + name + (extra ? " " + extra : ""));
    svg.setAttribute("viewBox", "0 0 48 48");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    var parts = DATA[name] || [];
    var groups = {};
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      if (!groups[p.g]) {
        groups[p.g] = document.createElementNS(SVG, "g");
        groups[p.g].setAttribute("class", "ic-g ic-g-" + p.g);
        svg.appendChild(groups[p.g]);
      }
      var path = document.createElementNS(SVG, "path");
      path.setAttribute("class", "ic-" + p.c);
      if (DRAWN.indexOf(p.c) >= 0) path.setAttribute("pathLength", "1");
      path.setAttribute("d", p.d);
      groups[p.g].appendChild(path);
    }
    return svg;
  }
  // The boil (motion/boil.js): for each path of a drawing, in the order make() and the pages
  // write them (grouped), its frames [still, 1, 2]; null for a drawing that does not boil.
  function frames(name) {
    var parts = DATA[name] || [];
    if (!parts.length || !parts[0].b) return null;
    var order = [], seen = {};
    for (var i = 0; i < parts.length; i++) {
      if (seen[parts[i].g]) continue;
      seen[parts[i].g] = true;
      for (var j = 0; j < parts.length; j++) {
        if (parts[j].g === parts[i].g) order.push([parts[j].d].concat(parts[j].b));
      }
    }
    return order;
  }
  window.BacktideIcons = { names: Object.keys(DATA), make: make, frames: frames };
})();
"""


def main():
    out = HERE / "svg"
    out.mkdir(exist_ok=True)
    colours = light_colours()
    for old in out.glob("*.svg"):
        if old.stem not in ICONS:
            old.unlink()
    for name in ICONS:
        (out / f"{name}.svg").write_text(file_svg(name, colours))
    data = {}
    for name, parts in ICONS.items():
        boil = BOIL.get(name)
        data[name] = [
            {"g": g, "c": cls, "d": d, **({"b": boil[i]} if boil else {})}
            for i, (g, cls, d) in enumerate(parts)
        ]
    (HERE / "icons.js").write_text(JS_HEAD + json.dumps(data, separators=(",", ":")) + JS_TAIL)
    print(f"wrote {len(ICONS)} icons: svg/*.svg and icons.js")


if __name__ == "__main__":
    main()
