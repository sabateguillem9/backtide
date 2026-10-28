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
from hand import TREMOR, circle, crescent, f, line, smooth, spiral, wave  # noqa: E402

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


def icon(name, meaning):
    def register(fn):
        ICONS[name] = fn()
        MEANING[name] = meaning
        return fn

    return register


@icon("progress", "In progress: a spiral still being drawn.")
def _progress():
    return [
        ("spin", "ink", spiral(24, 24, 1.2, 16.5, 2.25, 11, amp=0.45)),
        ("spin", "fill", dot(24, 24, 2.2, 12)),
    ]


@icon("preview", "Preview: a cairn that stands up on its own.")
def _preview():
    return [
        ("ground", "faint", line([(5, 44), (24, 43.4), (43, 44)], 21, amp=0.4, step=6)),
        ("stones", "ink", circle(24, 37.5, 15, 22, amp=0.6, ry=5.4)),
        ("stones", "ink", circle(23, 27.5, 10.8, 23, amp=0.5, ry=4.4)),
        ("stones", "ink", circle(24.6, 19.7, 7, 24, amp=0.4, ry=3.4)),
        ("stones", "fill", circle(24.2, 13.8, 3.6, 25, amp=0.2, ry=2.5, closed=True)),
    ]


@icon("done", "Done: a moon over still water.")
def _done():
    return [
        ("moon", "soft", crescent(22, 17, 10, 31, amp=0.3)),
        ("moon", "ink", crescent(22, 17, 10, 31, amp=0.3)),
        ("water", "ink", line([(5, 33), (24, 32.4), (43, 33)], 32, amp=0.4, step=6)),
        ("water", "faint", line([(13, 39), (35, 38.6)], 33, amp=0.3, step=6)),
    ]


@icon("tape", "backtide itself: a cassette whose reels turn back.")
def _tape():
    return [
        (
            "tape",
            "ink",
            line([(5, 13), (43, 12.4), (43.4, 36.4), (4.6, 37), (5, 13)], 41, amp=0.45, step=6),
        ),
        (
            "tape",
            "faint",
            line([(12, 18.4), (36, 18), (36.2, 29), (11.8, 29.4), (12, 18.4)], 42, amp=0.3, step=5),
        ),
        (
            "tape",
            "ink",
            line([(12, 37), (14.4, 31.6), (33.6, 31.4), (36, 36.8)], 43, amp=0.3, step=4),
        ),
        ("reelL", "ink", circle(17.5, 23.6, 3.6, 44, amp=0.2)),
        ("reelL", "ink", line([(17.5, 23.6), (17.5, 20.4)], 45, amp=0.1, step=2)),
        ("reelL", "fill", dot(17.5, 23.6, 1.6, 46)),
        ("reelR", "ink", circle(30.5, 23.6, 3.6, 47, amp=0.2)),
        ("reelR", "ink", line([(30.5, 23.6), (30.5, 20.4)], 48, amp=0.1, step=2)),
    ]


@icon("notebook", "The logbook, the history: an open notebook.")
def _notebook():
    return [
        ("book", "ink", line([(5, 15), (15, 11.5), (24, 15.5)], 51, curve=True)),
        ("book", "ink", line([(24, 15.5), (33, 11.5), (43, 15)], 52, curve=True)),
        ("book", "ink", line([(5, 15), (5.4, 37)], 53, amp=0.3, step=5)),
        ("book", "ink", line([(43, 15), (42.6, 37)], 54, amp=0.3, step=5)),
        (
            "book",
            "ink",
            line([(5.4, 37), (15, 33.6), (24, 37.6), (33, 33.6), (42.6, 37)], 55, curve=True),
        ),
        ("page", "clay", line([(24, 15.5), (24, 37.6)], 56, amp=0.3, step=5)),
        ("page", "faint", line([(10, 21), (19, 19)], 57, amp=0.2, step=4)),
        ("page", "faint", line([(10, 26), (18, 24.4)], 58, amp=0.2, step=4)),
    ]


@icon("pencil", "How it was made, writing, editing: a pencil and its trail.")
def _pencil():
    ax, ay, bx, by = 15.0, 35.0, 37.0, 13.0
    px, py = 2.6, 2.6  # half width, perpendicular to the axis
    tx, ty = 9.4, 40.6  # the point
    return [
        ("pencil", "ink", line([(ax + px, ay + py), (bx + px, by + py)], 61, amp=0.3, step=5)),
        ("pencil", "ink", line([(ax - px, ay - py), (bx - px, by - py)], 62, amp=0.3, step=5)),
        ("pencil", "ink", line([(bx + px, by + py), (bx - px, by - py)], 63, amp=0.2, step=3)),
        (
            "pencil",
            "ink",
            line([(ax + px, ay + py), (tx, ty), (ax - px, ay - py)], 64, amp=0.2, step=3),
        ),
        (
            "pencil",
            "fill",
            smooth([(tx, ty), (tx + 2.4, ty - 0.6), (tx + 0.6, ty - 2.4)], closed=True),
        ),
        (
            "pencil",
            "faint",
            line(
                [(bx - 3.4 + px, by + 3.4 + py), (bx - 3.4 - px, by + 3.4 - py)],
                65,
                amp=0.2,
                step=3,
            ),
        ),
        ("trail", "faint", wave(12, 42, 44.5, 1.2, 10, 66, jitter=0.2, step=1.5)),
    ]


@icon("scale", "Legal, rules, weighing a decision: a balance.")
def _scale():
    parts = [
        ("post", "ink", line([(24, 13), (24.3, 40)], 71, amp=0.3, step=5)),
        ("post", "ink", line([(14, 41), (34, 40.6)], 72, amp=0.3, step=5)),
        ("beam", "ink", line([(8, 14.4), (24, 13.6), (40, 14.2)], 73, amp=0.3, step=5)),
        ("beam", "fill", dot(24, 12.4, 2.3, 74)),
    ]
    for x, seed in ((8.0, 75), (40.0, 79)):
        parts += [
            ("beam", "ink", line([(x, 14.4), (x - 4.2, 26)], seed, amp=0.2, step=4)),
            ("beam", "ink", line([(x, 14.4), (x + 4.2, 26)], seed + 1, amp=0.2, step=4)),
            ("beam", "ink", arc(x, 25.6, 5.4, 0, 180, seed + 2, amp=0.2, n=10)),
        ]
    return parts


@icon("records", "It records: a dot that leaves a line behind it.")
def _records():
    return [
        (
            "trace",
            "ink",
            wave(
                5,
                33,
                27,
                3.6,
                11.5,
                81,
                jitter=0.25,
                step=1.2,
                fade=lambda t: (1 - t) ** 0.9 + 0.08,
            ),
        ),
        ("dot", "fill", dot(38.5, 27, 4.2, 82)),
    ]


@icon("rewinds", "It rewinds: a loop that turns back on itself.")
def _rewinds():
    return [
        ("loop", "ink", arc(24, 24, 14, -40, -310, 91, amp=0.4, n=26)),
        ("loop", "ink", arrowhead(24, 24, 14, -310, 92)),
        ("loop", "fill", dot(24, 24, 3.2, 93)),
    ]


@icon("holds", "It holds, a held request: a padlock.")
def _holds():
    shackle = [(17, 22.4)] + [
        (24 + 7 * math.cos(math.radians(a)), 15 + 7 * math.sin(math.radians(a)))
        for a in range(180, 361, 20)
    ]
    shackle += [(31, 22)]
    return [
        ("shackle", "ink", smooth(shackle)),
        (
            "body",
            "ink",
            line(
                [(12, 22.4), (36, 21.8), (36.6, 41.4), (11.6, 41.8), (12, 22.4)],
                101,
                amp=0.45,
                step=6,
            ),
        ),
        ("body", "fill", dot(24, 30.6, 2.6, 102)),
        ("body", "ink", line([(24, 32.6), (24.2, 36.4)], 103, amp=0.15, step=2)),
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
   Colours and motion come from bundle.css and motion.css (.ic, .ic-ink, .ic-g-...). */
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
  window.BacktideIcons = { names: Object.keys(DATA), make: make };
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
    data = {
        name: [{"g": g, "c": cls, "d": d} for g, cls, d in parts] for name, parts in ICONS.items()
    }
    (HERE / "icons.js").write_text(JS_HEAD + json.dumps(data, separators=(",", ":")) + JS_TAIL)
    print(f"wrote {len(ICONS)} icons: svg/*.svg and icons.js")


if __name__ == "__main__":
    main()
