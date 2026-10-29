"""backtide's mark, estela (wake): the clay dot going back, and the one line it leaves behind.

Chosen by the founder from the six logo proposals (brand/propuestas-logo/, proposal 1) and drawn
here with the icons' steady hand (icons/hand.py) on their 48 x 48 grid, with the proposal's
fixed seeds (1011 for the mark, 1013 for the favicon), so every run writes the same bytes.

It writes, in light and with -dark (the dark theme's values from tokens.json):

- assets/mark.svg: the mark alone, transparent;
- assets/lockup.svg: the mark and "backtide" in a row;
- assets/lockup-stacked.svg: the mark larger, above "backtide";
- assets/lockup-labs.svg: the mark and "backtide labs" in a row;
- assets/favicon.svg: a simplified drawing on the ivory (or charcoal) rounded square;

and components/Wordmark/mark.html, the inline drawing the Wordmark component puts before the
name in every page (classes only, no colours: the line takes the name's ink, the dot clay mark).
The site and the product web copy that fragment unchanged; their tests pin it.

The line is ink, the dot clay-mark: the only clay in the mark. The line never touches the dot.
Its stroke is 2.5 units on the 48 grid (1.75 px when the mark is drawn at an icon's 24 px) and,
next to the word, matches the stem of DM Sans 500 (2.6 units with the word at 30). The
favicon's stroke is 2.6 units on its 32 grid (1.3 px at 16 px).

Run by build.py, or alone: python3 brand/design-system/project/assets/mark.py
"""

import html
import importlib.util
import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
PROJECT = HERE.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hand = _load("backtide_hand", PROJECT / "icons" / "hand.py")
f, wave = hand.f, hand.wave

STROKE = 2.5  # on the 48 grid
ROW_STROKE = 2.6  # in a lockup's units: the stem of the word at 30 units (0.085 em)
STACK_STROKE = 2.8  # in a stacked lockup's units, where the mark is the larger thing
FAV_STROKE = 2.6  # on the favicon's 32 grid: 1.3 px at 16 px, 2.6 px at 32 px
FAV_BOX = 26.0  # the favicon's drawing fits in 26 of its 32 units
ROW_SCALE = 1.35  # the mark beside the word, against the word at 30 units
ROW_GAP = 0.4  # the air between the mark and the word, in ems of the word
FONT = "'DM Sans', 'Segoe UI', system-ui, sans-serif"
# DM Sans 500, measured in the browser at 100 px: "backtide" 380.4, "backtide labs" 575.7,
# x-height 49.6, ascender 71.2. The wordmark's tracking is -0.005em.
ADV = {"backtide": 3.804, "backtide labs": 5.757}
TRACK = -0.005
X_HEIGHT, ASCENDER = 0.496, 0.712
WORD = 30.0  # the word's size in every lockup
AIR = 5.0  # the margin inside a lockup file
TITLE = "backtide"


def colours():
    tokens = json.loads((PROJECT / "tokens.json").read_text())
    values = {c["name"]: c["value"] for c in tokens["color"]["tokens"]}
    return {
        theme: {name: values[name][theme] for name in ("paper", "ink", "clay-mark")}
        for theme in ("light", "dark")
    }


COL = colours()
PAINT = {"ink": "ink", "dot": "clay-mark"}

# ---------------------------------------------------------------- the drawing
# A part is (class, shape): "ink", a stroke with its path d; "dot", the clay dot (cx, cy, r),
# a true circle, the brand's only round shape.


def mark_parts():
    """The dot at the left, looking back; the line behind it, wavy far away, almost still
    beside it, where it has come back to."""
    trail = wave(21, 44.5, 24, 2.6, 13, 1011, jitter=0.15, fade=lambda t: 0.08 + 0.92 * t**1.3)
    return [("ink", trail), ("dot", (11.5, 24, 6.8))]


def favicon_parts():
    """Fewer waves and a thicker line, so the gesture survives at 16 px."""
    trail = wave(25, 43, 24, 3.2, 15, 1013, jitter=0.1, fade=lambda t: 0.15 + 0.85 * t)
    return [("ink", trail), ("dot", (13.5, 24, 8.8))]


def bbox(parts, sw=STROKE):
    """Every point and control point of the strokes, the dot, and half a stroke around."""
    xs, ys = [], []
    for cls, shape in parts:
        if cls == "dot":
            cx, cy, r = shape
            xs += [cx - r, cx + r]
            ys += [cy - r, cy + r]
        else:
            nums = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", shape)]
            xs += nums[0::2]
            ys += nums[1::2]
    pad = sw / 2
    return min(xs) - pad, min(ys) - pad, max(xs) + pad, max(ys) + pad


# ---------------------------------------------------------------- the files


def body(parts, theme, sw=STROKE):
    out = []
    for cls, shape in parts:
        if cls == "dot":
            cx, cy, r = shape
            out.append(
                f'<circle cx="{f(cx)}" cy="{f(cy)}" r="{f(r)}" fill="{COL[theme]["clay-mark"]}"/>'
            )
        else:
            out.append(
                f'<path d="{shape}" fill="none" stroke="{COL[theme][PAINT[cls]]}" '
                f'stroke-width="{f(sw)}" stroke-linecap="round" stroke-linejoin="round"/>'
            )
    return "".join(out)


def placed(parts, theme, tx, ty, scale, sw):
    """The mark moved and scaled into a lockup or a favicon, its stroke kept at sw there."""
    t = f"translate({f(tx)} {f(ty)})" + (f" scale({f(scale)})" if scale != 1 else "")
    return f'<g transform="{t}">' + body(parts, theme, sw=sw / scale) + "</g>"


def svg_open(w, h):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {f(w)} {f(h)}" '
        f'width="{f(w)}" height="{f(h)}"><title>{html.escape(TITLE)}</title>'
    )


def text_el(word, x, y, theme, anchor="start"):
    a = f' text-anchor="{anchor}"' if anchor != "start" else ""
    return (
        f'<text x="{f(x)}" y="{f(y)}" fill="{COL[theme]["ink"]}" font-family="{FONT}" '
        f'font-size="{f(WORD)}" font-weight="500" letter-spacing="{f(TRACK * WORD)}"{a}>'
        f"{word}</text>"
    )


def text_width(word):
    return ADV[word] * WORD + TRACK * WORD * (len(word) - 1)


def lockup(word, kind, theme):
    """kind "row": the mark, then the word, the mark's centre on the middle of the x-height.
    kind "stack": the mark larger, centred above the word."""
    parts = mark_parts()
    x0, y0, x1, y1 = bbox(parts)
    mw, mh = x1 - x0, y1 - y0
    if kind == "row":
        s = ROW_SCALE
        h = max(mh * s, 2 * (ASCENDER - X_HEIGHT / 2) * WORD) + 2 * AIR  # room for ascenders
        mid = h / 2
        tx = AIR + mw * s + ROW_GAP * WORD
        baseline = mid + X_HEIGHT * WORD / 2
        w = tx + text_width(word) + AIR
        mark = placed(parts, theme, AIR - x0 * s, mid - (y0 + mh / 2) * s, s, ROW_STROKE)
        return w, h, mark + text_el(word, tx, baseline, theme)
    tw = text_width(word)
    s = min(60 / mh, 0.8 * tw / mw)
    w = max(mw * s, tw) + 2 * AIR
    baseline = AIR + mh * s + 0.6 * WORD + ASCENDER * WORD
    h = baseline + 0.05 * WORD + AIR
    mark = placed(parts, theme, w / 2 - (x0 + mw / 2) * s, AIR - y0 * s, s, STACK_STROKE)
    return w, h, mark + text_el(word, w / 2, baseline, theme, anchor="middle")


def favicon(theme):
    """The simplified drawing on the 32 x 32 rounded square, fitted to FAV_BOX units."""
    parts = favicon_parts()
    x0, y0, x1, y1 = bbox(parts)
    s = FAV_BOX / max(x1 - x0, y1 - y0)
    tx = 16 - (x0 + (x1 - x0) / 2) * s
    ty = 16 - (y0 + (y1 - y0) / 2) * s
    tile = f'<rect width="32" height="32" rx="7" fill="{COL[theme]["paper"]}"/>'
    return tile + placed(parts, theme, tx, ty, s, FAV_STROKE)


def files():
    """{file name: contents} for every asset, light and dark."""
    out = {}
    for theme, sfx in (("light", ""), ("dark", "-dark")):
        out[f"mark{sfx}.svg"] = svg_open(48, 48) + body(mark_parts(), theme) + "</svg>\n"
        for word, kind, name in (
            ("backtide", "row", "lockup"),
            ("backtide", "stack", "lockup-stacked"),
            ("backtide labs", "row", "lockup-labs"),
        ):
            w, h, inner = lockup(word, kind, theme)
            out[f"{name}{sfx}.svg"] = svg_open(w, h) + inner + "</svg>\n"
        out[f"favicon{sfx}.svg"] = svg_open(32, 32) + favicon(theme) + "</svg>\n"
    return out


# ---------------------------------------------------------------- the Wordmark's drawing


def inline():
    """The mark as the Wordmark draws it before the name: cropped to the drawing (the dot's
    height, the line's end), aria-hidden, with classes for its colours and the row's stroke
    (2.6 units at a 30-unit word), so the line keeps the stem of the name at any size."""
    (_, trail), (_, (cx, cy, r)) = mark_parts()
    sw = ROW_STROKE / ROW_SCALE
    nums = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", trail)]
    left, top = cx - r, cy - r
    right = max(nums[0::2]) + sw / 2
    view = f"{f(left)} {f(top)} {f(right - left)} {f(2 * r)}"
    return (
        f'<svg class="wordmark__mark" viewBox="{view}" aria-hidden="true" focusable="false">'
        f'<path class="wordmark__trail" pathLength="1" stroke-width="{f(sw)}" d="{trail}"/>'
        f'<circle class="wordmark__dot" cx="{f(cx)}" cy="{f(cy)}" r="{f(r)}"/></svg>'
    )


FRAGMENT = PROJECT / "components" / "Wordmark" / "mark.html"


def main():
    for name, text in files().items():
        (HERE / name).write_text(text)
    FRAGMENT.write_text(inline() + "\n")
    print(f"wrote the mark: {len(files())} files in assets/ and components/Wordmark/mark.html")


if __name__ == "__main__":
    main()
