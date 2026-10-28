"""Builds the generated parts of the backtide design system from tokens.json.

- tokens.css: every token as a CSS custom property, light by default, dark under
  [data-theme="dark"] (or [data-theme="auto"] with a dark system preference), plus one
  class per type style (.t-display, .t-body...).
- The icons (icons/build.py): svg/*.svg and icons.js.
- index.html, the living sample page, from index.tpl.html: the token tables, the contrast
  table, the icon sheet and every {{ic:name}} are written in as static markup, so the page
  reads the same without JavaScript and needs nothing inline.
- sample/swatches.css: one class per token for the sample page's swatches and bars.

It also measures every text colour against every surface it may sit on, in both themes,
and stops with an error if one is under 4.5:1 (3:1 for shapes and the edges of controls).

Run: python3 brand/design-system/project/build.py
"""

import html
import importlib.util
import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent


def _load_icons():
    """icons/build.py, loaded by its path (both scripts are called build.py)."""
    spec = importlib.util.spec_from_file_location("backtide_icons", HERE / "icons" / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


icons = _load_icons()

TOKENS = json.loads((HERE / "tokens.json").read_text())
THEMES = ("light", "dark")

# ---------------------------------------------------------------- reading the tokens


def colour_tokens():
    """Every colour token with a value per theme: base, app and drawing."""
    out = []
    for group, tokens in (
        ("base", TOKENS["color"]["tokens"]),
        ("app", TOKENS["app"]["color"]["tokens"]),
        ("drawing", TOKENS["drawing"]["tokens"]),
    ):
        for t in tokens:
            out.append({**t, "group": group})
    return out


def by_name():
    return {t["name"]: t for t in colour_tokens()}


def flat(section):
    return TOKENS[section]["tokens"]


# ---------------------------------------------------------------- contrast


def luminance(hex_colour):
    h = hex_colour.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))

    def lin(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def ratio(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


TEXT_ROLES = {"text", "state", "feedback", "identity", "risk"}
SHAPES = {"clay-mark", "state-progress", "edge"}
BASE_SURFACES = ("paper", "band", "hover")


def surfaces_for(name, names):
    """The surfaces a colour may sit on: paper, band and hover, every wash of its own
    family, and the hold wash for what appears in a held request."""
    found = list(BASE_SURFACES)
    if name.startswith("agent-"):
        found.append(f"{name}-wash")
    for kind in ("info", "ok", "warn", "danger"):
        if name == kind or name in ("ink", "ink-soft", "ink-muted", "clay"):
            found.append(f"{kind}-wash")
    if name in ("ink", "ink-soft", "ink-muted", "clay") or name.startswith(("risk-", "state-")):
        found.append("hold-wash")
    if name in ("ink", "ink-soft", "ink-muted"):
        found += [f"agent-{i}-wash" for i in range(1, 7)]
    return [s for s in found if s in names]


def contrast_table():
    """[(token, theme, surface, ratio, floor)] for every pair that must hold."""
    names = by_name()
    rows = []
    for t in colour_tokens():
        name, role = t["name"], t.get("role")
        if name == "on-ink":
            for theme in THEMES:
                for under in ("ink", "ink-hover"):
                    fg, bg = t["value"][theme], names[under]["value"][theme]
                    rows.append((name, theme, under, ratio(fg, bg), 4.5))
            continue
        if name in SHAPES:
            floor, under_list = 3.0, ("paper", "band")
        elif role in TEXT_ROLES:
            floor, under_list = 4.5, surfaces_for(name, names)
        else:
            continue
        for theme in THEMES:
            for under in under_list:
                fg, bg = t["value"][theme], names[under]["value"][theme]
                rows.append((name, theme, under, ratio(fg, bg), floor))
    return rows


def check_contrast():
    rows = contrast_table()
    failing = [r for r in rows if r[3] < r[4]]
    for name, theme, under, value, floor in failing:
        print(f"contrast too low: {name} on {under} ({theme}) {value:.2f} < {floor}")
    if failing:
        raise SystemExit(1)
    print(f"contrast: {len(rows)} pairs, all at or above their floor")
    return rows


# ---------------------------------------------------------------- tokens.css


def type_styles():
    for group in TOKENS["type"]["groups"]:
        for style in group["styles"]:
            yield group["family"], style


def css_vars(theme):
    lines = [f"  --{t['name']}: {t['value'][theme]};" for t in colour_tokens()]
    return "\n".join(lines)


def tokens_css():
    fam = TOKENS["type"]["families"]
    fixed = [f"  --font-{k}: {v};" for k, v in fam.items()]
    for _family, s in type_styles():
        n = s["name"]
        fixed.append(f"  --type-{n}-size: {s['fontSize']};")
        fixed.append(f"  --type-{n}-leading: {s['lineHeight']};")
        fixed.append(f"  --type-{n}-weight: {s['fontWeight']};")
        fixed.append(f"  --type-{n}-tracking: {s.get('letterSpacing', 'normal')};")
    for section in ("spacing", "grid", "radius", "stroke", "size", "motion"):
        for t in TOKENS[section]["tokens"]:
            fixed.append(f"  --{t['name']}: {t['value']};")
    for t in TOKENS["focus"]["tokens"]:
        value = "var(--ink)" if t["value"] == "{ink}" else t["value"]
        fixed.append(f"  --{t['name']}: {value};")

    classes = []
    for family, s in type_styles():
        n = s["name"]
        italic = "italic " if s.get("fontStyle") == "italic" else ""
        rule = (
            f".t-{n} {{ font: {italic}var(--type-{n}-weight) var(--type-{n}-size)/"
            f"var(--type-{n}-leading) var(--font-{family}); "
            f"letter-spacing: var(--type-{n}-tracking);"
        )
        if s.get("textTransform"):
            rule += f" text-transform: {s['textTransform']};"
        classes.append(rule + " }")

    return f"""/* backtide · design tokens, generated from tokens.json by build.py. Do not edit.
   Light (ivory) is the default. Dark (charcoal with clay) applies under [data-theme="dark"],
   or under [data-theme="auto"] when the system prefers dark. Breakpoints cannot be custom
   properties: medium is max-width 1000px, narrow is max-width 720px. */

:root {{
  color-scheme: light;
{css_vars("light")}
{chr(10).join(fixed)}
}}

:root[data-theme="dark"] {{
  color-scheme: dark;
{css_vars("dark")}
}}

@media (prefers-color-scheme: dark) {{
  :root[data-theme="auto"] {{
    color-scheme: dark;
{css_vars("dark").replace("  --", "    --")}
  }}
}}

/* Type styles, one class each. On phones .t-body drops to 1rem (bundle.css). */
{chr(10).join(classes)}
"""


# ---------------------------------------------------------------- the sample page


def esc(s):
    return html.escape(str(s), quote=True)


def colour_rows(tokens, rows):
    """A swatch per token: both themes side by side, its usage and its lowest contrast."""
    lowest = {}
    for name, theme, _under, value, _floor in rows:
        key = (name, theme)
        lowest[key] = min(value, lowest.get(key, 99))
    out = []
    for t in tokens:
        n = t["name"]
        marks = []
        for theme in THEMES:
            low = lowest.get((n, theme))
            ratio_text = f'<span class="sw__ratio">{low:.1f}:1 min</span>' if low else ""
            marks.append(
                f'<span class="sw__chip sw__chip--{theme}"><span class="sw__fill sw--{n}">'
                f'</span><span class="sw__hex">{t["value"][theme]}</span>{ratio_text}</span>'
            )
        out.append(
            f'<li class="sw"><div class="sw__chips">{"".join(marks)}</div>'
            f'<p class="sw__name">{n}</p><p class="sw__use">{esc(t.get("usage", ""))}</p></li>'
        )
    return "".join(out)


def contrast_html(rows):
    keep = [r for r in rows if r[2] in ("paper", "band") or r[2].endswith("wash")]
    body = []
    for name, theme, under, value, floor in keep:
        ok = "pass" if value >= floor else "fail"
        body.append(
            f'<tr><th scope="row">{name}</th><td>{theme}</td><td>{under}</td>'
            f'<td class="num">{value:.2f}:1</td><td class="num">{floor:g}:1</td>'
            f'<td><span class="badge badge--{ok}">{ok}</span></td></tr>'
        )
    return "".join(body)


def type_html():
    out = []
    for family, s in type_styles():
        size = s["fontSize"]
        meta = f"{family} · {s['fontWeight']} · {size} / {s['lineHeight']}"
        if s.get("letterSpacing"):
            meta += f" · {s['letterSpacing']}"
        if s.get("fontStyle"):
            meta += " · italic"
        out.append(
            f'<li class="ty"><p class="ty__meta"><span class="ty__name">{s["name"]}</span>'
            f"<span>{esc(meta)}</span></p>"
            f'<p class="ty__sample t-{s["name"]}">{esc(s["sample"])}</p>'
            f'<p class="ty__use">{esc(s["usage"])}</p></li>'
        )
    return "".join(out)


def bars_html(section, kind):
    out = []
    for t in TOKENS[section]["tokens"]:
        out.append(
            f'<li class="bar-row"><span class="bar-row__name">{t["name"]}</span>'
            f'<span class="bar-row__value">{esc(t["value"])}</span>'
            f'<span class="bar-row__shape"><span class="{kind} {kind}--{t["name"]}"></span></span>'
            f'<span class="bar-row__use">{esc(t["usage"])}</span></li>'
        )
    return "".join(out)


def motion_html():
    out = []
    for t in TOKENS["motion"]["tokens"]:
        out.append(
            f'<tr><th scope="row">{t["name"]}</th><td><code>{esc(t["value"])}</code></td>'
            f"<td>{esc(t['usage'])}</td></tr>"
        )
    return "".join(out)


def icons_html():
    out = []
    for name in icons.ICONS:
        out.append(
            f'<li class="icon-cell ic-host" tabindex="0">'
            f"{icons.icon_svg(name, 'icon-cell__big')}"
            f'<span class="icon-cell__small">{icons.icon_svg(name)}{icons.icon_svg(name)}</span>'
            f'<span class="icon-cell__name">{name}</span>'
            f'<span class="icon-cell__use">{esc(icons.MEANING[name])}</span></li>'
        )
    return "".join(out)


def hero_art():
    shore = icons.line([(24, 222), (376, 221.6)], 201, amp=0.9)
    curl = icons.bezier(
        [
            ((376, 222), (330, 222), (300, 207), (286, 178)),
            ((286, 178), (273, 150), (284, 121), (313, 115)),
            ((313, 115), (339, 110), (357, 127), (351, 147)),
            ((351, 147), (346, 163), (327, 167), (317, 157)),
            ((317, 157), (309, 149), (313, 137), (323, 135)),
        ],
        202,
        amp=0.8,
    )
    dot = icons.circle(104, 213, 9, 203, amp=0.3, closed=True)
    return (
        '<svg class="hero-art" viewBox="0 0 400 300" aria-hidden="true" focusable="false">'
        f'<path class="art-line art-shore" pathLength="1" d="{shore}"/>'
        f'<path class="art-line art-curl" pathLength="1" d="{curl}"/>'
        f'<g class="art-roll"><path class="art-dot" d="{dot}"/></g>'
        "</svg>"
    )


def swatches_css():
    lines = [
        "/* Generated by build.py for the sample page only. Each half of a swatch shows its",
        "   own theme, whatever theme the page is in, so the values are written as they are. */",
    ]
    names = by_name()
    for theme in THEMES:
        paper, muted = names["paper"]["value"][theme], names["ink-muted"]["value"][theme]
        lines.append(f".sw__chip--{theme} {{ background: {paper}; color: {muted}; }}")
        for t in colour_tokens():
            lines.append(
                f".sw__chip--{theme} .sw--{t['name']} {{ background: {t['value'][theme]}; }}"
            )
    for t in TOKENS["spacing"]["tokens"]:
        lines.append(f".sp--{t['name']} {{ width: var(--{t['name']}); }}")
    for t in TOKENS["radius"]["tokens"]:
        lines.append(f".rd--{t['name']} {{ border-radius: var(--{t['name']}); }}")
    for t in TOKENS["stroke"]["tokens"]:
        lines.append(f".sk--{t['name']} {{ height: var(--{t['name']}); }}")
    return "\n".join(lines) + "\n"


ARROW = (
    '<svg class="arrow" viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
    '<path d="{d}"/></svg>'
)


def render_page(rows):
    tpl = (HERE / "index.tpl.html").read_text()
    names = by_name()
    base = [t for t in TOKENS["color"]["tokens"]]
    app = [t for t in TOKENS["app"]["color"]["tokens"]]
    drawing = [names[t["name"]] for t in TOKENS["drawing"]["tokens"]]
    parts = {
        "colors": colour_rows(base, rows),
        "app-colors": colour_rows(app, rows),
        "drawing-colors": colour_rows(drawing, rows),
        "contrast": contrast_html(rows),
        "type": type_html(),
        "spacing": bars_html("spacing", "sp"),
        "radius": bars_html("radius", "rd"),
        "stroke": bars_html("stroke", "sk"),
        "motion": motion_html(),
        "icons": icons_html(),
        "hero_art": hero_art(),
        "icon-count": str(len(icons.ICONS)),
        "arrow": ARROW.format(d="M3 8h10M9 4l4 4-4 4"),
        "arrow-back": ARROW.format(d="M13 8H3M7 4L3 8l4 4"),
    }

    def rep(m):
        key = m.group(1)
        if key.startswith("ic:"):
            _, name, *extra = key.split(":")
            return icons.icon_svg(name, " ".join(extra))
        return parts[key]

    return re.sub(r"\{\{([\w:-]+)\}\}", rep, tpl)


def main():
    rows = check_contrast()
    (HERE / "tokens.css").write_text(tokens_css())
    print("wrote tokens.css")
    icons.main()
    (HERE / "sample").mkdir(exist_ok=True)
    (HERE / "sample" / "swatches.css").write_text(swatches_css())
    (HERE / "index.html").write_text(render_page(rows))
    print("wrote sample/swatches.css and index.html")


if __name__ == "__main__":
    main()
