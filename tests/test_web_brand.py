"""The product web on the design system v2 (D31, phase 3).

`backtide web` copies the system's files unchanged from `brand/design-system/project/` (tokens,
fonts and their licences, motion, the favicon) and draws its icons with the system's own paths;
these tests pin every copy to its source, so a change of the system is copied again, never
edited here. The web's own stylesheet (`web.css`) uses only the system's tokens: no colour,
font, curve or time written by hand, no shadows, no gradients. Every page loads only our own
files, in the system's order, and the text colours the web uses keep 4.5:1 (3:1 for shapes and
control edges) on the grounds they sit on, in both themes. Static, plus a rendered page.

To copy the icons again: ``uv run python -m tests.test_web_brand`` (rewrites
``backtide/web/templates/icons.html`` from ``icons/icons.js``).
"""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backtide.web.security import CSP
from tests.webkit import PREFIX_PATH, new_box, new_client

ROOT = Path(__file__).resolve().parent.parent
SYSTEM = ROOT / "brand" / "design-system" / "project"
WEB = ROOT / "backtide" / "web"
STATIC = WEB / "static"
TEMPLATES = WEB / "templates"
ICONS = TEMPLATES / "icons.html"

# The system's files, copied unchanged (static path -> system path).
COPIES = {
    "tokens.css": "tokens.css",
    "fonts/fonts.css": "fonts/fonts.css",
    "fonts/lora-latin.woff2": "fonts/lora-latin.woff2",
    "fonts/lora-italic-latin.woff2": "fonts/lora-italic-latin.woff2",
    "fonts/dm-sans-latin.woff2": "fonts/dm-sans-latin.woff2",
    "fonts/lora-OFL.txt": "fonts/lora-OFL.txt",
    "fonts/dm-sans-OFL.txt": "fonts/dm-sans-OFL.txt",
    "motion/motion.css": "motion/motion.css",
    "motion/boot.js": "motion/boot.js",
    "favicon.svg": "assets/favicon.svg",
    "favicon-dark.svg": "assets/favicon-dark.svg",
}

# The drawings the web uses, each for one meaning (icons/README.md).
WEB_ICONS = (
    "approve",
    "ask",
    "bell",
    "eye",
    "flag",
    "holds",
    "info",
    "key",
    "notebook",
    "reject",
    "rewinds",
    "scale",
    "still",
    "warning",
)
DRAWN = ("ink", "clay", "faint")


def icons_data() -> dict[str, list[dict[str, str]]]:
    code = (SYSTEM / "icons" / "icons.js").read_text()
    match = re.search(r"var DATA = (\{.*?\});\n", code, re.S)
    assert match
    return json.loads(match.group(1))


def render_icons() -> str:
    """The macro file the templates import: the same markup as ``BacktideIcons.make``."""
    data = icons_data()
    lines = [
        "{# backtide · the hand-drawn icons of the design system v2 (D31), as a Jinja macro.",
        "   Generated from brand/design-system/project/icons/icons.js by",
        "   `uv run python -m tests.test_web_brand`; tests/test_web_brand.py checks it is the",
        '   same. Do not edit by hand. Use: {% from "icons.html" import ic %} then',
        "   {{ ic('holds') }} or {{ ic('flag', 'ic--l') }}. Always aria-hidden, next to its",
        "   word. #}",
        "{% macro ic(name, extra='') -%}",
        '<svg class="ic ic-{{ name }}{% if extra %} {{ extra }}{% endif %}" viewBox="0 0 48 48"'
        ' aria-hidden="true" focusable="false">',
    ]
    for i, name in enumerate(WEB_ICONS):
        groups: dict[str, list[str]] = {}
        for part in data[name]:
            length = ' pathLength="1"' if part["c"] in DRAWN else ""
            groups.setdefault(part["g"], []).append(
                f'<path class="ic-{part["c"]}"{length} d="{part["d"]}"/>'
            )
        body = "".join(
            f'<g class="ic-g ic-g-{g}">{"".join(paths)}</g>' for g, paths in groups.items()
        )
        lines.append(f"{{%- {'if' if i == 0 else 'elif'} name == '{name}' %}}{body}")
    lines += ["{%- endif %}</svg>", "{%- endmacro %}", ""]
    return "\n".join(lines)


def _luminance(colour: str) -> float:
    channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(a: str, b: str) -> float:
    high, low = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def tokens() -> dict[str, dict[str, str]]:
    """Every colour token of the system, light and dark (base, app and drawing)."""
    data = json.loads((SYSTEM / "tokens.json").read_text())
    found: dict[str, dict[str, str]] = {}
    for group in (data["color"]["tokens"], data["app"]["color"]["tokens"]):
        for token in group:
            if isinstance(token["value"], dict):
                found[token["name"]] = token["value"]
    return found


@pytest.fixture
def web(tmp_path: Path) -> TestClient:
    new_box(tmp_path).append("file", "create", "notes.md")
    return new_client(tmp_path)


# ---------------------------------------------------------------- the copies


@pytest.mark.parametrize("static_path", COPIES)
def test_the_systems_files_are_unchanged_copies(static_path: str) -> None:
    """Copy them again with `cp brand/design-system/project/<path> backtide/web/static/<path>`
    when the system changes; never edit them here."""
    assert (STATIC / static_path).read_bytes() == (SYSTEM / COPIES[static_path]).read_bytes()


def test_the_icons_are_the_systems_drawings() -> None:
    assert ICONS.read_text() == render_icons(), "run `uv run python -m tests.test_web_brand`"


def test_every_icon_a_template_draws_exists() -> None:
    used = set()
    for path in TEMPLATES.glob("*.html"):
        used |= set(re.findall(r"\bic\('([\w-]+)'", path.read_text()))
    assert used, "the web draws its icons"
    assert used <= set(WEB_ICONS), used - set(WEB_ICONS)


def test_the_fonts_are_lora_and_dm_sans_served_from_here() -> None:
    fonts = (STATIC / "fonts" / "fonts.css").read_text()
    for src in re.findall(r'url\("([^"]+)"\)', fonts):
        assert (STATIC / "fonts" / src).is_file(), src
    assert set(re.findall(r'font-family: "([^"]+)"', fonts)) == {"Lora", "DM Sans"}
    for path in [*STATIC.glob("*.css"), *STATIC.glob("*.js"), *TEMPLATES.glob("*.html")]:
        assert "Jost" not in path.read_text(), path.name


# ---------------------------------------------------------------- the web's own styles


def test_the_webs_styles_use_only_tokens_and_point_at_the_system() -> None:
    css = (STATIC / "web.css").read_text()
    header = css[: css.index("*/")]
    assert "brand/design-system/project/" in header and "D31" in header
    assert "design-system-v1" not in css
    body = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", body), "a colour written by hand"
    assert not re.search(r"\brgba?\(|\bhsla?\(|color-mix\(", body), "a colour made by hand"
    families = re.findall(r"font-family:\s*([^;}]*)", body)
    assert all(re.fullmatch(r"var\(--font-[a-z]+\)\s*", f) for f in families), (
        "the families come from tokens.css (--font-*)"
    )
    assert "box-shadow" not in body and "gradient" not in body
    assert not re.search(r"cubic-bezier|\b[1-9][\d.]*m?s\b", body), "a curve or time by hand"
    assert "url(" not in body, "the fonts are in fonts/fonts.css"


def test_every_custom_property_the_web_uses_is_a_token_or_its_own() -> None:
    css = (STATIC / "web.css").read_text()
    defined = set(re.findall(r"(--[\w-]+)\s*:", (STATIC / "tokens.css").read_text()))
    own = set(re.findall(r"(--[\w-]+)\s*:", css))
    used = set(re.findall(r"var\((--[\w-]+)", css))
    from_script = {"--i"}  # a row's place in its group, set by web.js (stagger)
    assert used <= defined | own | from_script, used - defined - own - from_script


def test_no_gradient_is_drawn_in_any_template() -> None:
    for path in TEMPLATES.glob("*.html"):
        assert "Gradient" not in path.read_text(), path.name


# ---------------------------------------------------------------- the pages


def test_each_page_loads_only_our_files_in_the_systems_order(web: TestClient) -> None:
    html = web.get("/ahora").text
    head = html[: html.index("</head>")]
    styles = re.findall(r'<link rel="stylesheet" href="([^"]+)">', head)
    assert styles == [
        f"{PREFIX_PATH}/static/fonts/fonts.css",
        f"{PREFIX_PATH}/static/tokens.css",
        f"{PREFIX_PATH}/static/motion/motion.css",
        f"{PREFIX_PATH}/static/web.css",
    ]
    scripts = re.findall(r'<script src="([^"]+)"', html)
    assert scripts[:2] == [
        f"{PREFIX_PATH}/static/motion/boot.js",
        f"{PREFIX_PATH}/static/theme.js",
    ]
    for src in styles + scripts:
        assert web.get(src.removeprefix(PREFIX_PATH)).status_code == 200, src
    for path in ("/static/fonts/lora-latin.woff2", "/static/fonts/dm-sans-latin.woff2"):
        response = web.get(path)
        assert response.status_code == 200 and "font" in response.headers["content-type"]


IDLE_MARKS = (
    "idle.css",
    "idle.js",
    "data-idle",
    "ic--idle",
    "ic--idling",
    "bt-idle-",
    "BacktideIdle",
)


def test_the_drawings_stay_still_here_the_idle_is_the_public_sites_only(web: TestClient) -> None:
    """D34: on the public site the drawings may idle; the product web, where people approve
    and reject, keeps them still. It never ships the system's motion/idle.css or idle.js and
    never opts a drawing in, so only a live agent's dot ever loops here."""
    assert sorted(p.name for p in (STATIC / "motion").iterdir()) == ["boot.js", "motion.css"]
    for path in WEB.rglob("*"):
        if path.is_file() and path.suffix in {".html", ".css", ".js", ".py"}:
            text = path.read_text()
            for mark in IDLE_MARKS:
                assert mark not in text, f"{mark} in {path.relative_to(WEB)}"
    for page in ("/ahora", "/historia?accion=nada", "/instantaneas"):
        html = web.get(page).text
        for mark in IDLE_MARKS:
            assert mark not in html, (page, mark)
    # The system's motion.css itself has no idle in it: the idle lives in its own file.
    assert "idle" not in (STATIC / "motion" / "motion.css").read_text()


def test_the_page_follows_the_system_theme_until_the_switch_says_otherwise(
    web: TestClient,
) -> None:
    html = web.get("/ahora").text
    assert re.search(r'<html lang="es" data-theme="auto">', html)
    tokens_css = (STATIC / "tokens.css").read_text()
    assert ':root[data-theme="dark"]' in tokens_css
    assert '@media (prefers-color-scheme: dark) {\n  :root[data-theme="auto"]' in tokens_css
    theme = (STATIC / "theme.js").read_text()
    assert "localStorage" in theme and "innerHTML" not in theme
    js = (STATIC / "web.js").read_text()
    assert 'root.setAttribute("data-theme", "auto")' in js, "back to the system, not to light"


def test_the_wordmark_is_the_clay_dot_and_the_name_in_lowercase(web: TestClient) -> None:
    html = web.get("/ahora").text
    home = re.search(r'<a class="home wordmark"[^>]*>(.*?)</a>', html, re.S)
    assert home and '<span class="wordmark__dot" aria-hidden="true"></span>' in home.group(1)
    assert re.sub(r"<[^>]+>", "", home.group(1)).strip() == "backtide"
    assert "Backtide" not in html and "BACKTIDE" not in html


def test_the_markup_is_still_strict(web: TestClient) -> None:
    """Restyling did not open the policy: the CSP is the reviewed one and nothing is inline."""
    assert CSP == (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response = web.get("/ahora")
    assert response.headers["content-security-policy"] == CSP
    html = response.text
    assert not re.search(r"<script(?![^>]*\bsrc=)|<style|\sstyle\s*=|\son[a-z]+\s*=", html, re.I)
    empty = web.get("/historia?accion=nada").text
    assert 'class="ic ic-notebook"' in empty, "an icon is markup of our own, not a file or a font"
    assert not re.search(r"\sstyle\s*=", empty)
    macro = ICONS.read_text()
    assert "style" not in macro and "<script" not in macro


# ---------------------------------------------------------------- contrast


# The text colours the web puts on each ground, as the stylesheet uses them.
TEXT_ON = {
    "paper": [
        "ink",
        "ink-soft",
        "ink-muted",
        "clay",
        "danger",
        "ok",
        *(f"agent-{n}" for n in range(1, 7)),
        *(f"risk-{n}" for n in range(4)),
        "state-working",
        "state-idle",
        "state-frozen",
        "state-waiting",
        "state-rewinding",
        "state-sensor-down",
    ],
    "band": ["ink", "ink-soft", "ink-muted", "warn", "danger"],
    "hold-wash": [
        "ink",
        "ink-soft",
        "ink-muted",
        "clay",
        *(f"agent-{n}" for n in range(1, 7)),
        *(f"risk-{n}" for n in range(4)),
    ],
    "info-wash": ["ink", "ink-soft", "info"],
    "warn-wash": ["ink", "ink-soft", "warn"],
    "ink": ["on-ink"],
    "ink-hover": ["on-ink"],
    "clay": ["on-ink"],
    **{
        f"agent-{n}-wash": [
            "ink",
            "ink-soft",
            "ink-muted",
            f"agent-{n}",
            *(f"risk-{r}" for r in range(4)),
            "state-working",
            "state-idle",
            "state-frozen",
            "state-waiting",
            "state-rewinding",
            "state-sensor-down",
        ]
        for n in range(1, 7)
    },
}
# Shapes and the edges of controls: 3:1.
SHAPE_ON = {
    "paper": ["edge", "clay-mark", "ink"],
    # Reject's border is `edge`, not the system's `line` (1.7:1 on hold-wash in dark): a control
    # that says no must be seen as one. The clock's bar is clay mark.
    "hold-wash": ["edge", "clay-mark"],
    # A card holds links, never a bordered control: only its identity line is a shape there.
    **{f"agent-{n}-wash": [f"agent-{n}"] for n in range(1, 7)},
}


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_every_text_colour_the_web_uses_is_at_least_4_5_to_1(theme: str) -> None:
    colours = tokens()
    for ground, texts in TEXT_ON.items():
        for text in texts:
            ratio = contrast(colours[text][theme], colours[ground][theme])
            assert ratio >= 4.5, (theme, text, ground, round(ratio, 2))


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_shapes_and_control_edges_are_at_least_3_to_1(theme: str) -> None:
    colours = tokens()
    for ground, shapes in SHAPE_ON.items():
        for shape in shapes:
            ratio = contrast(colours[shape][theme], colours[ground][theme])
            assert ratio >= 3, (theme, shape, ground, round(ratio, 2))


if __name__ == "__main__":
    ICONS.write_text(render_icons())
    print(f"wrote {ICONS.relative_to(ROOT)}")
