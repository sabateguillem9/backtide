# backtide · design system

The one source of style for everything backtide shows: the public site (`site/`, backtide labs) and the product web (`backtide web`). Decided on 2026-10-28 (D31), from the approved proposal `brand/propuestas-labs/c2-limpia/`. The first system (white first, Jost, the dot and the tide) is kept in `brand/design-system-v1/`; the product web follows it until phase 3.

Open `index.html` (served from this folder, see "Files") to see every token, the type scale, the drawings, the motion and every component in its states, in both themes.

## The idea

**backtide labs: things made slowly and with care, and the tide that comes back.**

backtide is a black box for AI agents: it records what an agent does, rewinds its folder and holds what cannot be undone. The brand should feel like the opposite of an alarm: a well-kept notebook on warm paper. Ivory paper, ink type, one touch of clay. A serif for what you read first, a quiet sans for the rest. Small drawings by a steady hand. Movement that arrives once and settles, like water coming back to the same line.

Three words to check any piece against: **calm, careful, warm.**

## Content and voice

- Write in English first; Spanish is the second language and every public string ships in both.
- Write `backtide` in lowercase, always, also at the start of a sentence. Never "Backtide" or "BackTide". The labs are "backtide labs".
- Short, calm, precise sentences. One idea each. State facts, never fear: "Deletes, payments and messages wait for your yes." No exclamation marks, no "revolutionary", no "magic".
- Sentence case for every heading. Pair a heading with one line that explains it.
- Say "you" to the reader and "your agent" for what it watches. Name buttons by what happens ("Approve", "Read the testers' guide").
- Be honest about where things stand: "Works" only when it has tests that pass; "Preview" for what is shown but not finished.
- Two voices in the product never mix: ours (what it does, the risk, the clock, the buttons) and the agent's (recipients, subject, the request), which sits in its own block, headed "What the agent asks".
- No emoji anywhere.

## Colour

All values are in `tokens.json` and, as custom properties, in `tokens.css` (generated). Light is the default; dark is a choice.

| Token | Light | Dark | Use |
|---|---|---|---|
| `paper` | `#F8F4EC` ivory | `#1A1815` charcoal | The page |
| `band` | `#F0E9DC` | `#25221E` | Quiet bands, notices, cards, the pressed language |
| `hover` | `#F2ECE1` | `#201D1A` | The layer under a row or a secondary button on hover |
| `ink` | `#1F1C18` | `#F2ECE2` | Headlines, important text, the primary button, icon strokes, focus |
| `ink-soft` | `#46403A` | `#D2C8BA` | Running text |
| `ink-muted` | `#6A6257` | `#A69C8E` | Warm grey: labels, dates, notes, placeholders |
| `clay` | `#A4472A` | `#E38C68` | Clay for text: links, a project's tagline |
| `clay-mark` | `#C4673F` | `#D9774D` | Clay for shapes only: the dot, the icons' mark, progress |
| `clay-soft` | `#EFD3C1` | `#4A3027` | A pale clay fill under an ink stroke |
| `hair` / `line` | `#DDD4C3` / `#B9AE9C` | `#34302A` / `#4D463D` | Rules: between rows / under heads and around buttons |
| `edge` | `#8E8476` | `#7D7366` | The border of a control (field, select, switch, checkbox) |

Plus `on-ink`, `ink-hover`, `selection`; the states of a project (`state-preview` tide blue, `state-progress` clay mark, `state-done` sage); the feedback colours with their washes (`info`, `ok`, `warn`, `danger`, `hold-wash`); and, for the product web, `app`: six agent identities with their washes, risk 0 to 3 and six agent states. `drawing` holds the slab colours of Inside the box.

**Clay, with restraint.** Clay is the only accent. Use it for one thing per view that you want found: a link, the tagline under a project's name, the dot in the wordmark, the one mark inside each drawing, the count of what waits for you. Never for a whole background, never for a block of text, never for decoration. In the product web clay means "this asks for you" (the waiting state, the held requests). `clay-mark` is never text: use `clay` for words.

**Colour is never the only signal.** A risk is also a shape (hollow, thick ring, filled, filled and ringed) and a word; a state is always written; an agent's colour sits next to its name.

### Contrast

Text is at least 4.5:1, shapes and the edges of controls at least 3:1, in both themes, on every surface they may sit on. `build.py` measures 292 pairs and stops if one falls short; the sample page measures them again in the browser. The lowest pairs:

| Pair | Light | Dark |
|---|---|---|
| `ink` on `paper` | 15.5:1 | 15.1:1 |
| `ink-soft` on `paper` | 9.3:1 | 10.7:1 |
| `ink-muted` on `paper` / `band` | 5.47:1 / 4.97:1 | 6.55:1 / 5.86:1 |
| `ink-muted` on the lowest wash (agent-5 / agent-4) | 4.88:1 | 5.34:1 |
| `clay` on `paper` / `band` / `hold-wash` | 5.45:1 / 4.95:1 / 5.00:1 | 6.93:1 / 6.20:1 / 6.03:1 |
| `on-ink` on `ink` / `ink-hover` (primary button) | 15.5:1 / 11.1:1 | 15.1:1 / 12.2:1 |
| every agent, risk and state colour, lowest (risk-2 on band / risk-0 on hold-wash) | 4.95:1 | 5.70:1 |
| `clay-mark` on `paper` (shape) | 3.57:1 | 5.65:1 |
| `edge` on `paper` (control border) | 3.35:1 | 3.81:1 |

The full table is on the sample page, under "Contrast, measured".

### Themes

`tokens.css` puts the light values on `:root`. The dark ones apply under `<html data-theme="dark">`, or under `data-theme="auto"` when the system prefers dark. Public pages are light by default; a switch may offer dark. The product web may follow the system (`auto`) with a switch, as it does today. A theme choice is remembered only in local storage, never in a cookie, and never sent anywhere.

## Type

Two families, both under the SIL Open Font License and served from `fonts/` (Latin subsets, woff2): **Lora** (serif, roman and italic) and **DM Sans** (sans). Code, paths and hashes use the system's monospace (`--font-mono`), which loads nothing.

- **Lora 400** for what you read first: display, titles, section heads, names. Italic Lora for a project's tagline (in clay) and a logbook entry's line.
- **DM Sans 400** for text, **500** for labels, buttons and the wordmark. No other weights.
- The scale (`type` in `tokens.json`, one `.t-<name>` class each): `display-xl`, `display`, `title`, `section`, `heading-l`, `heading-m`, `heading-s`, `quote`, `tagline`, `aside`, `lead`, `body`, `body-ui`, `button`, `label`, `caption`, `overline`, `code`. Display sizes are fluid (`clamp`); text sizes are fixed.
- Headlines are tight (-0.032em at the largest, -0.005em at the smallest); text is not tracked; `overline` is tracked +0.06em and uppercase, and only for tags.
- Running text at most `measure` (38rem) wide. Public pages use `body` (17px, 1.65); the product web uses `body-ui` (15px, 1.55).

## Grid and air

- Twelve columns, `gap` gutters, `margin` sides, at most `page` (76rem) wide; the product web uses `page-app` (64rem).
- Two breakpoints: **medium** at 1000px (side-by-side halves stack) and **narrow** at 720px (one column).
- Space between sections is `space-section` (96 to 160px). The air is part of the design: when in doubt, more space, fewer rules.
- Group with space and hairlines first; use a band (`band` background, `radius-l`) only for one block that must stand apart (a notice, a card, a held request, Inside the box).
- One focal thing per screen.

## Drawings

Twenty icons drawn by a steady hand, in `icons/` (generated by `icons/build.py` from `icons/hand.py`). The rule for drawing new ones is in `icons/README.md`.

- **When yes:** beside a heading to give a section a face; beside a state's word; inside a notice; as the picture of an empty state; for a project in the logbook.
- **When no:** as decoration, in a row of many (a table does not need one per line), twice on the same idea, or instead of a word. An icon is always next to its word, or `aria-hidden` inside something that has one.
- **How they are drawn:** a 48 x 48 grid; one regular stroke of 1.75px on screen at any size; round caps and joins; ink for the drawing, `line` for the ground and faint details, and one touch of clay (a filled dot, or one clay stroke, or a pale clay fill under an ink shape). Few strokes, each a smooth curve with a faint hand-made bow.
- **Larger drawings** (the hero's shore and wave, Inside the box) follow the same rules at their own scale.

## Movement

Everything is in `motion/` (`motion.css`, `boot.js`, `motion.js`); see `motion/README.md`.

- **What moves:** the entrance on load (the bar fades, the headline rises out of a soft blur word by word, the lead and actions follow, the drawing draws itself); blocks that rise into view once as you scroll, with their rule growing and their icon drawing; each icon's own small gesture when you point at its row (once, never looping); the language indicator sliding; underlines drawing from the left; a cross-fade between pages, with a title that flies to its place (view transitions).
- **How much:** 14px of rise, 80ms between siblings (at most five steps), 450 to 850ms, with `ease` (`cubic-bezier(.22, 1, .36, 1)`) for arrivals and `ease-reveal` (`cubic-bezier(.2, .7, .2, 1)`) for reveals. Only transform, opacity and a stroke's dash move.
- **What never moves:** text while you read it, anything in a loop (except a live state's dot in the product web, which breathes), the scroll itself (no scroll-jacking), layout properties, anything with `prefers-reduced-motion` (then everything is there, still), and anything while the tab is hidden (paused). Nothing is hidden unless JavaScript said so first, so without JavaScript every page reads the same.

## Focus and accessibility

- Every focusable thing shows a 2px ink ring (`focus-width`, `focus-color`), 3px away (`focus-offset`), closing in from 8px as it appears. Never remove it; never replace it with a colour change alone.
- Tap targets are at least 44px (`size-target`).
- Text contrast as above; never colour alone; states in words.
- Every page has a skip link, landmarks (`header`, `nav`, `main`, `footer`) and one `h1`.
- Icons and drawings are `aria-hidden`; a timeline drawn as SVG has `role="img"` and a sentence as its label.
- The language is set on `<html lang>`, and on any piece in the other language (`lang="es"`).

## Security rules of the web

These are not style choices; they keep the product web safe (see the docstring of `backtide/web/security.py`) and the public site honest.

- **Strict CSP.** No inline `<script>`, no inline `<style>`, no `style=` attribute, no event attributes (`onclick=`), no `javascript:` links. Every style is in a file; every script is a file. The sample page carries the same policy in a meta tag.
- **No markup from strings.** Never `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write`. Build elements with `createElement`/`createElementNS` and put text in with `textContent`. Anything the watched agent wrote enters the page only as text. (Setting a position through `element.style` is the CSSOM, which the CSP allows; it is never a `style` attribute in the markup.)
- **Everything from our own origin.** Fonts are self-hosted from `fonts/`, never Google Fonts or any CDN: no third party learns who reads the page. No analytics, no cookies, no trackers, no embeds.
- **No storage** on public pages. The product web may keep the theme in local storage, nothing else.
- **No forms** on public pages (D23). The product web's forms post to its own origin with CSRF, as today.

## Do not

- Nothing from Anthropic or Claude: not the name in the brand, not the asterisk or spark mark, not their illustrations, not their typefaces (no Styrene, no Tiempos, no Copernicus). The warmth is ours: ivory, clay, Lora and DM Sans.
- No hard shadows, no glows, no blur used as decoration (the headline's one clearing blur is the only exception). No gradients.
- No emoji, no stock photos, no 3D renders, no glassmorphism.
- No new colours, sizes or fonts outside `tokens.json`. If one is missing, add it there, with its use and its contrast, and run the build.
- No pure white or pure black: paper and ink.
- No capitals for `backtide`, no other weights, no outlined or shadowed wordmark.
- No stripes of colour on the left of a card, no pills of colour behind words, no badges for decoration.

## Wordmark and assets

- The wordmark is the name in DM Sans 500, lowercase, after a round dot in `clay-mark` (`Wordmark` component). On the site it is "backtide labs"; on a project's page and in the product web, "backtide".
- `assets/favicon.svg` (ivory square, clay dot) and `assets/favicon-dark.svg`; `assets/mark.svg`, the dot alone for avatars; `assets/wordmark.svg` and `assets/wordmark-dark.svg` for documents and slides (see `assets/README.md`).
- Clear space around the wordmark: at least the height of its dot on every side.

## Legal and languages

- Every public page has the `LegalFooter`: the wordmark, Privacy, Legal notice, GitHub, the language switch, and one line on what is collected ("This site collects no data: no cookies, no analytics, no forms.").
- The language follows the browser, can be changed with the switch, and lives in the address (`?lang=`), never in a cookie.
- English and Spanish, always both. Strings live in one file per site (`site/i18n.js` or the labs' strings; `backtide/web/i18n.py` for the product).
- The fonts' licences travel with them (`fonts/lora-OFL.txt`, `fonts/dm-sans-OFL.txt`).

## Files

| Path | What |
|---|---|
| `tokens.json` | Every value, with its use. The source of truth |
| `tokens.css` | Generated: custom properties for both themes and one class per type style |
| `build.py` | Builds `tokens.css`, the icons, `sample/swatches.css` and `index.html`; checks contrast |
| `fonts/` | Lora and DM Sans (woff2, Latin), `fonts.css`, the two OFL licences |
| `components/` | `bundle.css` (every component), `bundle.js` (language indicator, Layers), one folder per component with its README |
| `icons/` | `hand.py`, `build.py`, `svg/*.svg`, `icons.js`, the drawing rule |
| `motion/` | `motion.css`, `boot.js`, `motion.js` and their README |
| `assets/` | Favicon, mark and wordmark |
| `index.html` | The living sample (generated from `index.tpl.html`) |
| `sample/` | The sample page's own CSS and JS, and the wordmark export page |
| `capturas/` | Screenshots of the sample page |
| `design-system.json` | The system's manifest for the copy in Claude |

To work on it: edit `tokens.json`, the template or the CSS, then run `python3 brand/design-system/project/build.py`, and serve this folder (`python3 -m http.server 4175 --directory brand/design-system/project`, or the `design-system` entry of `.claude/launch.json`).

Load order in a page: `fonts/fonts.css`, `tokens.css`, `components/bundle.css`, `motion/motion.css`; `motion/boot.js` in `<head>`; `icons/icons.js` (if it builds icons), `components/bundle.js` and `motion/motion.js` at the end of `<body>`.
