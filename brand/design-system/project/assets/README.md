# Assets

backtide's mark is **estela** (wake): the clay dot going back, and the one line it leaves behind it, wavy far away and almost still beside the dot. It records (the line) and comes back (the direction). Chosen by the founder from the six proposals in `brand/propuestas-logo/` (proposal 1).

Every file here is written by `mark.py` (run by `../build.py`), drawn with the icons' steady hand (`../icons/hand.py`) on their 48 x 48 grid with fixed seeds, so the files never change unless the drawing does. Colours come from `tokens.json`: `ink` for the line, `clay-mark` for the dot (the mark's only clay), `paper` for the favicon's tile; the `-dark` files use the dark theme's values.

- `mark.svg` / `mark-dark.svg`: the mark alone, transparent, on the 48 grid. For an avatar or a sticker, put it on paper (or charcoal) with clear space.
- `lockup.svg` / `lockup-dark.svg`: the mark and `backtide` in a row, the mark's middle on the middle of the x-height. For documents and slides.
- `lockup-stacked.svg` / `lockup-stacked-dark.svg`: the mark larger, centred above `backtide`. For a cover or a square.
- `lockup-labs.svg` / `lockup-labs-dark.svg`: the mark and `backtide labs` in a row, for the labs.
- `favicon.svg`: a simplified drawing (fewer waves, a thicker line) on an ivory rounded square: the favicon of every page.
- `favicon-dark.svg`: the same on charcoal, for a dark theme or a dark tab strip.

There is no text-only wordmark file: the name alone is just `backtide` set in DM Sans 500, which any document can type. The old `wordmark.svg` (the plain dot and the name) is gone; `lockup.svg` takes its place.

The lockups set the name as SVG text in DM Sans 500: where DM Sans is not installed, a system sans takes its place. Outlining the glyphs needs a font tool the repository does not have yet (fontTools, a new dependency to approve); until then, for an image that must look exact, render `sample/wordmark.html` in a browser and take a screenshot of it.

In a page, the mark is not a file: the `Wordmark` component draws it inline (`components/Wordmark/mark.html`), so it follows the theme.

The stroke: 2.5 units on the 48 grid (1.75 px when the mark is drawn at an icon's 24 px); beside the word, the stem of DM Sans 500 (2.6 units with the word at 30); on the favicon, 2.6 units on its 32 grid (1.3 px at 16 px). At 16 px the favicon reads as the dot and a wavy line.

Clear space: at least the height of the dot on every side. Never stretch, recolour, flip, outline, shadow or capitalise, and never let the line touch the dot.
