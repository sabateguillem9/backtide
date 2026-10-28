# Assets

- `favicon.svg`: a clay dot (`clay-mark`) on an ivory rounded square. The favicon of every page.
- `favicon-dark.svg`: the same on charcoal, for a dark theme or a dark tab strip.
- `mark.svg`: the dot alone, clay, for avatars and app icons.
- `wordmark.svg` / `wordmark-dark.svg`: the dot and `backtide` for documents and slides, in ink or in the dark theme's ink.

The wordmark files set the name as SVG text in DM Sans 500: where DM Sans is not installed, a system sans takes its place. Outlining the glyphs needs a font tool the repository does not have yet (fontTools, a new dependency to approve); until then, for an image that must look exact, render `sample/wordmark.html` in a browser and take a screenshot of it.

Clear space: at least the height of the dot on every side. Never stretch, recolour, outline, shadow or capitalise.
