# Tide

The tide line: a dot hops (|sin|), the hops fade in and grow into the wave (sin), and the dot sits at the head.

- Use it as the one graphic of a section, or to separate two moments of a story. Horizontal is the record over time; `orientation: 'vertical'` is the rewind (the wave above, the dot at the bottom).
- Props: `width`, `height`, `periods` (2.25), `amplitude` (0.38 of the height), `hops` (true), `dot` (true), `stroke` (2, the `stroke-tide` token), `tone`, `label`, and a unique `id` when several tides share a page.
- Don't draw waves by hand, fill them, or add more than one tide per screen.
