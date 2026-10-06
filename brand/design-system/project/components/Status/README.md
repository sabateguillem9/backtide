# Status

Where a part of the product stands, in one short line: a dot for the state, then how it is solved.

- States: `built` (filled `ink` dot, "Built and tested"), `progress` (hollow `ink` dot, "In progress"), `next` (hollow `ink-muted` dot, "Next"). The dot is the brand's one shape, so the states need no icons and no color.
- Props: `state`, `label` (replaces the state's words, e.g. "Construido y probado", "En marcha", "Lo siguiente"), `children` (how it is solved, under twelve words).
- On the landing page each crest message carries one (pass it as `Message`'s `status`). Use the same three states on any public progress page.
- Be honest: `built` only when it has tests that pass. Update the states when the product moves; never leave a promise marked as built.
