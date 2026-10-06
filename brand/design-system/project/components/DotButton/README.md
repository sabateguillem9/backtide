# DotButton

The dot as a button: a 44px ink circle with an arrow in `on-ink`. It is backtide's only call to action.

- Use it at the end of a field's hairline (see `EmailCapture`) or alone for a single forward action.
- Props: `label` (required: it is the accessible name, e.g. "Join the waitlist"), `type` (`button` or `submit`), `onClick`, `disabled`.
- Hover nudges it 3px forward; focus is a 2px ink ring offset 4px. Never put text inside it.
