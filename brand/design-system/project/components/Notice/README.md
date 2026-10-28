# Notice

A short message on a soft ground with its drawing: information, success, warning, error, or something that waits for you.

## When to use it

A state of the page worth knowing before you act: approvals are off; a list may be incomplete; the sensor stopped; it was rewound; requests wait.

## Variants

- `.notice--info` (tide blue title, `info` icon), `.notice--ok` (sage, `approve`), `.notice--warn` (ochre, `warning`), `.notice--danger` (crimson, `warning`), `.notice--hold` (clay title on `hold-wash`, `holds`).
- Plain `.notice` on `band` for a neutral note; `.notice--quiet` with no ground.
- With a title (`.notice__title`) or text only; with links (`.notice__actions`).

## States

- Static. Do not animate a notice in; if it appears after an action, move focus or announce it.

## Accessibility

- `role="status"` for a result that appears after an action, `role="alert"` only for something urgent that appears on its own (the sensor stopped), `role="note"` otherwise.
- The title's colour is backed by its words; the icon is `aria-hidden`.

## Markup

```html
<div class="notice notice--info" role="note">
  <svg class="ic ic-info" ...></svg>
  <div><p class="notice__title">Approvals are off in this web</p><p class="notice__text">Start it with <code>backtide web --aprobar</code>.</p></div>
</div>
```

Styles: `components/bundle.css`, section "Notice". Every value is a token.

## In the product web today

`.note`, `.note.is-stale`, `.settings-off`, `.settings-warning`, `.rewind-off`, `.req-soon`, the outcomes of `settings_step.html` and `hold_step.html`.

## Do not

- One notice per view, two at most.
- Not for success after every click; a quiet word next to the button is often enough.
