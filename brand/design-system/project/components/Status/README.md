# Status

Where a project stands: its drawing (or a small dot in a ledger) and its word.

## When to use it

In the logbook, the project index and a project's page (`Preview`, `In progress`, `Done`); in a ledger of what works (`Works`, `In progress`).

## Variants

- `.status--preview` (the cairn; tide blue dot), `.status--progress` (the spiral; clay dot), `.status--done` (the moon; sage dot).
- With an icon: `{{ic:preview}}` etc. at 24px.
- With a dot: `.status__dot`, for long ledgers where icons would repeat.

## States

- Inside an `.ic-host` (a row, a section), the icon makes its gesture on hover.

## Accessibility

- The word is always there; the icon or dot is `aria-hidden`.
- Be honest: `Works` or `Done` only with tests that pass.

## Markup

```html
<span class="status status--preview"><svg class="ic ic-preview" ...></svg><span>Preview</span></span>
<span class="status status--done"><span class="status__dot" aria-hidden="true"></span><span>Works</span></span>
```

Styles: `components/bundle.css`, section "Status". Every value is a token.

## In the product web today

Not in the product web (its agent states are `Badge`).

## Do not

- No colour without the word.
