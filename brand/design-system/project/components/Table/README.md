# Table

Rows of facts: a caption, a head in `caption` type over a `line` rule, rows divided by hairlines, numbers on the right in tabular figures.

## When to use it

The history of an agent, the snapshots, the settings, the prices; any list you compare across columns.

## Variants

- `.table--stack`: on phones each row becomes a block and each cell shows its column's name (`data-label`).
- Inside `.table-wrap` to scroll sideways when it cannot stack.
- `th scope="row"` for the name of a row (a setting).

## States

- Row hover: `hover` ground.
- Empty: an `EmptyState` instead of the table, or `.table-empty` for a short line.

## Accessibility

- A real `<table>` with `<caption>`, `<thead>` and `scope` on headers.
- Times in `<time datetime>`.
- Commands and paths in `<code>`; anything from the agent is escaped and cut.

## Markup

```html
<div class="table-wrap"><table class="table table--stack">
  <caption>What research did, newest first</caption>
  <thead><tr><th scope="col">When</th><th scope="col">What</th><th scope="col">Risk</th><th scope="col" class="num">Size</th></tr></thead>
  <tbody><tr><td data-label="When"><time datetime="...">10:04:11</time></td><td data-label="What">Ran <code>git reset --hard</code></td><td data-label="Risk"><span class="badge badge--risk-2">...Important</span></td><td data-label="Size" class="num">—</td></tr></tbody>
</table></div>
```

Styles: `components/bundle.css`, section "Table". Every value is a token.

## In the product web today

`history_rows.html` / `event_row.html`, `snapshots.html` (`.snaplist`), `.settings-list` rows, the prices.

## Do not

- No zebra stripes, no vertical rules, no boxes around the table.
