# EmptyState

What a list shows when it has nothing: a drawing, one sentence in Lora, one line that says what will appear here and when, and maybe one link.

## When to use it

No requests waiting, no snapshots yet, no events for these filters, no agents.

## Variants

- Left-aligned (default) or `.empty--center` when it fills a page.
- Drawings: `still` (all calm), `flag` (no snapshots), `notebook` (no history), `holds` (nothing held), `eye` (not watching yet).

## States

- It is an `.ic-host`: the drawing gestures on hover.

## Accessibility

- The title is a paragraph, not a heading, unless it is the page's only content.
- The drawing is `aria-hidden`.

## Markup

```html
<div class="empty ic-host">
  <svg class="ic ic-still" ...></svg>
  <p class="empty__title">Nothing waits for you</p>
  <p class="empty__text">When an agent wants to delete, pay or send something, it stops here until you decide.</p>
</div>
```

Styles: `components/bundle.css`, section "EmptyState". Every value is a token.

## In the product web today

`wait.none`, `snaps.empty`, `card.nothing` and the empty history, all now a `.note`.

## Do not

- No jokes, no exclamation marks; say what will appear and when.
