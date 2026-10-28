# IndexRow

One project in the index at the top of backtide labs: its name in Lora, its line, the year, its status and an arrow, across the twelve columns.

## When to use it

The list of projects on the home page; any short list of things that each have a page.

## Variants

- With a `.tag` after the name (`Example`).
- On phones: name and status on one line, the line under it; year and arrow hidden.

## States

- Hover: a `hover` layer fades in, the name moves 6px right, the arrow steps 4px and turns ink, the status icon gestures (the row is an `.ic-host`).
- Focus: the ring 6px out.

## Accessibility

- The whole row is one link; its text reads in order (name, line, year, state).
- The list is an `<ol>` under a heading (`.index__head`) with its count.

## Markup

```html
<div class="index__head"><h2 class="index__title">Projects</h2><p class="index__count">1 project</p></div>
<ol class="index__list">
  <li class="index__item"><a class="index-row ic-host" href="backtide.html"><span class="index-row__name">backtide</span><span class="index-row__line">A black box for AI agents.</span><span class="index-row__year">2026</span><span class="status status--preview">...<span>Preview</span></span><svg class="arrow" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M3 8h10M9 4l4 4-4 4"/></svg></a></li>
</ol>
```

Styles: `components/bundle.css`, section "IndexRow". Every value is a token.

## In the product web today

Not in the product web; the snapshot list may borrow its hover.

## Do not

- No more than four pieces of information per row.
