# LogbookEntry

One project in the logbook, grouped by year: its month and drawing, its status, its name, its italic line, a paragraph, its links, and a few facts on the side.

## When to use it

The logbook of backtide labs, newest first.

## Variants

- With a page (`.entry__links`) or without one (`.entry__note`: "No page yet").
- On medium screens the facts move under the text; on phones everything stacks.

## States

- The year label is sticky beside its entries on wide screens. Entries rise into view on scroll, their rule growing (`data-reveal`).

## Accessibility

- Each year is a `<section>` labelled by its year; entries are an `<ol>`.
- Dates are `<time datetime>`.
- Facts are a `<dl>`.

## Markup

```html
<section class="year" aria-labelledby="y2026">
  <h3 class="year__label" id="y2026">2026</h3>
  <ol class="entries">
    <li class="entry ic-host">
      <p class="entry__when"><svg class="ic ic-tape" ...></svg><time datetime="2026-10">October 2026</time></p>
      <div class="entry__main">... <h4 class="entry__name"><a href="backtide.html">backtide</a></h4><p class="entry__line">A black box for AI agents.</p> ...</div>
      <dl class="entry__facts"><div><dt>Runs on</dt><dd>Linux</dd></div></dl>
    </li>
  </ol>
</section>
```

Styles: `components/bundle.css`, section "LogbookEntry". Every value is a token.

## In the product web today

Not in the product web.

## Do not

- No cards around entries: rules and space only.
