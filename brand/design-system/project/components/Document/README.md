# Document

A document page (privacy, legal notice): a title with its drawing, then sections with the heading on the left and the text on the right.

## When to use it

Legal pages and any long, plain page of the site.

## Variants

- On phones the heading sits above its text.

## States

- Sections rise into view on scroll.

## Accessibility

- One `h1`, then `h2` per section; text at most `measure` wide.

## Markup

```html
<main class="wrap"><div class="grid doc">
  <div class="doc__head ic-host"><svg class="ic ic-scale" ...></svg><h1 class="doc__title">Privacy</h1></div>
  <section class="doc__section"><h2>What is collected</h2><div><p>Nothing. ...</p></div></section>
</div></main>
```

Styles: `components/bundle.css`, section "Document". Every value is a token.

## In the product web today

Not in the product web.

## Do not

- No tables of contents in a sidebar; the page is short.
