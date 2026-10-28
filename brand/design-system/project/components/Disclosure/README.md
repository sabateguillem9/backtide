# Disclosure

A `<details>` that folds what most people do not need: a chevron that turns, a label, and what it hides.

## When to use it

More filters; More under a held request (trust this recipient, see the whole request); the full contrast table.

## Variants

- Open by default with `open` when what it hides is in use (a filter is on).

## States

- The chevron turns 90° (`duration-settle`). The body appears at once; it does not slide.

## Accessibility

- Native `<details>` and `<summary>`: keyboard and screen readers work without JavaScript.
- The summary is at least 44px high.

## Markup

```html
<details class="disclosure">
  <summary>More filters</summary>
  <div class="disclosure__body">...</div>
</details>
```

Styles: `components/bundle.css`, section "Disclosure". Every value is a token.

## In the product web today

`.more-filters`, `.req-more`.

## Do not

- Never hide the main action in one.
