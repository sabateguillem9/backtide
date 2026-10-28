# SectionHeader

A section's heading: an optional drawing above it, the heading in Lora, and one lead line under it.

## When to use it

At the start of every section of a public page (`section` type) and every page of the product web (`section-head--app`, `heading-l` type).

## Variants

- Default: `section` heading, a lead at most 36rem, seven of twelve columns.
- `.section-head--app`: smaller heading, `body` lead.
- With an icon (`.ic` as the first child, 52px); then make it an `.ic-host` so the drawing gestures on hover.

## States

- Revealed on scroll with `data-reveal`.

## Accessibility

- The heading level follows the page's outline (`h1` for a product page's title, `h2` for a section).
- The icon is `aria-hidden`.

## Markup

```html
<div class="section-head ic-host">
  <svg class="ic ic-notebook" ...></svg>
  <h2 class="section-head__title">Logbook</h2>
  <p class="section-head__lead">Everything made here, newest first.</p>
</div>
```

Styles: `components/bundle.css`, section "SectionHeader". Every value is a token.

## In the product web today

Each page's `h1` and `.lede`; `.section-title` inside settings.

## Do not

- One drawing per section at most, and not on every section.
