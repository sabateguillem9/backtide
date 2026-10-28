# Wordmark

The name, set in type: a round dot in `clay-mark`, then `backtide` (or `backtide labs`) in DM Sans 500, lowercase.

## When to use it

Once per page, as the home link at the top left, and again in the footer. In the product web it is the home link of the header.

## Variants

- default: `body` size, the dot at `size-dot`.
- `.wordmark--large`: `heading-m` size, the dot at 0.55em. For a cover or a slide.
- The text may be `backtide` or `backtide labs`; nothing else.

## States

- Hover and focus: none of its own; the focus ring as everywhere.

## Accessibility

- As a link, give it an `aria-label` that says where it goes ("backtide labs, home").
- The dot is `aria-hidden`.

## Markup

```html
<a class="wordmark" href="/" aria-label="backtide labs, home">
  <span class="wordmark__dot" aria-hidden="true"></span><span>backtide labs</span>
</a>
```

Styles: `components/bundle.css`, section "Wordmark". Every value is a token.

## In the product web today

`.home` in `base.html`.

## Do not

- No capitals, other weights, colours, outlines or shadows.
- The dot is always a circle, always clay.
