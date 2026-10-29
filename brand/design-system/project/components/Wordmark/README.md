# Wordmark

The mark, then the name set in type: the estela (a clay dot going back, and the one line it leaves behind it, in ink), then `backtide` (or `backtide labs`) in DM Sans 500, lowercase.

## When to use it

Once per page, as the home link at the top left, and again in the footer. In the product web it is the home link of the header.

## Variants

- default: `body` size; the mark as tall as the dot (`size-dot`).
- `.wordmark--large`: `heading-m` size, the mark at 0.55em. For a cover or a slide.
- The text may be `backtide` or `backtide labs`; nothing else.

## The drawing

`mark.html` in this folder is the mark as the Wordmark draws it: an inline SVG, cropped to the dot's height and the line's end, `aria-hidden`, with classes and no colours (the line takes the name's colour, `currentColor`; the dot is `clay-mark`). `assets/mark.py` writes it, with the same seeds as `assets/mark.svg`, and `build.py` puts it into the sample page wherever the template says `{{mark}}`. Pages copy it unchanged, character for character: `tests/test_site.py` and `tests/test_web_brand.py` check every copy against this file.

Its line's stroke is in the mark's own units (2.6 at a 30-unit word, the stem of DM Sans 500), so it grows with the name. The mark's middle sits on the middle of the x-height.

## Motion

- `.enter-mark` on the Wordmark (in a header, on the public site): once, on load, the dot comes back from the right and its line draws itself behind it, from far to near (`motion/motion.css`, `duration-draw`, `ease`). Only under `.anim`: never with reduced motion, never for a hidden tab, never after a view transition.
- Never in the product web, never in a footer, never on hover, never in a loop.

## States

- Hover and focus: none of its own; the focus ring as everywhere.

## Accessibility

- As a link, give it an `aria-label` that says where it goes ("backtide labs, home").
- The mark is `aria-hidden`; the name is the text.

## Markup

```html
<a class="wordmark" href="/" aria-label="backtide labs, home">
  <!-- mark.html, unchanged --><span>backtide labs</span>
</a>
```

Styles: `components/bundle.css`, section "Wordmark". Every value is a token, except the mark's own geometry.

## In the product web today

`.home` in `base.html`, still (no `.enter-mark`).

## Do not

- No capitals, other weights, colours, outlines or shadows.
- Never redraw, stretch or flip the mark, or put it after the name. The dot is always a circle, always clay; the line never touches it.
