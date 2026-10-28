# Layers

"Inside the box": four isometric slabs (agent, proxy, sensor, backtide) beside their descriptions, on a full-width band.

## When to use it

Once, on backtide's page, to show how it is built. The pattern (a drawing beside its legend, each lighting the other) may serve another diagram.

## Variants

- Light and dark slabs (`drawing` tokens).
- On phones the drawing sits above the list, smaller.

## States

- When a third of it is on screen (`motion.js`), the slabs drop one by one onto a stack, the stack opens, and the clay dot settles on top.
- Pointing at a slab or at its description lifts the slab 12px and lights the row (`components/bundle.js`, `data-hl`).
- With reduced motion, it is drawn open and still.

## Accessibility

- The drawing is `aria-hidden`; the list says everything it shows.

## Markup

```html
<section class="band inside" aria-labelledby="inside-title"> ... <svg class="layers" data-layers ...> <g class="layer l0" data-part="backtide"> ... </svg> <ol class="parts"><li data-part="backtide">...</li></ol> ...</section>
(Copy the full SVG from index.html.)
```

Styles: `components/bundle.css`, section "Layers". Every value is a token.

## In the product web today

Not in the product web.

## Do not

- No more than four layers; no colours outside the `drawing` tokens.
