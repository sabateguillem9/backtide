# Motion

Calm and once. Things arrive, settle and stay.

- `boot.js` (in `<head>`, as a file): adds `.js`; `.still` with reduced motion; `.anim` for the entrance, never for a hidden tab, removed after 2.6 s or when the page arrives through a view transition.
- `motion.css`: every keyframe and transition that is not a component's own hover.
- `motion.js` (end of `<body>`): reveal on scroll, Inside the box, the hidden tab, `BacktideMotion.swap(fn)`.

## What to mark

| You want | Mark | Notes |
|---|---|---|
| Fade in on load | `.enter-fade` | |
| Rise in on load | `.enter-rise` | 14px, `duration-reveal` |
| The headline, word by word | `.enter-title` with each word in `<span class="w">` | Rises out of an 8px blur that clears; 120 ms between words |
| A rule that grows on load | `.enter-rule` on the element with the border | |
| A list whose items rise one by one, then their icons draw | `.enter-list` | 80 ms apart, at most five steps |
| An icon that draws itself on load | `.enter-icon` around it | |
| Delay any of these | `.at-1` ... `.at-8` | 100 ms steps |
| Rise into view on scroll, once | `data-reveal` (or `"rise"`) | Only what is below the fold at load |
| A top rule that draws on scroll | `data-reveal="line"` (or `"rise line"`) | |
| A drawing that draws itself on scroll | `data-reveal="draw"` | Paths with `pathLength="1"` |
| Stagger siblings on scroll | `data-reveal-group` on the parent | Adds `.d-0` ... `.d-5` |
| An icon's gesture on hover and focus | `.ic-host` on its row, card or section | |
| A title that flies to the next page | `.vt-title` on both pages | Cross-document view transitions |
| A change in place, cross-faded | `BacktideMotion.swap(() => ...)` | Falls back to a plain change |

## Values

From `tokens.json`: `ease` `cubic-bezier(.22, 1, .36, 1)`, `ease-reveal` `cubic-bezier(.2, .7, .2, 1)`, `ease-draw` `cubic-bezier(.45, 0, .25, 1)`, `ease-drop` `cubic-bezier(.3, .7, .3, 1)`; 200 ms (focus), 250 ms (hover), 450 ms (settle), 600 ms (icon, page), 750 ms (reveal), 800 ms (entrance), 850 ms (draw); 14px rise, 18px for the headline, 80 ms stagger, 12px lift, 3px nudge.

## Never

- Nothing moves with `prefers-reduced-motion: reduce`: `.still` and the media query turn every animation and transition off, and every page is complete and still.
- Nothing runs while the tab is hidden: `.is-hidden` pauses every animation; the entrance is not played for a hidden tab; `BacktideMotion.swap` does not transition.
- Nothing loops, except a live agent state's dot in the product web (breathe, pulse), which also stops in both cases above.
- Only `transform`, `opacity` and `stroke-dashoffset` move (and the headline's blur, once). Never layout, never colour as motion, never the scroll.
- Nothing is hidden unless JavaScript said so first: without JavaScript the page reads the same.
- Never `innerHTML`; these files only add and remove classes.
