# Motion

Calm and once. Things arrive, settle and stay.

- `boot.js` (in `<head>`, as a file): adds `.js`; `.still` with reduced motion; `.anim` for the entrance, never for a hidden tab, removed after 2.6 s or when the page arrives through a view transition.
- `motion.css`: every keyframe and transition that is not a component's own hover.
- `motion.js` (end of `<body>`): reveal on scroll, Inside the box, the hidden tab, `BacktideMotion.swap(fn)`.
- `idle.css` and `idle.js` (after `motion.css` and `motion.js`): the drawings' slow idle, **for the public site only** (D34). The product web never loads them.

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
| Drawings that idle, slowly, while on screen (public site only) | `data-idle` on a container, or `.ic--idle` on one drawing | Needs `idle.css` and `idle.js`; `data-idle="off"` rests them again |
| A title that flies to the next page | `.vt-title` on both pages | Cross-document view transitions |
| A change in place, cross-faded | `BacktideMotion.swap(() => ...)` | Falls back to a plain change |

## Values

From `tokens.json`: `ease` `cubic-bezier(.22, 1, .36, 1)`, `ease-reveal` `cubic-bezier(.2, .7, .2, 1)`, `ease-draw` `cubic-bezier(.45, 0, .25, 1)`, `ease-drop` `cubic-bezier(.3, .7, .3, 1)`; 200 ms (focus), 250 ms (hover), 450 ms (settle), 600 ms (icon, page), 750 ms (reveal), 800 ms (entrance), 850 ms (draw); 14px rise, 18px for the headline, 80 ms stagger, 12px lift, 3px nudge.

## Idle (D34, the public site only)

On backtide labs and its project pages a drawing may idle: now and then it makes a smaller, slower version of its own gesture, and rests the rest of the time. The product web stays still (it is where people approve and reject; there only a live agent's dot breathes): it never loads `idle.css` or `idle.js`, and `tests/test_web_brand.py` checks that.

- **Opt in** with `data-idle` on a section, a row or a list (every drawing inside it), or `.ic--idle` on one drawing. Keep the hero calm: its drawing draws itself once and stays. Leave the states (Preview, In progress, Done) still: a moving state reads as something live.
- **What `idle.js` does:** gives each opted-in drawing a phase (`.ic--phase-0` to `-6`, 1.6 s apart, so even the first movements after a page opens are spread over ten seconds) and `.ic--idling` only while it is on screen (IntersectionObserver); drawings built or rebuilt later are picked up. It does nothing with reduced motion, without IntersectionObserver or without JavaScript, so without JavaScript nothing idles.
- **What `idle.css` does:** for each of the 20 drawings, one group moves with `transform` only, in the icon's 48 units, eased with `ease-draw` (the blink with `ease`). Each has its own period, 7 to 12.3 s, and moves for about a fifth of it (the blink for 3%), so a page of drawings never pulses in unison. While the drawing's `.ic-host` is pointed at or focused the idle stops and the gesture plays alone; afterwards the idle starts again from rest.
- **Stops:** with `prefers-reduced-motion` (and `.still`), with the tab hidden (`.is-hidden`), off screen. `idle.css` says so itself too, not only `motion.css`.

| Drawing | Group | Idle | Period |
|---|---|---|---|
| `progress` | spin | the spiral winds on 9° and settles | 9.2 s |
| `preview` | stones | the cairn finds its balance (1.4°, then less) | 11.3 s |
| `done` | moon, water | the moon lifts 1.2 units; the water drifts 1.1 units | 10.4 s, 7.6 s |
| `tape` | reels | both reels turn back once, slowly | 12 s |
| `notebook` | page | the left page lifts off the spine a little | 10.7 s |
| `pencil` | pencil | three tiny strokes of writing | 8.6 s |
| `scale` | beam | the beam weighs 2.2°, then settles | 11.6 s |
| `records` | dot | the dot steps on 1.6 units and comes back | 7.3 s |
| `rewinds` | loop | the loop turns back 20° | 9.6 s |
| `holds` | shackle | the shackle is tried, 1.3 units | 10.1 s |
| `approve` | tick | the tick nods twice | 8.9 s |
| `reject` | cross | the cross shakes its head, under a unit | 10.9 s |
| `info` | mark | the dot hops 1.6 units | 7.9 s |
| `warning` | sign | the sign rocks 1.6° on its base | 11.9 s |
| `key` | key | the key turns 7° and back | 9.9 s |
| `bell` | bell | the bell sways 2.4° and stills | 9.1 s |
| `flag` | cloth | the cloth ripples once | 7.1 s |
| `eye` | eye | the eye blinks, rarely | 12.3 s |
| `still` | sun, water | the sun sinks 0.9 units; the water drifts the other way | 11.1 s, 8.3 s |
| `ask` | bubble | the bubble floats up 1.2 units | 8.4 s |

The seven player controls never idle: they are controls.

## Never

- Nothing moves with `prefers-reduced-motion: reduce`: `.still` and the media query turn every animation and transition off, and every page is complete and still.
- Nothing runs while the tab is hidden: `.is-hidden` pauses every animation; the entrance is not played for a hidden tab; `BacktideMotion.swap` does not transition.
- Nothing loops, except a live agent state's dot in the product web (breathe, pulse) and, on the public site only, the drawings' idle (D34); both stop in the cases above, and the idle off screen too.
- Only `transform`, `opacity` and `stroke-dashoffset` move (and the headline's blur, once). Never layout, never colour as motion, never the scroll.
- Nothing is hidden unless JavaScript said so first: without JavaScript the page reads the same.
- Never `innerHTML`; these files only add and remove classes.
