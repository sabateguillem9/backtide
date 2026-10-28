# Timeline

One agent's day, drawn as an SVG by the server: a calm line of activity in the agent's colour over a hairline axis, risk marks on it, short clay ticks where snapshots were taken, and a clay dot for now.

## When to use it

The Now page and the snapshots page of the product web (it replaces the tide of v1); smaller in a card.

## Variants

- `.tl-mark--0` to `--3` follow the risk shapes (hollow, thick ring, filled).
- `.tl-snap` ticks; `.tl-now` dot; `.tl-label` times.
- A legend (`.timeline__legend`) with badges, when the marks need explaining.

## States

- Static. If it updates live, replace it whole; do not animate the line.

## Accessibility

- `role="img"` and an `aria-label` that says the day in a sentence; the list of events next to it carries the detail.
- Marks are never colour alone: their shape changes with the risk.

## Markup

```html
<figure class="timeline agent--2">
  <svg class="timeline__svg" viewBox="0 0 640 96" role="img" aria-label="research today: steady work, one important command at 10:04.">
    <path class="tl-axis" d="M8 72H632"/><path class="tl-line" d="M8 70C40 70 ..."/>
    <path class="tl-snap" d="M120 66V78"/><circle class="tl-mark tl-mark--2" cx="450" cy="30" r="4.5"/><circle class="tl-now" cx="632" cy="42" r="5"/>
  </svg>
</figure>
```

Styles: `components/bundle.css`, section "Timeline". Every value is a token.

## In the product web today

`tide.html`, `mini_tide.html`, `tide_frame.html` (built by `tide.py`).

## Do not

- No gradient under the line (v1's fade is gone).
- No smoothing that hides a spike: the line is the record.
