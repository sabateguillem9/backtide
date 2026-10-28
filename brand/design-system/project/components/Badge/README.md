# Badge

A small word with a mark: a risk (0 to 3), an agent's state, a count, or a tag.

## When to use it

Risk next to an event or a held request; state next to an agent's name; a count in the navigation (how many wait); a tag (`Example`) next to a name.

## Variants

- Risk: `.badge--risk-0` hollow dot, `-1` thick ring (ochre), `-2` filled (clay), `-3` filled and ringed (crimson). The word is in the risk's colour.
- State: `.badge--working` (sage, breathes), `--idle` (hollow), `--frozen` (thick ring, tide blue), `--waiting` (clay, pulses), `--rewinding` (plum, breathes), `--sensor-down` (crimson, pulses).
- `.badge--count`: a number on clay, `on-ink` text, pill.
- `.tag`: `overline` in a `line` pill.

## States

- The live states loop gently (motion.css); they stop with reduced motion and pause with the tab hidden.

## Accessibility

- The dot is `aria-hidden`; the word carries the meaning. Where the word is hidden (a dense row), put it in `.visually-hidden` or an `aria-label`.
- A count in a link adds its noun for screen readers (`<span class="visually-hidden"> waiting</span>`).

## Markup

```html
<span class="badge badge--risk-3"><span class="badge__dot" aria-hidden="true"></span>Serious</span>
<span class="badge badge--waiting"><span class="badge__dot" aria-hidden="true"></span>Waiting for you</span>
<span class="badge badge--count">2</span><span class="visually-hidden"> waiting</span>
<span class="tag">Example</span>
```

Styles: `components/bundle.css`, section "Badge". Every value is a token.

## In the product web today

`.dot.dot-0` to `.dot-3` and `.risk-word`; `.pulse` with `.st-*` (`card-state`); `.badge` with `.badge-dot` in the header; `.tag` is now `AgentTag`.

## Do not

- No colour without a word or a shape.
- Not as decoration.
