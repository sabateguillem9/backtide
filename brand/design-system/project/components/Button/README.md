# Button

An action. Primary in ink with paper text; secondary with a `line` border; danger with crimson text for what removes something.

## When to use it

Primary for the one action a view is for (Approve, Read the testers' guide); secondary for the alternative (Reject, Source on GitHub); danger for removing a key or a rule. At most one primary per group.

## Variants

- `.btn--primary`, `.btn--secondary`, `.btn--danger`.
- `.btn--small`: 44px high, `label` size, for the product web's rows and cards.
- With an arrow (`.arrow` after the text) when it takes you somewhere; the arrow steps 3px on hover.
- `.btn-row` lays several out with `space-3` between them.

## States

- Hover: a layer fades in (`ink-hover` or `hover`); only opacity moves.
- Active (secondary): the layer turns `band`.
- Focus: the 2px ring.
- Disabled (`disabled` or `aria-disabled="true"`): `band` ground and `ink-muted` text, no hover. Say why next to it (`aria-describedby`).

## Accessibility

- Use `<button>` for actions and `<a>` for navigation; never a `div`.
- At least `size-button` (48px) or `size-target` (44px) high.
- The text says what happens; an arrow is `aria-hidden`.

## Markup

```html
<a class="btn btn--primary" href="/guide"><span>Read the testers' guide</span><svg class="arrow" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M3 8h10M9 4l4 4-4 4"/></svg></a>
<button class="btn btn--secondary" type="button">Reject</button>
<button class="btn btn--primary btn--small" type="button" disabled aria-describedby="why">Approve</button>
```

Styles: `components/bundle.css`, section "Button". Every value is a token.

## In the product web today

`.req-yes` (with its `.dot-button`), `.req-no`, `.setting-go`, `.setting-remove`, `.settings-yes`, `.settings-cancel`.

## Do not

- No shadows, no gradients, no pill-shaped buttons (10px radius, always).
- No icon-only buttons without a visible word.
