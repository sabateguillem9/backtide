# Field

Form controls: a text field, a text area, a select, a switch, a checkbox, each with its label, an optional hint and its error.

## When to use it

Settings (keys, caps, alerts), the filters of the history, the confirmation steps, asking the agent.

## Variants

- `.input` (text), `.input--area` (several lines), `.input--code` (monospace, for keys and commands).
- `.select > select` (a native select with a drawn chevron).
- `.switch` (a checkbox with `role="switch"`, drawn as a track and thumb) with its state in words (`.switch__state`).
- `.check` (a checkbox).
- `.field--error` with `.field__error`; `.fields` stacks fields with `space-6`.

## States

- Rest: `edge` border on paper (3:1). Hover: `ink-muted`. Focus: ink border and the 2px ring.
- Error: crimson border and a crimson sentence with the warning drawing, linked by `aria-describedby`, and `aria-invalid="true"`.
- Disabled: `band` ground, `hair` border, `ink-muted` text, and a hint saying why.

## Accessibility

- Every control has a visible `<label>`; placeholders are examples, never labels.
- Hints and errors are tied with `aria-describedby`.
- The switch is a real checkbox: keyboard and screen readers work without JavaScript.
- Never put a secret back in a field: show only its last four characters, as text.

## Markup

```html
<div class="field field--error">
  <label class="field__label" for="cap">Daily cap, in euros</label>
  <input class="input" id="cap" type="text" inputmode="decimal" aria-invalid="true" aria-describedby="cap-error">
  <p class="field__error" id="cap-error"><svg class="ic ic-warning" ...></svg>Write an amount of zero or more.</p>
</div>
<label class="switch"><input class="switch__input" type="checkbox" role="switch"><span class="switch__track" aria-hidden="true"><span class="switch__thumb"></span></span><span class="switch__label">Hold every email <span class="switch__state">Off</span></span></label>
```

Styles: `components/bundle.css`, section "Field". Every value is a token.

## In the product web today

`.filters` in `history.html`, `settings_step.html` (`.setting-field`, `.setting-input`, `.setting-hint`, `.setting-check`), `ask_form.html`.

## Do not

- No floating labels, no fields that are only an underline (that was v1).
