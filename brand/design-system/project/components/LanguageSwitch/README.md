# LanguageSwitch

EN and ES as two small buttons; the current one sits on a `band` pill that slides between them. The theme switch (Light, Dark) is the same component.

## When to use it

In the header and the footer of every public page; in the footer of the product web, with the theme switch beside it.

## Variants

- Buttons with `aria-pressed` (pages that change language in place) or links with `aria-current="true"` (pages that reload, like the product web).
- The theme switch: the same markup with Light and Dark.

## States

- Without JavaScript the pressed one has its own `band` background. With `components/bundle.js`, one `.langs__ind` slides (transform only, `duration-settle`).

## Accessibility

- A `role="group"` with `aria-label="Language"`.
- The Spanish button has `lang="es"`.
- The choice lives in the address (`?lang=`), never in a cookie.

## Markup

```html
<div class="langs" role="group" aria-label="Language">
  <button type="button" data-lang="en" aria-pressed="true">EN</button>
  <button type="button" data-lang="es" aria-pressed="false" lang="es">ES</button>
</div>
```

Styles: `components/bundle.css`, section "LanguageSwitch". Every value is a token.

## In the product web today

`.langs` and `.theme-switch` in the footer of `base.html`.

## Do not

- No flags.
