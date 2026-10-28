# LegalFooter

The footer of every public page: the wordmark, Privacy, Legal notice and GitHub, the language switch, and one line on what is collected.

## When to use it

On every public page, last. The product web uses `.foot--app`, shorter: what it is (local), the theme and language switches.

## Variants

- `.foot` (public), `.foot--app` (product web).

## States

- Its rule grows when it enters the screen (`data-reveal="line"` on `.foot__inner`).

## Accessibility

- A `<footer>` with a `<nav aria-label="Site">`.
- Links at least 15px with room around them.

## Markup

```html
<footer class="wrap foot">
  <div class="foot__inner" data-reveal="line">
    <div class="foot__row">
      <a class="wordmark" href="/">...</a>
      <nav class="foot__links" aria-label="Site"><a href="legal.html#privacy">Privacy</a><a href="legal.html#legal">Legal notice</a><a href="https://github.com/...">GitHub</a></nav>
      <div class="langs" role="group" aria-label="Language">...</div>
    </div>
    <p class="foot__note">This site collects no data: no cookies, no analytics, no forms.</p>
  </div>
</footer>
```

Styles: `components/bundle.css`, section "LegalFooter". Every value is a token.

## In the product web today

`.foot` in `base.html`.

## Do not

- No newsletter form, no social icons.
