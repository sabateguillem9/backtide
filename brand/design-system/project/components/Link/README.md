# Link

A link with a quiet underline at 35% that, on hover, draws itself fully from the left. In clay, or in ink for the quiet one.

## When to use it

Clay `.link` for the link you want found (Read about backtide). `.link--quiet` in ink for a second one beside it. Inside running text, a plain `<a>` keeps the browser's underline in the text's colour.

## Variants

- `.link`: clay, with an optional arrow.
- `.link--quiet`: ink.
- `.link--back`: an arrow pointing back, before the text; it steps left on hover.

## States

- Hover and focus-visible: the underline draws (`duration-settle`, `ease`); the arrow steps `nudge`.
- Focus: the ring with `focus-radius` corners.

## Accessibility

- The text alone says where it goes; no "click here".
- The arrow is `aria-hidden`.

## Markup

```html
<a class="link" href="/backtide"><span>Read about backtide</span><svg class="arrow" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M3 8h10M9 4l4 4-4 4"/></svg></a>
<a class="link link--quiet" href="https://github.com/...">Source on GitHub</a>
```

Styles: `components/bundle.css`, section "Link". Every value is a token.

## In the product web today

`.card-links a`, `.card-cta`, the links inside notes.

## Do not

- Clay once or twice per view, not on every link of a list.
