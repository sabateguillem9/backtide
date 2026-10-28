# Card

One agent in the control room: its name and state, its last action, its day in one line, and its links.

## When to use it

The panel of the product web, one per agent, in a grid.

## Variants

- On its agent's wash (`.agent--N`), or on `band` without one.
- With a call to action when something waits (a clay `.link`).

## States

- The state badge changes with the agent; the whole card is replaced by the stream, so keep it static markup.

## Accessibility

- The card is an `<article>` labelled by its name (`aria-labelledby`).
- The last action's risk is a badge with its word (visually hidden if needed).

## Markup

```html
<article class="card agent--1" aria-labelledby="name-mail">
  <div class="card__head">
    <h3 class="card__name" id="name-mail"><a class="agent-tag" href="..."><span class="agent-tag__name">mail-helper</span></a></h3>
    <span class="badge badge--waiting"><span class="badge__dot" aria-hidden="true"></span>Waiting for you</span>
  </div>
  <p class="card__last">Wants to send an email to two people <time class="muted">2 min ago</time></p>
  <p class="card__day">Today 214 actions · 12 points to go back to · nothing serious</p>
  <p class="card__links"><a href="...">Now</a><a href="...">History</a><a href="...">Snapshots</a></p>
</article>
```

Styles: `components/bundle.css`, section "Card". Every value is a token.

## In the product web today

`card.html` (`.card-in`, `.card-head`, `.card-last`, `.card-day`, `.card-cta`, `.card-links`).

## Do not

- No border box, no shadow, no coloured stripe on the side.
