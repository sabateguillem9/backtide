# AgentTag

An agent's name after a short rounded line in its identity colour (`agent-1` to `agent-6`, by its place in the list).

## When to use it

Wherever an agent is named in the product web: its card, a held request, the agent bar, the feed.

## Variants

- `.agent--1` to `.agent--6` on the tag or on any ancestor (a card, a held request) set `--agent` and `--agent-wash`.
- `.agent-tag--hue`: the name in the agent's colour too (the live feed).

## States

- As a link: the name underlines on hover.

## Accessibility

- The colour is never alone: the name is always written. The line is a pseudo-element, invisible to screen readers.
- Agent names come from outside: put them in with `textContent` or escaped by the template, cut to 48 characters.

## Markup

```html
<a class="agent-tag agent--2" href="/agents/research/now"><span class="agent-tag__name">research</span></a>
```

Styles: `components/bundle.css`, section "AgentTag". Every value is a token.

## In the product web today

`.tag` + `.agent-name` inside `.a-N`.

## Do not

- No more than six colours: a seventh agent reuses from the start, as today.
