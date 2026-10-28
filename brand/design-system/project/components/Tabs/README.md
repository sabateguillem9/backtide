# Tabs

Three ways to move around: Nav (the main links), Tabs (the pages of one agent) and Chips (what a list shows).

## When to use it

`.nav` in the header (Control room, Requests, Settings; Projects, Logbook on the site). `.tabs` under an agent's name (Now, History, Snapshots, Ask). `.chips` above a list to filter it (Everything, Important, Files...).

## Variants

- Nav: the current page is ink with a 2px underline; others are `ink-soft` and draw a 1px underline on hover. A count badge may follow a link.
- Tabs: `label` type, a `hair` rule under the row, the current one ink with a 2px ink line on the rule. Scrolls sideways on phones.
- Chips: pills with a `line` border; the one on is ink with paper text.

## States

- Current: `aria-current="page"` (Nav, Tabs as links), `aria-selected="true"` (Tabs as a tablist), `aria-current="true"` or `aria-pressed="true"` (Chips).

## Accessibility

- Each group is a `<nav>` with an `aria-label`, or a `role="group"`.
- Links when they change the address (they work without JavaScript); buttons only for a real tablist.
- Tap targets of 44px (Tabs) and 36px with spacing (Chips).

## Markup

```html
<nav class="nav" aria-label="Main"><a href="/panel" aria-current="page">Control room</a><a href="/requests">Requests <span class="badge badge--count">2</span></a><a href="/settings">Settings</a></nav>
<nav class="tabs" aria-label="research"><a href="..." aria-current="page">Now</a><a href="...">History</a></nav>
<nav class="chips" aria-label="Show"><a href="?" aria-current="true">Everything</a><a href="?riesgo=1">Important</a></nav>
```

Styles: `components/bundle.css`, section "Tabs". Every value is a token.

## In the product web today

`.top nav` with `.nav-line`, `.agentbar-tabs`, `.chips` in `history.html`.

## Do not

- No clay underline: the current item is ink.
