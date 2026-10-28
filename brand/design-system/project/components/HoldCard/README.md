# HoldCard

An action the agent wants to take that waits for your yes: who and when, what it wants to do (in our words), what it costs, the agent's own words in a block of their own, why it waits, its risk, the time left, and Approve and Reject.

## When to use it

In "Waiting for your yes" in the control room and on the Requests page. One per held request, the first to run out first.

## Variants

- Waiting, with approvals on: Approve (primary, with an arrow) and Reject (secondary), then More (a `Disclosure`: trust this recipient, see the whole request).
- Waiting, with approvals off: both disabled, and `.hold__note` saying how to answer.
- In its last minute: `.countdown--last` (crimson time and bar).
- Answered: `.hold--approved` (sage ground, `.hold__outcome` with the approve drawing) or `.hold--rejected` / `.hold--expired` (band ground, `reject` drawing). `.hold--compact` drops the side column.

## States

- The countdown bar is `data-q="0"` to `"10"` (tenths left), set by the server and the stream, so nothing needs a style attribute; its text is the time left.
- Approve and Reject are links to a confirmation page (GET changes nothing), as today.

## Accessibility

- An `<article>` labelled by what it wants (`aria-labelledby`).
- The risk is a badge with its word; the time left is text, the bar is `aria-hidden`.
- Disabled buttons point to their reason (`aria-describedby`).
- Everything in `.hold__words` comes from the agent: escaped, invisible characters made visible, cut (`vis()`), and in JavaScript only `textContent`.

## Markup

```html
<article class="hold agent--1" aria-labelledby="h1">
  <div class="hold__main">
    <p class="hold__who"><a class="agent-tag" href="..."><span class="agent-tag__name">mail-helper</span></a><span class="hold__when">held <time datetime="...">2 min ago</time></span></p>
    <h3 class="hold__what" id="h1">Send an email to two people</h3>
    <p class="hold__cost">Once it leaves, it cannot be called back.</p>
    <div class="hold__words"><p class="hold__words-head">What the agent asks</p><p><span class="muted">To</span> ana@exam…le.com</p></div>
    <p class="hold__why"><span class="muted">Why it waits</span> Every email waits for you.</p>
  </div>
  <div class="hold__side">
    <span class="badge badge--risk-2"><span class="badge__dot" aria-hidden="true"></span>Important</span>
    <div class="countdown" data-q="7"><p class="countdown__text">Left <span class="countdown__left">3:24</span></p><span class="countdown__bar" aria-hidden="true"><span class="countdown__fill"></span></span></div>
    <div class="hold__actions"><a class="btn btn--primary btn--small" href="...&v=aprobar"><span>Approve</span><svg class="arrow" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M3 8h10M9 4l4 4-4 4"/></svg></a><a class="btn btn--secondary btn--small" href="...&v=rechazar">Reject</a></div>
  </div>
</article>
```

Styles: `components/bundle.css`, section "HoldCard". Every value is a token.

## In the product web today

`.req` in `requests.html` (`.req-main`, `.req-side`, `.req-who`, `.req-what`, `.req-cost`, `.req-agent`, `.req-why`, `.req-risk`, `.req-clock`, `.req-bar`/`.req-fill q-N`, `.req-actions`, `.req-more`), `hold_view.html` and `hold_step.html`.

## Do not

- Never mix the agent's words into ours.
- No red ground: the risk speaks through its badge and the clock.
