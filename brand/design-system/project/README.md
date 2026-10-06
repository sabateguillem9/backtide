backtide is the flight recorder and the rewind button for AI agents. The brand is one idea drawn with one shape: **the dot**. A dot is a moment of the agent; its hops are the agent's activity; the line it leaves is the record; the wave is the tide, which is also time; the tide calming back into a still line is the rewind: everything as it was. Everything below follows from that.

## Content fundamentals

- Write in English for the product and its pages. Spanish is the second language on the website; every string ships in both.
- Write the name `backtide`, always lowercase, also at the start of a sentence. Never "BackTide" or "Backtide".
- Write short, calm, precise sentences. One idea per sentence. No exclamation marks, no "revolutionary", no fear as a hook: state the facts of what agents do ("Deletes, payments and messages wait for your approval on your phone.").
- Address the reader as "you" and the product's subject as "your agent". Use sentence case for headlines.
- Pair every headline with one line that explains it. Real pairs from the landing page:
  - "Rewind anything." / "The whole workspace, back to any moment."
  - "Even the rewind." / "Changed your mind? Undo it."
  - "A black box it can't erase." / "Every action, chained and signed. Tampering shows."
- Show where each part of the product stands with a `Status` line: "Built and tested", "In progress" or "Next", then how it is solved in one sentence ("Btrfs snapshots, swapped atomically."). Say "Built and tested" only when it has tests that pass.
- Name buttons by what happens ("Join the waitlist"); report results plainly ("Almost there: check your inbox to confirm your email.").
- No emoji, no icons as decoration.

## Visual foundations

### Color
- Set every page on `paper` with text in `ink`. backtide is white first: web pages use the light theme; the dark theme exists for dark slides and dark-mode documents.
- Use `ink-muted` for the line under a headline, labels, notes and footer links; `ink-soft` for long running text; `placeholder` only inside fields.
- Put glyphs on an ink fill in `on-ink`, never a literal white.
- There is no accent color. Do not add one. Emphasis comes from size, weight and space, never hue.

### Type
- Use Jost (`--font-sans`) for everything: wordmark, headlines and text. Weight 500 for the wordmark and headlines, 400 for text.
- Use the type styles by role: `wordmark` for the name only; `statement` for one sentence alone on screen, once per page; `headline` + `body` for a message; `title`, `section` and `body-long` for documents; `input` inside fields; `small` for labels and notes; `micro` for the footer.
- Keep running text at most `size-measure` (40rem) wide; balance headlines.

### The dot, the line, the wave
- The dot is a perfect circle (`radius-dot`) in `ink`. It is the dot of the i in the wordmark, the brand mark, the favicon and the submit button.
- The line is `stroke-tide` (2px) in `ink`, round caps and joins. Fields are a single `stroke-hairline` under the text: never a box.
- The wave is a sine. Hops are |sine|: a bouncing dot draws |sin x|, the tide is sin x, and the brand morphs one into the other. Draw waves with the `Tide` component rather than freehand.
- There are no cards, no shadows, no borders around groups, no gradients except the tide's fade-in, no photos, no illustrations. White space does the grouping.

### Layout
- One focal element per screen, centered or alone in generous white. Let `space-16` and `space-24` breathe around it.
- Keep a side gutter of at least `space-4`. Stack to one column on phones.
- Documents: a narrow column (`size-measure`), the small wordmark as a home link at the top, sections separated by `space-8`, a hairline above the footer.

### Motion
- Scroll leads; never hijack it beyond the intro. On the landing page the first scroll (or a tap on the dot of the i) plays the intro on its own for 1.8 s, until the first wave; after that the animation follows the scroll.
- The physics is the message: the dot hops (|sin|), the hops become the tide (sin), and at the end the tide calms: the waves flatten into a still line that settles exactly on the email field's hairline, and the dot becomes its button. That calm is the rewind. Nothing runs backwards or spins.
- Ease with sine in-out for travel and cubic out for arrivals. No springs, no overshoot, nothing that blinks.
- Always respect `prefers-reduced-motion`: show the same words and the same form, still. Without JavaScript the page must read the same.

### States
- Keyboard focus is a solid `stroke-focus` (2px) outline in `ink`, offset 3px (4px around the dot button). Never remove it.
- The active language shows in `ink`, the others in `ink-muted`.
- Errors are a short sentence in `ink` replacing the note; nothing turns red.

## Iconography

- backtide has no icon set. The only glyph is the arrow inside the dot button: a 16px stroke icon, 1.6px, round caps, in `on-ink`.
- Use the dot itself where another brand would use an icon. Never use emoji.

## Logos

- `assets/Logos/backtide-wordmark.svg` is the wordmark outlined from Jost Medium with the round dot; use it where the font cannot load (emails, slides, social images). In pages, set the wordmark in type with the `Wordmark` component.
- `backtide-mark.svg` is the dot alone, for the favicon and avatars. Use the `-white` versions on `ink` grounds.
- Give the wordmark clear space of at least the height of its x-height on every side. Never stretch, outline, shadow, recolor or set it in capitals.

## Legal and language on every public page

- Every public page shows, in the footer and in `micro`, links to the privacy policy and the legal notice, and the language switch (EN, ES). The language follows the browser, can be changed, and is remembered only in local storage.
- Forms that collect data say what for in one line next to the field and link the privacy policy ("One email when it's ready. Nothing else. Unsubscribe anytime.").
- The site sets no cookies and loads nothing from third parties; fonts are served from our own files.
