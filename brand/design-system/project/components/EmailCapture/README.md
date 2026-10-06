# EmailCapture

The waitlist form: label, email field, the dot as submit, one line saying what the email is for, and the privacy link.

- Props: `onSubmit(email, setStatus)`: send the address to the waitlist service (with double opt-in) and report with `setStatus({ text, error })`. Texts are props too (`label`, `placeholder`, `submitLabel`, `info`, `privacyHref`, `privacyLabel`, `invalidText`) so every language can be passed in.
- Keep the info line ("One email when it's ready. Nothing else. Unsubscribe anytime.") and the privacy link: they are the legal first layer.
- Errors are one sentence in `ink` that replaces the note; nothing turns red.
