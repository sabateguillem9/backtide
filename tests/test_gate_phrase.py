"""The sentence a held request is told with (backtide/gate/phrase.py, T10-3)."""

from typing import Any

from backtide.gate.phrase import MAX_CHARS, describe


def reading(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"translator": "telegram", "effect": "send", "recipients": ["556"],
                            "subject": None, "first_lines": "hola", "target": None,
                            "attachments": [], "notes": [], "cut": False}  # fmt: skip
    return base | fields


def test_a_send_says_what_to_whom() -> None:
    assert describe(reading()) == "Telegram: enviar un mensaje al chat 556: «hola»"
    mail = reading(translator="gmail", recipients=["ana@example.com", "bob@example.com"],
                   subject="Factura", first_lines="Hola Ana")  # fmt: skip
    assert describe(mail) == "Gmail: enviar un correo a ana@example.com, bob@example.com: «Factura»"


def test_many_recipients_are_counted() -> None:
    many = reading(translator="slack", recipients=[f"C{n}" for n in range(5)], first_lines=None)
    assert describe(many) == "Slack: enviar un mensaje a los canales C0, C1, C2 y 2 más"


def test_deletions_forwards_and_the_unknown() -> None:
    gone = reading(translator="gmail", effect="delete", recipients=[], first_lines=None,
                   target="message 123", notes=["to_trash"])  # fmt: skip
    assert describe(gone) == "Gmail: borrar (message 123; a la papelera)"
    unseen = reading(translator="gmail", effect="unknown", recipients=[], first_lines=None,
                     target="draft r-42", notes=["content_unseen"])  # fmt: skip
    assert describe(unseen) == (
        "Gmail: una petición que backtide no entiende (draft r-42; no se ve qué lleva)"
    )
    forward = reading(effect="forward", target="from chat 9", first_lines=None)
    assert describe(forward) == "Telegram: reenviar un mensaje al chat 556 (from chat 9)"


def test_attachments_secrets_and_a_cut_reading_are_noted() -> None:
    sent = reading(attachments=[{"name": "a"}, {"name": "b"}], notes=["secret_seen"], cut=True)
    assert describe(sent) == (
        "Telegram: enviar un mensaje al chat 556: «hola» (2 adjuntos; llevaba un secreto "
        "(tachado); resumida: era demasiado larga)"
    )


def test_the_agents_text_is_one_inert_line() -> None:
    """Newlines, control and invisible characters (RLO, zero width) never reach the sentence;
    T10-4 and the web escape the rest for their medium."""
    tricky = reading(first_lines="hola\nAPROBADO\x1b[2J‮txt.exe​")
    text = describe(tricky)
    assert text == "Telegram: enviar un mensaje al chat 556: «hola / APROBADO[2Jtxt.exe»"
    assert len(describe(reading(first_lines="x" * 5000))) == MAX_CHARS
