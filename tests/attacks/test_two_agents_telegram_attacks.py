"""T26-2e (invariants 6, 7): one Telegram bot and two real agents, under the real unit.

A button of one agent must never act on another, and an order that does not say which must not
guess. On the lab of tests/attacks/two_agents_kit.py, with the bot of the service pointed at a FAKE
Bot API on the VM's 127.0.0.1 (tests/telegram_fake.py): nothing reaches Telegram and no real token
is used (invariant 8). In vigia-dev, and only with the Claude Code battery:

    make ataques PERFIL=claude-code ATK_PATH=tests/attacks/test_two_agents_telegram_attacks.py

Its own file, so its own lab: with the bot on, a hold's notice is its alert, and the scenarios of
test_two_agents_attacks.py are about a service with no bot.
"""

import json
import secrets
import time
from collections.abc import Iterator

import pytest
from attack_kit import CONTAINER_WORK, Attack, scenario
from test_two_agents_attacks import SEEN_TIMEOUT, _hold, said_in
from two_agents_kit import MAIN, OTHER, SLUG, Agent, Lab, open_lab, sh, wait

from tests.telegram_fake import OWNER, TOKEN, Call, FakeBotApi, buttons

REWIND_TIMEOUT = 180.0
WRECKED = 300  # files deleted at once: past the 100 of mass-delete-severe
TRANSIENT_WINDOW = 3.0  # seconds; the watcher's own is 2 (default_rules.toml, `transient`)


@pytest.fixture(scope="module")
def fake() -> Iterator[FakeBotApi]:
    with FakeBotApi(token=TOKEN, max_poll=5.0) as made:
        yield made


@pytest.fixture(scope="module")
def lab(fake: FakeBotApi) -> Iterator[Lab]:
    found = open_lab(
        telegram=f'token = "{TOKEN}"\nchat_id = {OWNER}\napi_base = "{fake.base}"\n',
    )
    try:
        yield found
    finally:
        found.close()


def paused(agent: Agent) -> bool:
    ran = sh("docker", "inspect", "--format", "{{.State.Paused}}", agent.container)
    return ran.stdout.strip() == "true"


def answered(fake: FakeBotApi, contains: str, before: float) -> Call:
    """What the bot answered a press: said once it has decided what to do with it."""
    return fake.wait_call(
        "answerCallbackQuery",
        lambda c: contains in c.params.get("text", ""),
        after=before,
        timeout=30,
    )


def reply_to(fake: FakeBotApi, text: str, contains: str, timeout: float = 30) -> Call:
    before = time.monotonic()
    fake.push_message(text)
    return said_after(fake, contains, before, timeout)


def said_after(fake: FakeBotApi, contains: str, before: float, timeout: float = 30) -> Call:
    found = fake.wait_call(
        "sendMessage", lambda c: contains in c.params.get("text", ""), after=before, timeout=timeout
    )
    time.sleep(0.3)  # the bot binds its buttons once the Bot API's answer reaches it
    return found


def notice_of(fake: FakeBotApi, agent: Agent, hold_id: str) -> Call:
    head = f"Agente {agent.slug}:\n⏸ backtide · RETENIDA"
    found = fake.wait_call(
        "sendMessage",
        lambda c: c.params.get("text", "").startswith(head) and hold_id in c.params["text"],
        timeout=15,
    )
    time.sleep(0.3)
    return found


def press(fake: FakeBotApi, call: Call, label: str) -> float:
    before = time.monotonic()
    fake.push_callback(dict(buttons(call))[label], call.message_id)
    return before


@scenario("boton-de-otro-agente")
def test_a_button_acts_on_its_agent_and_on_no_other(
    attack: Attack, lab: Lab, fake: FakeBotApi
) -> None:
    """Every defence has its control: the same button on its own message does act, on its agent."""
    their_hold = _hold(attack, lab, OTHER, "boton")
    my_hold = _hold(attack, lab, MAIN, "boton")
    theirs, mine = notice_of(fake, OTHER, their_hold), notice_of(fake, MAIN, my_hold)

    # What must do nothing: a button moved to the other agent's message, one written by hand with
    # the agent inside, an order with a made-up agent or a path, and orders that do not say which.
    moved_at = time.monotonic()
    fake.push_callback(dict(buttons(theirs))["Aprobar"], mine.message_id)
    answered(fake, "no es de este mensaje", moved_at)
    forged_at = time.monotonic()
    fake.push_callback(f"approve:{SLUG}:{their_hold}", theirs.message_id)
    answered(fake, "ya no vale", forged_at)
    nobody = reply_to(fake, "/pausar nadie", "no existe en esta instalación")
    a_path = reply_to(fake, "/seguir ../revisor", "no existe en esta instalación")
    asked = reply_to(fake, "/pausar", "todavía no se ha congelado ninguno")
    refused = reply_to(fake, "/seguir", "no se ha reanudado ninguno")
    nothing_yet = (
        not said_in(lab.events(OTHER, "approved"), their_hold)
        and not said_in(lab.events(MAIN, "approved"), my_hold)
        and not paused(OTHER)
        and not paused(MAIN)
        and "../revisor" not in a_path.params["text"]
        and "..∕revisor" not in a_path.params["text"]  # as ``inert`` would show it
        and "nadie" not in nobody.params["text"]
        and MAIN.slug in refused.params["text"]
    )

    # Its own button, on its own message: that agent's gate, and only that one's.
    answered(fake, "Aprobando", press(fake, theirs, "Aprobar"))
    wait(
        lambda: said_in(lab.events(OTHER, "approved"), their_hold),
        SEEN_TIMEOUT,
        "the neighbour's yes",
        lab.diagnosis,
    )
    (approved,) = said_in(lab.events(OTHER, "approved"), their_hold)
    still_mine = not said_in(lab.events(MAIN, "approved"), my_hold)
    press(fake, mine, "Rechazar")
    wait(
        lambda: said_in(lab.events(MAIN, "rejected"), my_hold),
        SEEN_TIMEOUT,
        "the main agent's no",
        lab.diagnosis,
    )
    crossed = said_in(lab.events(MAIN), their_hold) + said_in(lab.events(OTHER), my_hold)
    attack.check(
        "held",
        nothing_yet and still_mine and approved["details"]["by"] == "telegram" and crossed == [],
        f"un botón movido al mensaje del otro, uno escrito a mano con el agente dentro, un agente "
        f"inventado, una ruta y las órdenes sin agente no sueltan ni congelan nada; el «Aprobar» "
        f"de {their_hold} suelta solo lo del vecino, y {my_hold} sigue abierta hasta su «Rechazar»",
    )

    # Freezing one, by its name and by the button of the question.
    frozen = reply_to(fake, f"/pausar {SLUG}", "congelado")
    wait(lambda: paused(OTHER), SEEN_TIMEOUT, "the neighbour frozen", lab.diagnosis)
    only_it = not paused(MAIN)
    press(fake, asked, f"Pausar {MAIN.slug}")
    wait(lambda: paused(MAIN), SEEN_TIMEOUT, "the main agent frozen", lab.diagnosis)
    # With both frozen, the orders that do not say which, or say nobody, let neither go.
    reply_to(fake, "/seguir", "no se ha reanudado ninguno")
    reply_to(fake, "/seguir ../revisor", "no existe en esta instalación")
    reply_to(fake, "/seguir nadie", "no existe en esta instalación")
    both_still = paused(OTHER) and paused(MAIN)
    reply_to(fake, f"/seguir {SLUG}", "donde estaba")
    wait(lambda: not paused(OTHER), SEEN_TIMEOUT, "the neighbour thawed", lab.diagnosis)
    thawed_only_it = paused(MAIN)
    reply_to(fake, f"/seguir {MAIN.slug}", "donde estaba")
    wait(lambda: not paused(MAIN), SEEN_TIMEOUT, "the main agent thawed", lab.diagnosis)

    # An alert of the neighbour, with its buttons back: its rewind is its own.
    tag = secrets.token_hex(4)
    kept = f"{CONTAINER_WORK}/vuelve-{tag}"
    before = set(lab.snapshots(OTHER))
    made = f"mkdir {kept} && for n in $(seq {WRECKED}); do echo x > {kept}/f$n; done"
    assert lab.in_agent(OTHER, made).returncode == 0
    wait(
        lambda: bool(set(lab.snapshots(OTHER)) - before),
        SEEN_TIMEOUT,
        "a snapshot with the files",
        lab.diagnosis,
    )
    # Past the watcher's window, or it would be a delete of something just made (`transient`).
    time.sleep(TRANSIENT_WINDOW)
    main_rewinds = len(lab.events(MAIN, "rewind_requested"))
    main_id = sh("docker", "inspect", "--format", "{{.Id}}", MAIN.container).stdout.strip()
    started = time.monotonic()
    assert lab.in_agent(OTHER, f"rm -rf {kept}").returncode == 0  # mass-delete-severe: risk 3
    alert = said_after(fake, f"{SLUG}: Riesgo máximo", started, 60)
    labels = [label for label, _ in buttons(alert)]
    press_at = press(fake, alert, "Rebobinar")
    question = said_after(fake, "¿Rebobinar?", press_at)
    press_at = press(fake, question, "Sí, rebobinar")
    done = said_after(fake, "Rebobinado", press_at, REWIND_TIMEOUT)
    wait(lambda: lab.running(OTHER), SEEN_TIMEOUT, "the neighbour back", lab.diagnosis)
    seen = lab.in_agent(OTHER, f"ls {kept}/f1 {kept}/f{WRECKED}")
    requested = lab.events(OTHER, "rewind_requested")[-1]
    same_main = sh("docker", "inspect", "--format", "{{.Id}}", MAIN.container).stdout.strip()
    attack.check(
        "stopped",
        only_it
        and both_still
        and thawed_only_it
        and frozen.params["text"].startswith(f"Agente {SLUG}:\n")
        and main_id == same_main
        and len(lab.events(MAIN, "rewind_requested")) == main_rewinds,
        f"/pausar {SLUG} congela solo al vecino; con los dos congelados, /seguir sin decir cuál, "
        f"una ruta o un agente inventado no sueltan a ninguno, y /seguir {SLUG} solo lo reanuda a "
        "él; cada mensaje dice de quién es, y su rebobinado no toca al principal",
    )
    attack.check(
        "recoverable",
        labels == ["Pausar", "Rebobinar"]
        and question.params["text"].startswith(f"Agente {SLUG}:\n")
        and done.params["text"].startswith(f"Agente {SLUG}:\n")
        and seen.returncode == 0,
        f"el aviso del vecino vuelve a tener {labels}, y «Rebobinar» le devuelve su carpeta: "
        f"{seen.stdout!r}",
    )
    ignored = lab.events(MAIN, "telegram_ignored")
    reasons = {event["details"]["reason"] for event in ignored}
    attack.check(
        "recorded",
        {"wrong_message", "unknown_button", "unknown_agent"} <= reasons
        and "revisor" not in json.dumps(ignored)
        and "nadie" not in json.dumps(ignored)
        and "telegram (uid" in json.dumps(requested)
        and lab.verify(OTHER)["ok"]
        and lab.verify(MAIN)["ok"],
        f"lo rechazado queda como telegram_ignored ({sorted(reasons)}), sin lo que decía; "
        f"el rebobinado, en la caja del vecino, pedido por Telegram: {requested['details']}",
    )
