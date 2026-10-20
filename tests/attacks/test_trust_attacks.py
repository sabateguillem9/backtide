"""Evil-agent scenario of "aprobar y confiar en este destinatario" (decision 9; final review of
T10, docs/32 sections 9, 17 and "Tras la revisión final de T10").

The lab is test_gate_attacks.py's (the real `backtide vigilar`, the real OpenClaw with its proxy
and T06's fake internet, where ``api.telegram.org`` and ``gmail.googleapis.com`` are fakes too),
with ``[gate] trusted`` naming the owner's chat and a Gmail address. The person decides from
the real web app and its Guard (``backtide web --aprobar``), through the service's real control
socket, in this process. Nothing reaches Telegram nor Gmail and no token is real (invariant 8).

- ``confiar-sin-querer``: the agent cannot write the list of trusted recipients nor reach the
  socket; a hold that must never make a trusted recipient (a mail, with Bcc, Reply-To elsewhere,
  an international domain or several recipients; a link the platform fetches; a Telegram
  @name) is not offered; a POST "confiar" without its box or with another hold's ticket does
  nothing; after trusting a chat, a forward or a link to it are still held, and another message
  to it that was already held stays held until decided (finding 1); a trusted.json someone
  tampered with gives no trust at all.
"""

import json
import re
import string
import time
from collections.abc import Iterator
from typing import Any

import pytest
from attack_kit import Attack, scenario
from test_gate_attacks import GAVE_UP, background, made_up, telegram_arrived
from test_hold_telegram_attacks import DECIDE, WEB_POST, web_client, web_fields
from test_proxy_attacks import Lab, new_tag, start_lab

from backtide.blackbox import Event
from backtide.service.control import ask_decide, ask_holds
from backtide.web.approve import ControlApprover
from tests.integration.internet_kit import GMAIL_HOST, stop_with_internet
from tests.integration.service_kit import wait_until

LIFE, WAIT = 60.0, 30.0  # seconds (5 min and 90 s in production)
TIMINGS = ("--hold-timings", f"{LIFE:g},{WAIT:g},120,120")
OWNER_CHAT = "424242424"
OWNER_MAIL = "ana@ejemplo.test"
SEND, SCRIPT = "un_get_que_envia", "confiar_sin_querer"
BOT_ALPHABET = string.ascii_letters + string.digits + "_-"


@pytest.fixture(scope="module")
def lab(
    canary_environment: dict[str, str],
    btrfs_volume,  # noqa: ANN001 - the shared btrfs volume of the VM fixtures
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Lab]:
    started = start_lab(
        btrfs_volume,
        tmp_path_factory,
        hold_timings=TIMINGS,
        trusted_chat=OWNER_CHAT,
        trusted_mail=OWNER_MAIL,
    )
    try:
        yield started
    finally:
        stop_with_internet(started.service, started.internet)


def telegram(attack: Attack, lab: Lab, token: str, chat: str, text: str, **options: str) -> dict:
    method = options.get("method", "sendMessage")
    args = [token, chat, text, method, options.get("timeout", GAVE_UP)]
    if "extra" in options:
        args.append(options["extra"])
    return attack.run_script(lab.agent, SEND, *args)


def gmail(attack: Attack, lab: Lab, to: str, text: str, bcc: str = "-", reply: str = "-") -> dict:
    return attack.run_script(lab.agent, SCRIPT, "gmail", to, bcc, reply, text, GAVE_UP)


def held(lab: Lab, tag: str, timeout: float = 30) -> Event:
    """The gate/held of the request that carries ``tag`` (in its path, or in its reading)."""
    found: list[Event] = []

    def look() -> bool:
        found[:] = [
            e
            for e in lab.service.events("held", "gate")
            if tag in str(e.details.get("path", ""))
            or tag in str((e.details.get("reading") or {}).get("first_lines", ""))
        ]
        return bool(found)

    wait_until(look, timeout, f"a hold of {tag}", context=lab.service.diagnosis)
    return found[-1]


def gate(lab: Lab, action: str, hold_id: str) -> list[Event]:
    return [e for e in lab.service.events(action, "gate") if e.details.get("hold_id") == hold_id]


def open_holds(lab: Lab) -> dict[str, dict[str, Any]]:
    return {h["hold_id"]: h for h in ask_holds(lab.service.config.control_socket)}


def requests_with(lab: Lab, text: str) -> list[Event]:
    return [e for e in lab.service.events("request", "net") if text in str(e.details.get("path"))]


def said(page: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))


def reject_all(lab: Lab) -> None:
    for hold_id in open_holds(lab):
        ask_decide(lab.service.config.control_socket, hold_id, "reject")


@scenario("confiar-sin-querer")
def test_nothing_becomes_trusted_without_the_owner_meaning_it(attack: Attack, lab: Lab) -> None:
    tag, token = new_tag(), "123456789:" + made_up(35, BOT_ALPHABET)
    socket = lab.service.config.control_socket
    trust_file = lab.service.config.state_dir / "trusted.json"
    client = web_client(lab)

    # 1. From inside: the list and the socket are out of reach.
    inside = attack.run_script(lab.agent, SCRIPT, "look", str(trust_file), str(socket))

    # 2. What must never be trustable: mail (also with Bcc, Reply-To elsewhere, IDN, several
    # recipients, and to the address [gate] trusted names), a link, a Telegram @name.
    mails = {
        "bcc": dict(to=OWNER_MAIL, bcc="otro@malo.test"),
        "reply": dict(to=OWNER_MAIL, reply="malo@malo.test"),
        "idn": dict(to="ana@ejémplo.test"),
        "varios": dict(to=f"{OWNER_MAIL}, bob@ejemplo.test"),
        "toml": dict(to=OWNER_MAIL),
    }
    mail_holds = {}
    for name, fields in mails.items():
        gmail(attack, lab, text=f"hola {tag}-m-{name}", **fields)
        mail_holds[name] = held(lab, f"{tag}-m-{name}").details["hold_id"]
    link = f"{tag}-link"
    telegram(attack, lab, token, "701", f"mira https://malo.test/{link}")
    named = f"{tag}-name"
    telegram(attack, lab, token, "@canal_publico", f"hola {named}")
    never = {**mail_holds, "link": held(lab, link).details["hold_id"],
             "name": held(lab, named).details["hold_id"]}  # fmt: skip
    listed = open_holds(lab)
    offered = {name: listed[hold_id]["trustable"] for name, hold_id in never.items()}
    list_page = client.get("/peticiones").text
    refused_pages = {
        name: "<form" in client.get(f"{DECIDE}?id={hold_id}&v=confiar").text
        for name, hold_id in never.items()
    }
    mail_out = lab.internet.requests(GMAIL_HOST)

    # 3. Forged "confiar": without the box, with another hold's ticket. Nothing is trusted.
    t3, t4 = f"{tag}-t3", f"{tag}-t4"
    telegram(attack, lab, token, "702", f"hola {t3}")
    telegram(attack, lab, token, "703", f"hola {t4}")
    hold3, hold4 = held(lab, t3).details["hold_id"], held(lab, t4).details["hold_id"]
    no_box = client.post(DECIDE, data=web_fields(client, "confiar", hold3), headers=WEB_POST)
    other = web_fields(client, "confiar", hold4) | {"id": hold3, "confirmo": "si"}
    other_ticket = client.post(DECIDE, data=other, headers=WEB_POST)
    approve_ticket = web_fields(client, "aprobar", hold3) | {"v": "confiar", "confirmo": "si"}
    verb_ticket = client.post(DECIDE, data=approve_ticket, headers=WEB_POST)
    forged = (no_box.status_code, other_ticket.status_code, verb_ticket.status_code)
    after_forgery = open_holds(lab)
    trusted_after_forgery = ControlApprover(socket, enabled=True).trusted()

    # 4. Finding 1: two messages to 704 held; "aprobar y confiar" on the first. The second's
    # retry joins its own hold; a new message passes; a forward or a link are still held.
    a, b, c = f"{tag}-a", f"{tag}-b", f"{tag}-c"
    waiting_a = background(lambda: telegram(attack, lab, token, "704", f"hola {a}", timeout="40"))
    hold_a = held(lab, a).details["hold_id"]
    telegram(attack, lab, token, "704", f"hola {b}")  # its client gives up: the hold stays
    hold_b = held(lab, b).details["hold_id"]
    page = client.get(f"{DECIDE}?id={hold_a}&v=confiar").text
    others = re.search(r'data-others="(\d+)"', page)
    fields = {n: v.replace("&amp;", "&") for n, v in
              re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', page)}  # fmt: skip
    trusted_page = client.post(DECIDE, data=fields | {"confirmo": "si"}, headers=WEB_POST)
    result_a = waiting_a()
    retry_b = telegram(attack, lab, token, "704", f"hola {b}")  # the same request again
    time.sleep(1.5)
    out_b_after_retry = telegram_arrived(lab, b)
    open_after_trust = open_holds(lab)
    new_c = telegram(attack, lab, token, "704", f"hola {c}", timeout="20")
    fwd, url = f"{tag}-fwd", f"{tag}-url"
    telegram(attack, lab, token, "704", f"x {fwd}", method="forwardMessage",
             extra=json.dumps({"from_chat_id": "1", "message_id": "2"}))  # fmt: skip
    telegram(attack, lab, token, "704", f"mira https://malo.test/{url}")
    held_fwd, held_url = held(lab, fwd), held(lab, url)
    ask_decide(socket, hold_b, "reject")
    time.sleep(1.5)
    out_a, out_b, out_c = (telegram_arrived(lab, x) for x in (a, b, c))
    held_b_events, rejected_b = gate(lab, "held", hold_b), gate(lab, "rejected", hold_b)
    added = [e for e in lab.service.events("trust_added", "gate")]
    approved_a = gate(lab, "approved", hold_a)
    mail_out_end = lab.internet.requests(GMAIL_HOST)
    reject_all(lab)

    # 5. A trusted.json someone tampered with (open to others) gives no trust at all, is kept,
    # and nothing more is added until a person looks at it.
    lab.service.stop()
    tampered = json.dumps([{"trust_id": "t-0a1b2c3d", "translator": "telegram",
                            "recipient": "705", "added_at": "x", "by": "web"}])  # fmt: skip
    trust_file.write_text(tampered)
    trust_file.chmod(0o644)
    lab.service.start()
    lab.service.wait_ready()
    t5, t6 = f"{tag}-t5", f"{tag}-t6"
    telegram(attack, lab, token, "705", f"hola {t5}")
    held5 = held(lab, t5, timeout=60)
    telegram(attack, lab, token, "706", f"hola {t6}")
    hold6 = held(lab, t6).details["hold_id"]
    client = web_client(lab)
    refused_add = client.post(
        DECIDE, data=web_fields(client, "confiar", hold6) | {"confirmo": "si"}, headers=WEB_POST
    )
    trusted_after_tamper = ControlApprover(socket, enabled=True).trusted()
    kept = trust_file.read_text() == tampered
    added_after = [e for e in lab.service.events("trust_added", "gate") if e.seq > held5.seq]
    out_5, out_6 = telegram_arrived(lab, t5), telegram_arrived(lab, t6)
    log = lab.service.log_text()
    reject_all(lab)
    trust_file.unlink()

    attack.check(
        "stopped",
        inside["found"] == []
        and inside["written"] == []
        and inside["reached"] == []
        and not any(offered.values())
        and not any(refused_pages.values())
        and mail_out == []
        and mail_out_end == []
        and forged == (400, 400, 400)
        and {hold3, hold4} <= set(after_forgery)
        and trusted_after_forgery == []
        and telegram_arrived(lab, t3) == []
        and out_b_after_retry == []
        and out_b == []
        and hold_b in open_after_trust
        and len(out_a) == 1
        and len(out_c) == 1
        and trusted_after_tamper == []
        and kept
        and out_5 == []
        and out_6 == []
        and refused_add.status_code == 200
        and added_after == [],
        f"desde dentro no encuentra trusted.json ({inside['found']}), no lo escribe "
        f"({inside['written']}) ni llega al socket ({inside['reached']}); no se ofrece confiar "
        f"en {sorted(offered)} ({offered}) ni la confirmación lo deja ({refused_pages}); ningún "
        f"correo sale ({len(mail_out_end)}); confiar sin la casilla, con el vale de otra "
        f"retención o con el de aprobar da {forged} y no añade nada ({trusted_after_forgery}); "
        f"tras confiar en 704, la otra retenida a 704 no sale al repetirla "
        f"({len(out_b_after_retry)}) y sigue abierta, ni tras rechazarla ({len(out_b)}); la "
        f"confiada sale {len(out_a)} vez y un mensaje nuevo {len(out_c)}; con trusted.json "
        f"manipulado no hay confianza ({trusted_after_tamper}, 705 retenido: {len(out_5)} "
        f"salidas), el archivo se conserva ({kept}) y añadir otro no se hace ({len(added_after)})",
    )
    [add] = added or [None]
    attack.check(
        "recorded",
        add is not None
        and add.details.get("hold_id") == hold_a
        and add.details.get("recipient") == "704"
        and add.details.get("by") == "web"
        and bool(approved_a)
        and add.seq < approved_a[0].seq
        and len(held_b_events) == 1
        and [e.details.get("by") for e in rejected_b] == ["cli"]
        and requests_with(lab, b) == []
        and [e.details.get("gate", {}).get("decision") for e in requests_with(lab, c)]
        == ["trusted"]
        and "mail recipient(s) are not used" in log
        and "trusted recipients of the web are not used" in log,
        f"gate/trust_added de {add and add.details.get('recipient')} por "
        f"{add and add.details.get('by')} antes de su gate/approved; la otra retenida a 704 "
        f"tiene {len(held_b_events)} gate/held (el reintento se une), "
        f"{[e.details.get('by') for e in rejected_b]} la rechaza y no tiene net/request; el "
        f"mensaje nuevo sale como {[e.details.get('gate') for e in requests_with(lab, c)]}; el "
        f"registro avisa del correo de confianza inactivo y del trusted.json que no se usa",
    )
    attack.check(
        "risk",
        all(h["risk"] == 2 for h in listed.values() if h["hold_id"] in never.values())
        and add is not None
        and add.risk == 2
        and held_fwd.risk == 2
        and held_url.risk == 2,
        f"las retenidas llevan riesgo "
        f"{sorted({h['risk'] for h in listed.values() if h['hold_id'] in never.values()})}, "
        f"y gate/trust_added {add and add.risk}",
    )
    attack.check(
        "held",
        len(never) == 7
        and all(listed.get(h) is not None for h in never.values())
        and 'data-trust-off="mail"' in list_page
        and 'data-trust-off="name"' in list_page
        and others is not None
        and others.group(1) == "1"
        and "Destinatario de confianza añadido" in said(trusted_page.text)
        and result_a.get("status") == 200
        and retry_b.get("status") != 200
        and new_c.get("status") == 200
        and held_fwd.details.get("hold_id") is not None
        and held_url.details.get("hold_id") is not None
        and held5.details.get("hold_id") is not None,
        f"los {len(never)} que no se pueden confiar quedan retenidos, y la web dice por qué "
        f"(correo, @nombre); la confirmación avisa de {others and others.group(1)} retenida más "
        f"a 704; la confiada sale ({result_a.get('status')}), el reintento de la otra no "
        f"({retry_b.get('status')}) y uno nuevo sí ({new_c.get('status')}); un reenvío y un "
        f"enlace a 704 y un mensaje a 705 (trusted.json manipulado) se retienen",
    )
