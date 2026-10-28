"""The fake Telegram Bot API for a clean VM's lab (D27): never Telegram's real API.

    sudo python3 -I tests/install/telegram_lab.py TOKEN_FILE OUT_DIR

Serves tests/telegram_fake.py's fake on 127.0.0.1 (a free port) for the made-up token in
TOKEN_FILE (`instalar_lab.sh token`), writes its address to OUT_DIR/base and, every two seconds,
what reached it to OUT_DIR/calls.json: each call's method, whether it came with that token, its
chat and the start of its text. Never the token itself, nor a call's path (which holds it). A
line ``<chat id> <text>`` in OUT_DIR/push is sent to the bot as a message from that chat. Runs
until it is stopped (systemd-run).
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # the copied source: tests/

from tests.telegram_fake import FakeBotApi  # noqa: E402


def main() -> None:
    token = Path(sys.argv[1]).read_text().strip()
    out = Path(sys.argv[2])
    out.mkdir(mode=0o700, exist_ok=True)
    with FakeBotApi(token) as fake:
        (out / "base").write_text(fake.base + "\n")
        while True:
            push = out / "push"
            if push.exists():
                for line in push.read_text().splitlines():
                    chat, _, text = line.partition(" ")
                    fake.push_message(text, chat_id=int(chat))
                push.unlink()
            seen = [
                {"method": call.method, "token_ok": call.path.startswith(f"/bot{token}/"),
                 "chat_id": call.params.get("chat_id"),
                 "text": str(call.params.get("text", ""))[:80]}
                for call in list(fake.calls)
            ]  # fmt: skip
            (out / "calls.json.tmp").write_text(json.dumps(seen))
            (out / "calls.json.tmp").replace(out / "calls.json")
            time.sleep(2)


if __name__ == "__main__":
    main()
