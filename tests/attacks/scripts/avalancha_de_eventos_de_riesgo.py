"""Evil agent: thousands of events of risk 3 in a row, to drown the analyzer's answer.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> build|storm <directory>.
Prints one JSON object on its last line.

``build``: 1,500 small files, which backtide will snapshot.
``storm``: three rounds of "delete every file, make them again": 4,500 deletes in about twenty
seconds. Each round is far past the 100 deletes a minute that the default rules rate as risk 3,
so the black box gets hundreds of events of risk 3 (and the watcher folds the rest into
summaries that carry the delete counts), and the analyzer must answer them with one evidence
snapshot and a few alerts, not one per event.
"""

import json
import os
import sys
import time

mode, directory = sys.argv[1], sys.argv[2]
FILES = 1500
ROUNDS = 3
PAUSE = 4.0  # between rounds: the watcher's dumper (2 s) writes what it saw


def make() -> None:
    os.makedirs(directory, exist_ok=True)
    for index in range(FILES):
        with open(os.path.join(directory, f"f{index}"), "wb") as handle:
            handle.write(b"x")


outcome: dict[str, object] = {"mode": mode}
if mode == "build":
    make()
    outcome["files"] = FILES
else:
    deleted = 0
    began = time.monotonic()
    for _ in range(ROUNDS):
        for name in os.listdir(directory):
            os.unlink(os.path.join(directory, name))
            deleted += 1
        time.sleep(PAUSE)
        make()
        time.sleep(PAUSE)
    outcome.update(deleted=deleted, seconds=round(time.monotonic() - began, 1))
print(json.dumps(outcome))
