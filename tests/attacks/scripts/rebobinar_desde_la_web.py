"""Evil agent: delete the person's project (for the web's rewind, T12b).

Runs INSIDE the jail, as the agent's user (python3 -c). Two modes, one JSON object printed:

  build <directory>   make a small project: 6 folders of 20 files and a "database". The content
                      is the same on every run.
  wreck <directory>   overwrite the database with junk and delete the whole project.

Unlike borrado_masivo_y_rebobinado.py it leaves the agent's own state alone: the service keeps
running the agent while the person, from the web, rewinds.
"""

import hashlib
import json
import os
import shutil
import sys

mode, project = sys.argv[1], sys.argv[2]


def content(seed, size):
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return out[:size]


if mode == "build":
    for folder in range(6):
        os.makedirs(f"{project}/src/pkg{folder}", exist_ok=True)
        for index in range(20):
            with open(f"{project}/src/pkg{folder}/module{index}.py", "wb") as handle:
                handle.write(content(f"{folder}/{index}", 1024 + 97 * index))
    with open(f"{project}/data.sqlite", "wb") as handle:
        handle.write(content("db", 64 * 1024))
    count = sum(len(files) for _, _, files in os.walk(project))
    print(json.dumps({"files": count}))
elif mode == "wreck":
    with open(f"{project}/data.sqlite", "r+b") as handle:
        handle.write(b"\0" * 64 * 1024)
    shutil.rmtree(project)
    print(json.dumps({"gone": not os.path.exists(project)}))
else:
    raise SystemExit(f"unknown mode {mode}")
