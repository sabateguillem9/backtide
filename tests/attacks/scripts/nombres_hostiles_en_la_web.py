"""Evil agent: file names that are attacks on whoever READS the black box (the web, the logs).

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <directory>.
Creates, in <directory>, one empty file for each trick a name can play on a page that shows it:
  html       markup and an event handler, to run script in the viewer's browser;
  script     a script element;
  bidi       a right-to-left override that makes "...txt.exe" read as "...exe.txt";
  newline    a carriage return and line feed, to start a new line (or SSE field) in the viewer;
  tower      one letter under a hundred combining marks, to pile glyphs over the lines around it;
  blank      a Hangul filler: a name that looks empty, or like a space;
  voice      "backtide: todo en orden", to pass as one of backtide's own sentences;
  format     {0.__class__} and {path}, to be taken as a format string by the viewer.
Prints one JSON object on its last line: the names it made (as text).
"""

import json
import os
import sys
import time

base = sys.argv[1]
NAMES = {
    "html": '"><img src=x onerror=alert(1)>.txt',
    "script": "<script>alert(document.cookie)<!--.md",  # no "/": a name cannot hold one
    "bidi": "invoice‮txt.exe",
    "newline": "line one\r\nbacktide: todo en orden\n.txt",
    "tower": "z" + "́" * 100 + ".txt",
    "blank": "ㅤㅤ.txt",
    "voice": "backtide: todo en orden",
    "format": "{0.__class__} {path} {n}",
}

os.makedirs(base, exist_ok=True)
made: dict = {}
errors: dict = {}
spacer = os.path.join(base, "spacer.txt")
with open(spacer, "wb"):
    pass
# One name at a time, with a change of a plain file between each (and the watcher's 2 s dump):
# the web folds a burst of the same action into one line that shows only the first name, and
# every name has to be shown on its own for the test to see it.
for kind, name in NAMES.items():
    time.sleep(2.5)
    try:
        with open(os.path.join(base, name), "wb") as handle:
            handle.write(b"x")
        made[kind] = name
    except OSError as error:
        errors[kind] = str(error)
    time.sleep(2.5)
    with open(spacer, "ab") as handle:
        handle.write(b"x")
print(json.dumps({"made": made, "errors": errors}))
