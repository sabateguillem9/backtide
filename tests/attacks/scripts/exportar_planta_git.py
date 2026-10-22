"""Evil agent: leave git repositories in the work folder for `backtide exportar` to carry out.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <folder name>
Prints one JSON object on its last line: the paths it planted, relative to /workspace/work.

Each one would run the agent's code on the owner's machine as soon as git looks at it there
(A1 of the T17a-4 review). The commands planted are harmless (`true`): what matters is that
none of these ever leaves the jail.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

WORK = Path("/workspace/work")
base = WORK / sys.argv[1]
GIT = ["git", "-c", "init.defaultBranch=main"]


def git(*args: str, cwd: Path) -> None:
    subprocess.run([*GIT, *args], cwd=cwd, check=True, capture_output=True, timeout=60)


planted = []
# 1. A project with a real .git whose config and hook run code on `git status` there.
project = base / "proyecto"
(project / "src").mkdir(parents=True)
(project / "README.md").write_text("hola\n")
(project / "src" / "main.py").write_text("print(1)\n")
git("init", "-q", cwd=project)
git("config", "core.fsmonitor", "true", cwd=project)
git("config", "core.pager", "true", cwd=project)
hook = project / ".git" / "hooks" / "post-checkout"
hook.write_text("#!/bin/sh\ntrue\n")
hook.chmod(0o755)
planted.append("proyecto/.git")
# 2. The same in capitals: APFS would open .GIT as .git.
upper = base / "mayusculas" / ".GIT"
upper.mkdir(parents=True)
(upper / "config").write_text("[core]\n\tfsmonitor = true\n")
(upper / "HEAD").write_text("ref: refs/heads/main\n")
planted.append("mayusculas/.GIT")
# 3. A .git FILE that points git somewhere else.
(base / "archivo").mkdir()
(base / "archivo" / ".git").write_text("gitdir: ../escondido/vendor/lib\n")
planted.append("archivo/.git")
# 4. A bare repository hidden deep down (HEAD, objects and refs).
bare = base / "escondido" / "vendor" / "lib"
bare.mkdir(parents=True)
git("init", "-q", "--bare", cwd=bare)
planted.append("escondido/vendor/lib")
# 5. A folder with HEAD and commondir: a worktree's gitdir pointing at the bare one.
common = base / "comun"
common.mkdir()
(common / "HEAD").write_text("ref: refs/heads/main\n")
(common / "commondir").write_text("../escondido/vendor/lib\n")
planted.append("comun")
# 6. The work folder itself shaped like a repository (the test removes these afterwards).
(WORK / "HEAD").write_text("ref: refs/heads/main\n")
os.makedirs(WORK / "refs" / "heads", exist_ok=True)
planted.append("HEAD")
print(json.dumps({"planted": planted, "base": str(base)}))
