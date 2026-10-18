"""Evil agent: try to run a program without the sensor seeing it.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <workdir> <marker>.
Prints one JSON object on its last line.

Each technique runs a copy of ``/bin/true`` under a name of its own, so the test can find that
exec by its binary and nothing else can stand in for it:
- a renamed binary (``rename-<marker>``);
- ``os.execv`` from a child Python (``execv-<marker>``), to replace a process image in place;
- a file name that is not UTF-8 (``utf8-\\xff-<marker>``, bytes on the disk);
- arguments with a byte that is not UTF-8, a newline and a terminal escape (``\\x1b[2J``, which
  clears a screen), to forge or wipe what a person reads (``ctrl-<marker>``);
- a program that is no file at all: ``memfd_create`` and ``execveat(fd, "", AT_EMPTY_PATH)``
  (``os.execve`` with a descriptor, which glibc's fexecve turns into exactly that). The kernel
  names it ``/dev/fd/<n>``: the exec is recorded, its memfd name is not;
- ``exec -a <fake name>`` in bash, so ``argv[0]`` lies about the program (``execa-<marker>``);
- a huge argv of control characters (``bloat-<marker>``): the kernel caps one exec at about
  2 MiB of arguments and each one at 128 KiB (MAX_ARG_STRLEN), and Tetragon keeps ~327 KiB, so
  ~600 KiB makes Tetragon drop the arguments (``arguments_lost``) while the binary is still
  attributed from the head of the line;
- a shell built-in (``echo``), which does NOT exec a program, so it leaves no exec of its own:
  the test checks there is none and says so, instead of pretending it was hidden.
"""

import json
import os
import shutil
import subprocess
import sys

workdir, marker = sys.argv[1], sys.argv[2]
os.makedirs(workdir, exist_ok=True)
done: dict[str, object] = {}
TRUE = "/bin/true"


def copy_true(name: str | bytes) -> str | bytes:
    if isinstance(name, bytes):
        path = os.fsencode(workdir) + b"/" + name
    else:
        path = os.path.join(workdir, name)
    shutil.copy(TRUE, path)
    os.chmod(path, 0o755)  # noqa: S103 - the agent makes its copy runnable
    return path


def run(name: str, argv: list) -> None:
    try:
        done[name] = subprocess.run(argv, capture_output=True, timeout=60).returncode
    except (OSError, subprocess.SubprocessError) as error:
        done[name] = type(error).__name__


# 1. A renamed binary.
run("renamed", [copy_true(f"rename-{marker}"), marker])

# 2. os.execv in a child: the child's image is replaced by the copied binary.
execv_path = copy_true(f"execv-{marker}")
child = "import os,sys; os.execv(sys.argv[1], [sys.argv[1], sys.argv[2]])"
run("execv", [sys.executable, "-c", child, execv_path, marker])

# 3. A file name that is not UTF-8.
utf8_path = copy_true(b"utf8-\xff-" + marker.encode())
run("utf8_name", [utf8_path, marker])

# 4. Arguments that are not UTF-8, with a newline and a terminal escape.
ctrl_path = copy_true(f"ctrl-{marker}")
run("controls", [ctrl_path, b"bad\xffbyte", f"one\nfake-line-{marker}", "\x1b[2J\x1b[H", marker])

# 5. memfd_create + execveat(AT_EMPTY_PATH): a program with no path on any disk.
try:
    fd = os.memfd_create(f"memfd-{marker}", 0)
    with open(TRUE, "rb") as source:
        os.write(fd, source.read())
    pid = os.fork()
    if pid == 0:
        try:
            os.execve(fd, [f"memfd-{marker}", marker], dict(os.environ))  # noqa: S606 - fexecve
        finally:
            os._exit(127)
    _, status = os.waitpid(pid, 0)
    done["memfd"] = os.waitstatus_to_exitcode(status)
    os.close(fd)
except OSError as error:
    done["memfd"] = f"{type(error).__name__}: {error}"[:200]

# 6. exec -a: argv[0] is a lie, the binary is not.
execa_path = copy_true(f"execa-{marker}")
if shutil.which("bash"):
    run("exec_a", ["bash", "-c", f'exec -a "sshd-{marker}" "$0" "$1"', execa_path, marker])
else:  # the same thing without bash: argv[0] chosen by the caller
    run(
        "exec_a",
        [sys.executable, "-c", child.replace("[sys.argv[1], ", "['sshd', "), execa_path, marker],
    )

# 7. A huge argv of control characters (no NUL: it cannot go in argv). The blob goes in 100 KB
# chunks (under MAX_ARG_STRLEN); ~600 KB in all is well past the ~327 KiB Tetragon keeps.
bloat_path = copy_true(f"bloat-{marker}")
chunk = ("\x01\x02\x03\x04\x05\x06\x07" * 15000)[:100000]
chunks = [chunk] * 6
run("bloat", [bloat_path, *chunks])
done["bloat_bytes"] = sum(len(c) for c in chunks)

# 8. A shell built-in: echo runs no program, so there is no exec to see.
run("builtin_echo", ["sh", "-c", f"echo esconder-builtin-{marker}; :"])

print(json.dumps({"workdir": workdir, "marker": marker, "done": done}))
