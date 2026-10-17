"""The egress proxy's CA: made once per installation with the host's openssl, never replaced.

Design: docs/21-diseno-t06-proxy.md, section 3 (and T06-1, P2).

- RSA 3072, five years, ``CA:TRUE`` and ``keyCertSign`` (what mitmproxy needs), named
  ``backtide agent CA <installation id>``. openssl runs with a fixed argv and a config file of
  our own (never the system's), like the other CLIs of backtide: no shell, ``LC_ALL=C``, a
  timeout.
- The key is made in a private (0700) folder next to the state, never in a mounted one, and
  that folder is removed afterwards. It only ever lands in ``proxy-ca/mitmproxy-ca.pem`` (key,
  then certificate: mitmproxy's format), 0440 and group the proxy's: the proxy reads it through
  its read-only ``/ca``. Next to it, ``mitmproxy-dhparam.pem`` (RFC 7919 ffdhe3072): without
  it mitmproxy tries to write one into the read-only ``/ca`` and does not start.
- The CA is written once: the file is linked into place, which fails if one is already there,
  so an existing CA is never replaced. A broken one is refused, not mended: removing it is a
  person's decision (the agent then trusts a new CA, after it is created again).
- ``agent-ca/ca.pem`` is the certificate alone (0444), copied from the CA every time it differs:
  the agent sees it at ``/etc/backtide-ca``. A test and agent.py both refuse ``PRIVATE KEY``
  there (invariant 1).
- Both folders are mounted into a container, so each must hold exactly its files: anything
  else is refused (nothing of backtide may land there by mistake). Nothing here follows a
  symlink. The CA is never installed in the host's trust store.
"""

import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from backtide.jail.config import CA_CERT_FILE
from backtide.jail.docker import JailError, sanitize

PROGRAM = "openssl"
OPENSSL_TIMEOUT = 120.0  # RSA 3072 took 0.06-0.25 s in the VM (T06-1)
CA_BITS = 3072
CA_DAYS = 1826  # five years
DH_GROUP = "ffdhe3072"
CA_FILE = "mitmproxy-ca.pem"  # key, then certificate
DHPARAM_FILE = "mitmproxy-dhparam.pem"
PROXY_DIR_MODE = 0o750
PROXY_FILE_MODE = 0o440
AGENT_DIR_MODE = 0o755
AGENT_FILE_MODE = 0o444
MAX_PEM_BYTES = 64 * 1024
# openssl runs with this environment only. OPENSSL_CONF=/dev/null: the system's openssl.cnf is
# never read (``req`` gets our own with -config).
OPENSSL_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}
_WORK_PREFIXES = (".backtide-ca-", ".backtide-dh-")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NEW_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_INSTALL_ID_RE = re.compile(r"[a-z0-9-]{1,32}", re.ASCII)
_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n[A-Za-z0-9+/=\r\n]*-----END \1-----\r?\n?"
)


@dataclass(frozen=True)
class CaPaths:
    """Where the CA lives. ``proxy_dir`` (``proxy-ca/``) holds the key and the certificate, for
    the proxy only; ``agent_dir`` (``agent-ca/``) holds the certificate alone, for the agent.
    ``gid`` is the proxy's group, the only one that may read the key."""

    proxy_dir: Path
    agent_dir: Path
    gid: int

    def __post_init__(self) -> None:
        for label, path in (("proxy_dir", self.proxy_dir), ("agent_dir", self.agent_dir)):
            if not isinstance(path, Path) or not path.is_absolute() or "\0" in str(path):
                raise ValueError(f"{label} must be an absolute Path, got {path!r}")
        if self.proxy_dir.is_relative_to(self.agent_dir) or self.agent_dir.is_relative_to(
            self.proxy_dir
        ):
            raise ValueError("proxy_dir and agent_dir must not contain each other")
        if isinstance(self.gid, bool) or not isinstance(self.gid, int) or self.gid <= 0:
            raise ValueError(f"gid must be a positive integer (the proxy's), got {self.gid!r}")


def ca_config(install_id: str) -> str:
    """openssl's config for the CA: our own, so the system's openssl.cnf changes nothing."""
    if not isinstance(install_id, str) or not _INSTALL_ID_RE.fullmatch(install_id):
        raise ValueError(f"invalid installation id: {install_id!r}")
    return (
        "[req]\n"
        "distinguished_name = dn\n"
        "x509_extensions = v3_ca\n"
        "prompt = no\n"
        "[dn]\n"
        f"CN = backtide agent CA {install_id}\n"
        "[v3_ca]\n"
        # pathlen:0: it signs the proxy's leaf certificates, never another CA.
        "basicConstraints = critical,CA:TRUE,pathlen:0\n"
        "keyUsage = critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier = hash\n"
    )


def ca_argv(config_file: Path, key_file: Path, cert_file: Path) -> list[str]:
    """``openssl req`` that makes the CA's key (unencrypted: mitmproxy reads it as is) and its
    self-signed certificate."""
    return [
        "req", "-x509", "-new", "-config", str(config_file), "-newkey", f"rsa:{CA_BITS}",
        "-nodes", "-sha256", "-days", str(CA_DAYS), "-keyout", str(key_file),
        "-out", str(cert_file),
    ]  # fmt: skip


def dhparam_argv(out: Path) -> list[str]:
    return [
        "genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt", f"group:{DH_GROUP}",
        "-out", str(out),
    ]  # fmt: skip


def run_openssl(args: Sequence[str]) -> None:
    """Run ``openssl *args``; any failure raises JailError with its stderr (openssl never prints
    a key there). Called as ``ca.run_openssl`` so the unit tests can fake it."""
    argv = [PROGRAM, *args]
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT,
            env=OPENSSL_ENV,  # not ours: no OPENSSL_CONF, OPENSSL_MODULES or PATH of the caller
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise JailError(f"cannot run {shlex.join(argv)}: {e}") from e
    if result.returncode != 0:
        stderr = sanitize(result.stderr.strip())
        raise JailError(
            f"{shlex.join(argv)} failed with exit code {result.returncode}: {stderr}",
            returncode=result.returncode,
            stderr=stderr,
        )


def certificates_only(pem: bytes) -> bytes:
    """The CERTIFICATE blocks of ``pem``, nothing else: what the agent may see."""
    return b"".join(
        match.group(0).rstrip(b"\r\n") + b"\n"
        for match in _PEM_BLOCK_RE.finditer(pem)
        if match.group(1) == b"CERTIFICATE"
    )


def ensure_ca(paths: CaPaths, *, install_id: str | None = None) -> bool:
    """Make whatever is missing of the CA, the dhparam and the agent's certificate, and check
    what exists. Returns True if the CA itself was created now. Raises JailError (never
    replacing anything of the CA) when something cannot be trusted or made."""
    _remove_stale_work(paths.proxy_dir.parent)
    proxy_fd = _ensure_dir(paths.proxy_dir, PROXY_DIR_MODE, paths.gid)
    try:
        _clean_and_check(proxy_fd, paths.proxy_dir, {CA_FILE, DHPARAM_FILE})
        created = False
        if not _exists(proxy_fd, CA_FILE):
            key, cert = _make(paths.proxy_dir.parent, install_id or secrets.token_hex(4))
            created = _install_once(proxy_fd, paths.proxy_dir, CA_FILE, key + cert, paths.gid)
        ca_pem = _read_ca(proxy_fd, paths.proxy_dir / CA_FILE, paths.gid)
        if not _exists(proxy_fd, DHPARAM_FILE):
            dhparam = _make_dhparam(paths.proxy_dir.parent)
            _install_once(proxy_fd, paths.proxy_dir, DHPARAM_FILE, dhparam, paths.gid)
        _read_file(proxy_fd, paths.proxy_dir / DHPARAM_FILE, DHPARAM_FILE)
        os.fsync(proxy_fd)
    finally:
        os.close(proxy_fd)
    certificate = certificates_only(ca_pem)
    agent_fd = _ensure_dir(paths.agent_dir, AGENT_DIR_MODE, None)
    try:
        _clean_and_check(agent_fd, paths.agent_dir, {CA_CERT_FILE})
        current = _read_file(agent_fd, paths.agent_dir / CA_CERT_FILE, CA_CERT_FILE, missing=b"")
        if current != certificate:
            _replace(agent_fd, paths.agent_dir, CA_CERT_FILE, certificate)
    finally:
        os.close(agent_fd)
    return created


# Making the files


def _make(parent: Path, install_id: str) -> tuple[bytes, bytes]:
    """The CA's key and certificate, made by openssl in a private folder that is then removed."""
    config_text = ca_config(install_id)
    work = Path(tempfile.mkdtemp(prefix=_WORK_PREFIXES[0], dir=parent))  # 0700, ours
    try:
        config_file, key_file, cert_file = work / "ca.cnf", work / "ca.key", work / "ca.crt"
        config_file.write_text(config_text)
        run_openssl(ca_argv(config_file, key_file, cert_file))
        key, cert = key_file.read_bytes(), cert_file.read_bytes()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if _blocks(key, b"PRIVATE KEY") != 1 or _blocks(cert, b"CERTIFICATE") != 1:
        raise JailError("openssl did not write one key and one certificate for the CA")
    return key, cert


def _make_dhparam(parent: Path) -> bytes:
    work = Path(tempfile.mkdtemp(prefix=_WORK_PREFIXES[1], dir=parent))
    try:
        out = work / DHPARAM_FILE
        run_openssl(dhparam_argv(out))
        return out.read_bytes()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _remove_stale_work(parent: Path) -> None:
    """The private folders a killed run left (a key may be in one): removed, never followed."""
    try:
        fd = os.open(parent, _DIR_FLAGS)
    except OSError as e:
        raise JailError(f"cannot open {parent}: {e}") from e
    try:
        for name in os.listdir(fd):
            if not name.startswith(_WORK_PREFIXES):
                continue
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid():
                shutil.rmtree(name, dir_fd=fd)
    except OSError as e:
        raise JailError(f"cannot remove what a killed run left in {parent}: {e}") from e
    finally:
        os.close(fd)


def _install_once(dir_fd: int, folder: Path, name: str, content: bytes, gid: int) -> bool:
    """Write ``name`` once: a temporary file, then a hard link to the final name, which fails if
    it exists (it is then left as it is). Returns whether this call wrote it."""
    tmp = _tmp_name(name)
    _write_new(dir_fd, folder / tmp, tmp, content, PROXY_FILE_MODE, gid)
    try:
        os.link(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
        return True
    except FileExistsError:
        return False  # someone else made it meanwhile: it is checked like any existing one
    except OSError as e:
        raise JailError(f"cannot write {folder / name}: {e}") from e
    finally:
        _unlink(dir_fd, tmp)


def _replace(dir_fd: int, folder: Path, name: str, content: bytes) -> None:
    tmp = _tmp_name(name)
    _write_new(dir_fd, folder / tmp, tmp, content, AGENT_FILE_MODE, None)
    try:
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except OSError as e:
        _unlink(dir_fd, tmp)
        raise JailError(f"cannot write {folder / name}: {e}") from e


def _write_new(
    dir_fd: int, path: Path, name: str, content: bytes, mode: int, gid: int | None
) -> None:
    try:
        fd = os.open(name, _NEW_FLAGS, 0o600, dir_fd=dir_fd)
    except OSError as e:
        raise JailError(f"cannot create {path}: {e}") from e
    try:
        if gid is not None and os.fstat(fd).st_gid != gid:
            os.fchown(fd, -1, gid)
        os.fchmod(fd, mode)  # after the content's owner is right, and the umask is out of it
        view = memoryview(content)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    except OSError as e:
        os.close(fd)
        _unlink(dir_fd, name)
        raise JailError(f"cannot write {path}: {e}") from e
    os.close(fd)


# Checking what exists


def _ensure_dir(path: Path, mode: int, gid: int | None) -> int:
    """Open ``path`` as a directory (created if missing), ours, with ``mode`` and ``gid``."""
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        pass
    except OSError as e:
        raise JailError(f"cannot create {path}: {e}") from e
    try:
        fd = os.open(path, _DIR_FLAGS)
    except OSError as e:  # ELOOP: a symlink; ENOTDIR: a file
        raise JailError(f"{path} is not a directory (a symlink or a file?): {e}") from e
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid():
            raise JailError(f"{path} is owned by uid {st.st_uid}, not backtide's {os.geteuid()}")
        if gid is not None and st.st_gid != gid:
            os.fchown(fd, -1, gid)
        if stat.S_IMODE(st.st_mode) != mode:
            os.fchmod(fd, mode)
    except OSError as e:
        os.close(fd)
        raise JailError(f"cannot set the owner and mode of {path}: {e}") from e
    except BaseException:
        os.close(fd)
        raise
    return fd


def _clean_and_check(dir_fd: int, folder: Path, allowed: set[str]) -> None:
    """Remove our temporary files left by a crash; anything else but ``allowed`` is refused."""
    for name in allowed:
        _unlink(dir_fd, _tmp_name(name))
    strays = sorted(set(os.listdir(dir_fd)) - allowed)
    if strays:
        raise JailError(
            f"{folder} is mounted into a container and must hold only {sorted(allowed)}; "
            f"found {strays}: move them elsewhere"
        )


def _read_ca(dir_fd: int, path: Path, gid: int) -> bytes:
    content = _read_file(dir_fd, path, CA_FILE)
    if _blocks(content, b"PRIVATE KEY") != 1 or _blocks(content, b"CERTIFICATE") < 1:
        raise JailError(
            f"{path} is not one key and its certificate: remove it by hand to make a new CA "
            "(the agent then trusts the new one once both are created again)"
        )
    fd = os.open(CA_FILE, _READ_FLAGS, dir_fd=dir_fd)
    try:
        if os.fstat(fd).st_gid != gid:
            os.fchown(fd, -1, gid)
        if stat.S_IMODE(os.fstat(fd).st_mode) != PROXY_FILE_MODE:
            os.fchmod(fd, PROXY_FILE_MODE)
    except OSError as e:
        raise JailError(f"cannot set the owner and mode of {path}: {e}") from e
    finally:
        os.close(fd)
    return content


def _read_file(dir_fd: int, path: Path, name: str, *, missing: bytes | None = None) -> bytes:
    """A small regular file of ours that nobody else may write. ``missing``: what a missing
    file reads as (by default, an error)."""
    try:
        fd = os.open(name, _READ_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError as e:
        if missing is not None:
            return missing
        raise JailError(f"{path} is missing") from e
    except OSError as e:  # ELOOP: a symlink
        raise JailError(f"cannot open {path} (a symlink?): {e}") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise JailError(f"{path} is not a regular file")
        if st.st_uid != os.geteuid():
            raise JailError(f"{path} is owned by uid {st.st_uid}, not backtide's {os.geteuid()}")
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise JailError(f"{path} is writable by group or others: remove it by hand")
        content = os.read(fd, MAX_PEM_BYTES + 1)
    finally:
        os.close(fd)
    if len(content) > MAX_PEM_BYTES:
        raise JailError(f"{path} is bigger than {MAX_PEM_BYTES} bytes: remove it by hand")
    return content


def _blocks(pem: bytes, label: bytes) -> int:
    """How many PEM blocks whose label ends with ``label`` (``PRIVATE KEY`` counts
    ``RSA PRIVATE KEY`` too)."""
    return sum(1 for match in _PEM_BLOCK_RE.finditer(pem) if match.group(1).endswith(label))


def _exists(dir_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _tmp_name(name: str) -> str:
    return f".{name}.tmp"


def _unlink(dir_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
