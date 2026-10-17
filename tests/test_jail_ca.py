"""Unit tests for backtide/jail/ca.py: the egress proxy's CA and the agent's certificate.

openssl is faked (``run_openssl``): the fake writes PEM-shaped files where the real one would.
The folders are real. The VM test (tests/integration/test_proxy_container.py) runs the real openssl
and mitmproxy on the result."""

import os
import stat
from pathlib import Path

import pytest

from backtide.jail import ca
from backtide.jail.ca import CaPaths, ensure_ca
from backtide.jail.docker import JailError

KEY = b"-----BEGIN PRIVATE KEY-----\nMIIG\n-----END PRIVATE KEY-----\n"
CERT = b"-----BEGIN CERTIFICATE-----\nMIIE\n-----END CERTIFICATE-----\n"
DH = b"-----BEGIN DH PARAMETERS-----\nMIIB\n-----END DH PARAMETERS-----\n"


class FakeOpenssl:
    """Writes what ``openssl req`` and ``openssl genpkey`` would, and records each argv."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.fail: str | None = None
        self.config_text = ""

    def __call__(self, args: list[str]) -> None:
        self.calls.append(list(args))
        if self.fail is not None:
            raise JailError(self.fail)
        if args[0] == "req":
            self.config_text = Path(args[args.index("-config") + 1]).read_text()
            Path(args[args.index("-keyout") + 1]).write_bytes(KEY)
            Path(args[args.index("-out") + 1]).write_bytes(CERT)
        elif args[0] == "genpkey":
            Path(args[args.index("-out") + 1]).write_bytes(DH)


@pytest.fixture
def openssl(monkeypatch: pytest.MonkeyPatch) -> FakeOpenssl:
    fake = FakeOpenssl()
    monkeypatch.setattr(ca, "run_openssl", fake)
    return fake


@pytest.fixture
def paths(tmp_path: Path) -> CaPaths:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    # Without root, the only group this user can give the folder to is one of its own.
    return CaPaths(proxy_dir=state / "proxy-ca", agent_dir=state / "agent-ca", gid=os.getgid())


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


# The openssl argv


def test_the_ca_argv_is_rsa_3072_for_five_years_with_our_own_config() -> None:
    argv = ca.ca_argv(Path("/w/ca.cnf"), Path("/w/ca.key"), Path("/w/ca.crt"))
    assert argv == [
        "req", "-x509", "-new", "-config", "/w/ca.cnf", "-newkey", "rsa:3072", "-nodes",
        "-sha256", "-days", "1826", "-keyout", "/w/ca.key", "-out", "/w/ca.crt",
    ]  # fmt: skip


def test_the_ca_config_makes_a_ca_that_mitmproxy_accepts() -> None:
    """mitmproxy needs CA:TRUE and keyCertSign (docs/21, section 3); the name says whose."""
    text = ca.ca_config("0a1b2c3d")
    assert "CN = backtide agent CA 0a1b2c3d" in text
    assert "basicConstraints = critical,CA:TRUE,pathlen:0" in text
    assert "keyUsage = critical,keyCertSign,cRLSign" in text
    assert "prompt = no" in text


@pytest.mark.parametrize("install_id", ["", "UPPER", "a b", "x\nCN = evil", "a" * 33])
def test_the_ca_name_is_checked(install_id: str) -> None:
    with pytest.raises(ValueError):
        ca.ca_config(install_id)


def test_the_dhparam_argv_is_a_standard_group() -> None:
    """RFC 7919's ffdhe3072: instant, unlike ``openssl dhparam`` (T06-1, P2)."""
    assert ca.dhparam_argv(Path("/w/dh.pem")) == [
        "genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt", "group:ffdhe3072",
        "-out", "/w/dh.pem",
    ]  # fmt: skip


# Making it


def test_ensure_ca_makes_the_ca_the_dhparam_and_the_agents_certificate(
    paths: CaPaths, openssl: FakeOpenssl
) -> None:
    assert ensure_ca(paths) is True
    assert [call[0] for call in openssl.calls] == ["req", "genpkey"]
    assert sorted(os.listdir(paths.proxy_dir)) == ["mitmproxy-ca.pem", "mitmproxy-dhparam.pem"]
    assert (paths.proxy_dir / "mitmproxy-ca.pem").read_bytes() == KEY + CERT  # mitmproxy's order
    assert (paths.proxy_dir / "mitmproxy-dhparam.pem").read_bytes() == DH
    assert os.listdir(paths.agent_dir) == ["ca.pem"]
    assert (paths.agent_dir / "ca.pem").read_bytes() == CERT
    assert "backtide agent CA " in openssl.config_text


def test_the_modes_and_groups_of_the_design(paths: CaPaths, openssl: FakeOpenssl) -> None:
    """proxy-ca 0750 and its files 0440, group the proxy's; agent-ca 0755 and ca.pem 0444."""
    ensure_ca(paths)
    assert mode(paths.proxy_dir) == 0o750
    for name in ("mitmproxy-ca.pem", "mitmproxy-dhparam.pem"):
        assert mode(paths.proxy_dir / name) == 0o440, name
        assert (paths.proxy_dir / name).stat().st_gid == paths.gid
    assert paths.proxy_dir.stat().st_gid == paths.gid
    assert mode(paths.agent_dir) == 0o755
    assert mode(paths.agent_dir / "ca.pem") == 0o444


def test_the_key_is_made_in_a_private_folder_that_is_removed(
    paths: CaPaths, openssl: FakeOpenssl
) -> None:
    ensure_ca(paths)
    req = openssl.calls[0]
    work = Path(req[req.index("-keyout") + 1]).parent
    assert work.parent == paths.proxy_dir.parent  # next to the state, not in a mounted folder
    assert not work.exists()
    assert sorted(os.listdir(paths.proxy_dir.parent)) == ["agent-ca", "proxy-ca"]


def test_the_agent_never_gets_the_key(paths: CaPaths, openssl: FakeOpenssl) -> None:
    ensure_ca(paths)
    for path in paths.agent_dir.iterdir():
        assert b"PRIVATE KEY" not in path.read_bytes()


def test_ensure_ca_never_replaces_an_existing_ca(paths: CaPaths, openssl: FakeOpenssl) -> None:
    ensure_ca(paths)
    openssl.calls.clear()
    assert ensure_ca(paths) is False
    assert openssl.calls == []
    assert (paths.proxy_dir / "mitmproxy-ca.pem").read_bytes() == KEY + CERT


def test_a_missing_dhparam_or_agent_certificate_is_made_again(
    paths: CaPaths, openssl: FakeOpenssl
) -> None:
    ensure_ca(paths)
    (paths.proxy_dir / "mitmproxy-dhparam.pem").unlink()
    (paths.agent_dir / "ca.pem").unlink()
    openssl.calls.clear()
    assert ensure_ca(paths) is False  # the CA itself is the same one
    assert [call[0] for call in openssl.calls] == ["genpkey"]
    assert (paths.agent_dir / "ca.pem").read_bytes() == CERT


def test_a_stale_agent_certificate_is_replaced_by_the_cas(
    paths: CaPaths, openssl: FakeOpenssl
) -> None:
    ensure_ca(paths)
    stale = paths.agent_dir / "ca.pem"
    stale.chmod(0o644)
    stale.write_bytes(b"-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n")
    ensure_ca(paths)
    assert stale.read_bytes() == CERT
    assert mode(stale) == 0o444


def test_leftovers_of_a_crash_are_removed(paths: CaPaths, openssl: FakeOpenssl) -> None:
    ensure_ca(paths)
    (paths.proxy_dir / ".mitmproxy-ca.pem.tmp").write_bytes(KEY)
    (paths.agent_dir / ".ca.pem.tmp").write_bytes(CERT)
    ensure_ca(paths)
    assert sorted(os.listdir(paths.proxy_dir)) == ["mitmproxy-ca.pem", "mitmproxy-dhparam.pem"]
    assert os.listdir(paths.agent_dir) == ["ca.pem"]


def test_what_a_killed_run_left_is_removed(paths: CaPaths, openssl: FakeOpenssl) -> None:
    """A kill -9 in the middle of _make leaves the key in a private folder: the next run
    removes it (and never follows a symlink with that name)."""
    stale = paths.proxy_dir.parent / ".backtide-ca-abc123"
    stale.mkdir(mode=0o700)
    (stale / "ca.key").write_bytes(KEY)
    elsewhere = paths.proxy_dir.parent.parent / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep").write_text("x")
    (paths.proxy_dir.parent / ".backtide-dh-link").symlink_to(elsewhere)
    ensure_ca(paths)
    assert not stale.exists()
    assert (elsewhere / "keep").exists()


def test_openssl_never_reads_the_callers_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """No OPENSSL_CONF or OPENSSL_MODULES of whoever runs backtide, and not the system's cnf."""
    seen: dict[str, object] = {}

    def run(argv: list[str], **kwargs: object) -> object:
        seen.update(kwargs, argv=argv)
        return ca.subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setenv("OPENSSL_CONF", "/srv/evil.cnf")
    monkeypatch.setenv("OPENSSL_MODULES", "/srv/evil")
    monkeypatch.setattr(ca.subprocess, "run", run)
    ca.run_openssl(["version"])
    assert seen["env"] == {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C",
        "OPENSSL_CONF": "/dev/null",
    }


def test_an_openssl_failure_leaves_nothing_behind(paths: CaPaths, openssl: FakeOpenssl) -> None:
    openssl.fail = "openssl req failed"
    with pytest.raises(JailError, match="openssl req failed"):
        ensure_ca(paths)
    assert os.listdir(paths.proxy_dir) == []
    assert sorted(os.listdir(paths.proxy_dir.parent)) == ["proxy-ca"]


# What it refuses


@pytest.mark.parametrize("stray", ["notes.txt", "mitmproxy-ca-cert.pem", "events.sock"])
def test_anything_else_in_the_proxys_ca_folder_is_refused(
    paths: CaPaths, openssl: FakeOpenssl, stray: str
) -> None:
    """The proxy sees this folder: nothing of backtide may land in it by mistake."""
    ensure_ca(paths)
    (paths.proxy_dir / stray).write_text("x")
    with pytest.raises(JailError, match=f"must hold only.*{stray}"):
        ensure_ca(paths)


def test_anything_else_in_the_agents_ca_folder_is_refused(
    paths: CaPaths, openssl: FakeOpenssl
) -> None:
    ensure_ca(paths)
    (paths.agent_dir / "mitmproxy-ca.pem").write_bytes(KEY + CERT)
    with pytest.raises(JailError, match=r"must hold only \[.ca.pem.\]"):
        ensure_ca(paths)


@pytest.mark.parametrize(
    "content",
    [b"", CERT, KEY, KEY + KEY + CERT, b"garbage"],
    ids=["empty", "no-key", "no-certificate", "two-keys", "garbage"],
)
def test_a_broken_ca_is_refused_never_replaced(
    paths: CaPaths, openssl: FakeOpenssl, content: bytes
) -> None:
    paths.proxy_dir.mkdir(mode=0o750)
    (paths.proxy_dir / "mitmproxy-ca.pem").write_bytes(content)
    with pytest.raises(JailError, match="remove it by hand"):
        ensure_ca(paths)
    assert openssl.calls == []
    assert (paths.proxy_dir / "mitmproxy-ca.pem").read_bytes() == content


def test_symlinks_are_refused(paths: CaPaths, openssl: FakeOpenssl, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    paths.proxy_dir.symlink_to(elsewhere)
    with pytest.raises(JailError, match="not a directory"):
        ensure_ca(paths)
    paths.proxy_dir.unlink()
    paths.proxy_dir.mkdir(mode=0o750)
    (paths.proxy_dir / "mitmproxy-ca.pem").symlink_to(elsewhere / "planted.pem")
    with pytest.raises(JailError, match="mitmproxy-ca.pem"):
        ensure_ca(paths)
    assert not (elsewhere / "planted.pem").exists()


def test_a_ca_writable_by_others_is_refused(paths: CaPaths, openssl: FakeOpenssl) -> None:
    ensure_ca(paths)
    (paths.proxy_dir / "mitmproxy-ca.pem").chmod(0o666)
    with pytest.raises(JailError, match="writable by group or others"):
        ensure_ca(paths)


def test_paths_are_checked() -> None:
    with pytest.raises(ValueError):
        CaPaths(proxy_dir=Path("relative"), agent_dir=Path("/a"), gid=1)
    with pytest.raises(ValueError):
        CaPaths(proxy_dir=Path("/s/ca"), agent_dir=Path("/s/ca/agent"), gid=1)
    with pytest.raises(ValueError):
        CaPaths(proxy_dir=Path("/s/ca"), agent_dir=Path("/s/agent"), gid=0)


def test_certificates_only_keeps_the_certificate_blocks() -> None:
    other = b"-----BEGIN CERTIFICATE-----\nSECOND\n-----END CERTIFICATE-----\n"
    assert ca.certificates_only(KEY + CERT + other) == CERT + other
    assert ca.certificates_only(KEY) == b""
