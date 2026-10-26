"""The pinned images, the distribution and its packages, and the manifest (T13-3)."""

import json
import os
from collections.abc import Sequence
from pathlib import Path

import pytest

from backtide.jail import IMAGE as OPENCLAW_IMAGE
from backtide.jail import proxy_config
from backtide.jail import sensor as sensor_jail
from backtide.setup import images, manifest, packages
from backtide.setup.host import Ran
from backtide.setup.images import ImageError
from backtide.setup.manifest import Manifest, ManifestError

# Images


def test_the_three_images_come_from_their_modules_and_are_pinned() -> None:
    refs = [image.ref for image in images.pinned()]
    assert refs == [OPENCLAW_IMAGE, proxy_config.IMAGE, sensor_jail.IMAGE]
    for image in images.pinned():
        assert image.digest.startswith("sha256:") and len(image.digest) == 71
        assert "@" not in image.repo and ":" not in image.repo.rsplit("/", 1)[-1]
    assert images.listing().count("@sha256:") == 3


class Docker:
    def __init__(self, *, pulls_fail: int = 0, wrong_digest: bool = False) -> None:
        self.have: set[str] = set()
        self.pulls_fail = pulls_fail
        self.wrong_digest = wrong_digest
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str]) -> Ran | None:
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:2] == ("docker", "pull"):
            if self.pulls_fail:
                self.pulls_fail -= 1
                return Ran(1, "", "toomanyrequests: rate limit")
            self.have.add(argv[-1])
            return Ran(0, "", "")
        ref = argv[-1]
        if ref not in self.have:
            return Ran(1, "", "No such image")
        image = next(i for i in images.pinned() if i.ref == ref)
        digest = "sha256:" + "0" * 64 if self.wrong_digest else image.digest
        return Ran(0, json.dumps([f"{image.repo}@{digest}"]), "")


def test_an_image_is_pulled_once_and_checked() -> None:
    docker, image = Docker(), images.pinned()[1]
    assert images.pull(image, run=docker, run_long=docker, sleep=lambda s: None) is True
    assert images.pull(image, run=docker, run_long=docker, sleep=lambda s: None) is False
    assert [argv for argv in docker.calls if argv[1] == "pull"] == [images.pull_argv(image)]
    assert images.pull_argv(image)[-1] == image.ref  # by digest, never by tag


def test_a_rate_limit_is_waited_out() -> None:
    docker, pauses = Docker(pulls_fail=2), []
    images.pull(images.pinned()[0], run=docker, run_long=docker, sleep=pauses.append)
    assert pauses == [images.PULL_PAUSE, images.PULL_PAUSE * 2]


def test_a_pull_that_never_works_says_so() -> None:
    docker = Docker(pulls_fail=images.PULL_ATTEMPTS)
    with pytest.raises(ImageError, match="rate limit"):
        images.pull(images.pinned()[0], run=docker, run_long=docker, sleep=lambda s: None)


def test_an_image_that_does_not_answer_to_its_digest_is_not_used() -> None:
    docker = Docker(wrong_digest=True)
    with pytest.raises(ImageError, match="no responde a su digest"):
        images.pull(images.pinned()[2], run=docker, run_long=docker, sleep=lambda s: None)
    assert images.is_present(images.pinned()[2], run=docker) is False


# The distribution and its packages


class Host:
    def __init__(self, os_release: bytes | None, present: set[str] = frozenset()) -> None:
        self.os_release = os_release
        self.present = present

    def read(self, path: str, limit: int = 65536) -> bytes | None:
        # As on Fedora and Ubuntu: /etc/os-release is a link (never followed), the file is here.
        return self.os_release if path == "/usr/lib/os-release" else None

    def run(self, argv: Sequence[str]) -> Ran | None:
        return Ran(0, "", "") if argv[0] in self.present else None


def test_read_distro() -> None:
    ubuntu = packages.read_distro(
        Host(b'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu"\n')
    )
    assert ubuntu is not None and ubuntu.apt and ubuntu.supported and ubuntu.codename == "noble"
    fedora = packages.read_distro(Host(b"ID=fedora\nVERSION_ID=44\n"))
    assert fedora is not None and not fedora.apt and fedora.supported
    assert not packages.read_distro(Host(b"ID=debian\nVERSION_ID=13\n")).supported
    assert not packages.read_distro(Host(b"ID=fedora\nVERSION_ID=42\n")).supported
    assert packages.read_distro(Host(None)) is None


def test_missing_tools_and_their_packages() -> None:
    host = Host(b"ID=fedora\nVERSION_ID=44\n", present={"mkfs.btrfs", "curl", "ip"})
    missing = packages.missing_tools(host)
    assert [tool.name for tool in missing] == ["openssl", "gnupg"]
    fedora = packages.read_distro(host)
    assert packages.package_names(fedora, missing) == ["openssl", "gnupg2"]
    assert packages.install_argvs(fedora, ["openssl"]) == [("dnf", "-y", "install", "openssl")]
    ubuntu = packages.Distro("ubuntu", "24.04", "noble", "Ubuntu")
    assert packages.install_argvs(ubuntu, ["gnupg"])[-1] == (
        "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y",
        "--no-install-recommends", "gnupg",
    )  # fmt: skip


def test_dockers_key_is_checked_by_its_published_fingerprint() -> None:
    colons = (
        "pub:-:4096:1:8D81803C0EBFCD88:1487788586:::-:::scESC::::::23::0:\n"
        "fpr:::::::::9DC858229FC7DD38854AE2D88D81803C0EBFCD88:\n"
        "sub:-:4096:1:7EA0A9C3F273FCD8:1487792064::::::s::::::23:\n"
        "fpr:::::::::D3306A018370199E527AE7997EA0A9C3F273FCD8:\n"
    )
    assert packages.primary_fingerprints(colons) == [packages.DOCKER_KEYS["ubuntu"][1]]
    assert packages.primary_fingerprints("") == []
    # A second key in the same file is a second pub record, whatever its subkeys
    other = (
        "pub:-:4096:1:AAAAAAAAAAAAAAAA:1487788586:::-:::scESC::::::23::0:\n"
        "fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n"
    )
    assert packages.primary_fingerprints(colons + other) == [
        packages.DOCKER_KEYS["ubuntu"][1],
        "A" * 40,
    ]
    assert packages.primary_fingerprints("pub:-:4096:1:X:1:::-:::scESC:\n") == [""]


def test_the_repositories_are_dockers_and_signed() -> None:
    ubuntu = packages.Distro("ubuntu", "26.04", "resolute", "Ubuntu")
    source = packages.apt_source(ubuntu, "x86_64", "/etc/apt/keyrings/docker.asc")
    assert "[arch=amd64 signed-by=/etc/apt/keyrings/docker.asc]" in source
    assert "https://download.docker.com/linux/ubuntu resolute stable" in source
    repo = packages.dnf_repo(Path("/etc/pki/rpm-gpg/backtide-docker-ce.asc"))
    assert "gpgcheck=1" in repo and "https://download.docker.com/linux/fedora/" in repo
    # dnf checks against the key the installer verified, never one it downloads itself
    assert "gpgkey=file:///etc/pki/rpm-gpg/backtide-docker-ce.asc\n" in repo
    assert "gpgkey=https" not in repo


# The manifest


def test_the_manifest_round_trips_and_its_lists_are_sets(tmp_path: Path) -> None:
    record = Manifest()
    record.add("files", tmp_path / "a")
    record.add("files", tmp_path / "a")
    record.done("state")
    record.done("state")
    record.facts["subnets"] = {"x": "172.29.255.0/24"}
    path = tmp_path / "install-manifest.json"
    manifest.save(record, path)
    assert os.stat(path).st_mode & 0o777 == 0o600
    again = manifest.load(path)
    assert again.created["files"] == [str(tmp_path / "a")]
    assert again.steps == ["state"]
    assert again.facts == record.facts
    with pytest.raises(ValueError):
        record.add("spaceships", "x")


def test_a_missing_manifest_is_an_empty_one(tmp_path: Path) -> None:
    assert manifest.load(tmp_path / "none.json").steps == []


@pytest.mark.parametrize(
    ("content", "mode", "said"),
    [
        ("{}", 0o600, "versión"),
        ("not json", 0o600, "JSON"),
        (Manifest().to_json(), 0o644, "abierto"),
    ],
)
def test_a_manifest_that_cannot_be_trusted_is_refused(
    tmp_path: Path, content: str, mode: int, said: str
) -> None:
    path = tmp_path / "install-manifest.json"
    path.write_text(content)
    path.chmod(mode)
    with pytest.raises(ManifestError, match=said):
        manifest.load(path)
