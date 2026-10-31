"""The web's passkeys (T26-3b-2, D40): registered from a live session, kept by the service.

After the first entry with the password, the web asks to register a passkey; through the
domain (T26-4) it will be the way in, and changing the agents, the keys and the terminal will ask
to touch it again (T26-3c). This part only registers them; signing in with one is T26-3c.

- The service checks the browser's answer with ``webauthn`` (3.0.1, pinned with its packages by
  hash in uv.lock), never the web: the web only carries the challenge and the answer.
- A challenge is good for one answer and ``CHALLENGE_SECONDS``, for the session that asked for
  it. The answer must come from our own origin (``http://backtide.localhost:<port>``: a passkey
  cannot belong to an address like 127.0.0.1) and for our relying party, with the user verified
  (Touch ID, a PIN), and must not be a key already kept.
- Only public keys are kept: ``<state_dir>/web-auth/passkeys.json``, root's and 0600, at most
  ``MAX_KEYS``. Whoever reads the file cannot sign in with it. Each key has a name the owner
  gives it (``NAME_CHARS`` at most, printable) and the date it was added.
"""

import base64
import hashlib
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import parse_attestation_object, parse_registration_credential_json
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationFormat,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from backtide.service.settings import SettingsError, write_private

FOLDER = "web-auth"
FILE = "passkeys.json"
RP_ID = "backtide.localhost"
RP_NAME = "backtide"
WEB_PORT = 8765  # the installed web's port (`backtide web`'s default): its origin is the answer's
USER_ID = b"backtide-owner"  # one owner: every key is for the same account
CHALLENGE_SECONDS = 120
MAX_KEYS = 10
NAME_CHARS = 48
MAX_FILE_BYTES = 64 * 1024
MAX_ANSWER_CHARS = 3500  # the narrow socket's line is 4 KiB
ALGORITHMS = [  # what a platform authenticator or a security key signs with
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.EDDSA,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
]


class PasskeyError(Exception):
    """A key that cannot be registered, or a file that is not ours. Says why, never a secret."""


@dataclass(frozen=True)
class Passkey:
    id: str  # base64url of the credential id
    public_key: str  # base64 of the COSE public key
    sign_count: int
    name: str
    added: str  # ISO 8601, UTC

    @property
    def tail(self) -> str:
        """The last four characters of its id: enough to tell keys apart in a list or an event."""
        return self.id[-4:]


def origin_for(port: int) -> str:
    return f"http://{RP_ID}:{port}"


def path_of(state_dir: Path) -> Path:
    return Path(state_dir) / FOLDER / FILE


def name_problem(name: object) -> str | None:
    if not isinstance(name, str) or not name.strip():
        return "la llave necesita un nombre (por ejemplo «portátil» o «móvil»)"
    if len(name) > NAME_CHARS or name != name.strip():
        return f"el nombre de la llave es texto normal de hasta {NAME_CHARS} caracteres"
    # Letters, digits, spaces, - and _: it goes into an alert, where a chat would turn a
    # "t.me/…" or an "@someone" into a link (review of T26-3b-2).
    if not all(c.isalnum() or c in " -_" for c in name):
        return "el nombre de la llave lleva solo letras, cifras, espacios, - y _"
    return None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _digest(session_id: str) -> bytes:
    return hashlib.sha256(session_id.encode()).digest()


class Passkeys:
    """The service's side: one per service, thread-safe. ``origins`` are the web's own (the
    answer must come from one of them); ``clock`` is monotonic seconds, ``now`` the date."""

    def __init__(
        self,
        state_dir: Path,
        *,
        origins: Sequence[str],
        rp_id: str = RP_ID,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not origins:
            raise ValueError("a passkey needs the web's origin")
        self._state_dir = Path(state_dir)
        self._origins = list(origins)
        self._rp_id = rp_id
        self._clock = clock
        self._now = now
        self._challenges: dict[bytes, tuple[bytes, float]] = {}  # session digest -> challenge
        self._lock = threading.Lock()

    # -- reading and writing the file --------------------------------------------------------

    def keys(self) -> list[Passkey]:
        """The kept keys, oldest first. PasskeyError for a file that is not ours."""
        path = path_of(self._state_dir)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            return []
        except OSError as error:
            raise PasskeyError(f"no se puede abrir {path}: {error.strerror}") from None
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > MAX_FILE_BYTES
            ):
                raise PasskeyError(f"{path} no es el archivo de las llaves: no se usa")
            raw = os.read(fd, MAX_FILE_BYTES + 1)
        finally:
            os.close(fd)
        try:
            data = json.loads(raw)
            return [Passkey(**item) for item in data["keys"]]
        except (ValueError, TypeError, KeyError) as error:
            raise PasskeyError(f"{path} no se entiende: {type(error).__name__}") from None

    def _write(self, keys: list[Passkey]) -> None:
        folder = self._state_dir / FOLDER
        try:
            folder.mkdir(mode=0o700, exist_ok=True)
            info = os.lstat(folder)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise PasskeyError(f"{folder} no es una carpeta nuestra")
            os.chmod(folder, 0o700)
            data = json.dumps({"keys": [asdict(key) for key in keys]}, indent=2) + "\n"
            write_private(folder, FILE, data.encode(), private_dir=True)
        except OSError as error:
            raise PasskeyError(f"no se puede guardar en {folder}: {error.strerror}") from None
        except SettingsError as error:
            raise PasskeyError(f"no se puede guardar en {folder}: {error}") from None

    def remove(self, key_id: str) -> bool:
        """Take a key out (a registration the black box did not take; T26-3d's "quitar")."""
        with self._lock:
            kept = self.keys()
            left = [k for k in kept if k.id != key_id]
            if len(left) == len(kept):
                return False
            self._write(left)
            return True

    # -- registering ---------------------------------------------------------------------------

    def begin(self, session_id: str) -> str:
        """The options for the browser's ``navigator.credentials.create``, as JSON, with a new
        challenge for this session (the one before, if any, dies)."""
        kept = self.keys()
        if len(kept) >= MAX_KEYS:
            raise PasskeyError(f"ya hay {MAX_KEYS} llaves: quita alguna antes")
        challenge = secrets.token_bytes(32)
        options = generate_registration_options(
            rp_id=self._rp_id,
            rp_name=RP_NAME,
            user_id=USER_ID,
            user_name="backtide",
            user_display_name="backtide",
            challenge=challenge,
            timeout=CHALLENGE_SECONDS * 1000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64.urlsafe_b64decode(k.id + "=" * (-len(k.id) % 4))
                )
                for k in kept
            ],
        )
        with self._lock:
            now = self._clock()
            self._challenges = {d: c for d, c in self._challenges.items() if c[1] > now}
            self._challenges[_digest(session_id)] = (challenge, now + CHALLENGE_SECONDS)
        return options_to_json(options)

    def verify(self, session_id: str, answer: object, name: object) -> Passkey:
        """Check the browser's answer to this session's challenge: the key it would keep,
        written nowhere yet (``keep`` writes it, once the black box has it). The challenge is
        spent whatever happens. PasskeyError says why not."""
        with self._lock:
            pending = self._challenges.pop(_digest(session_id), None)
            now = self._clock()
        if pending is None or now >= pending[1]:
            raise PasskeyError(
                "no hay un registro pedido para esta sesión, o ya caducó: empieza otra vez"
            )
        why = name_problem(name)
        if why is not None:
            raise PasskeyError(why)
        if not isinstance(answer, str) or not 0 < len(answer) <= MAX_ANSWER_CHARS:
            raise PasskeyError("la respuesta del navegador no tiene la forma esperada")
        try:
            # Only "none" (what we ask for): root never parses the certificates, TPM structures
            # or JWS another format would bring, which we would not trust anyway.
            credential = parse_registration_credential_json(answer)
            fmt = parse_attestation_object(credential.response.attestation_object).fmt
            if fmt != AttestationFormat.NONE.value:
                raise PasskeyError("solo se aceptan llaves sin certificado del fabricante (none)")
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=pending[0],
                expected_rp_id=self._rp_id,
                expected_origin=self._origins,
                require_user_verification=True,
                supported_pub_key_algs=ALGORITHMS,
            )
        except PasskeyError:
            raise
        except (WebAuthnException, ValueError, TypeError, KeyError, RecursionError) as error:
            raise PasskeyError(
                f"el navegador no ha dado una llave válida: {type(error).__name__}"
            ) from None
        key = Passkey(
            id=_b64url(verified.credential_id),
            public_key=base64.b64encode(verified.credential_public_key).decode(),
            sign_count=verified.sign_count,
            name=str(name),
            added=self._now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self._check_room(self.keys(), key)
        return key

    @staticmethod
    def _check_room(kept: list[Passkey], key: Passkey) -> None:
        if any(k.id == key.id for k in kept):
            raise PasskeyError("esa llave ya está registrada")
        if len(kept) >= MAX_KEYS:
            raise PasskeyError(f"ya hay {MAX_KEYS} llaves: quita alguna antes")

    def keep(self, key: Passkey) -> None:
        """Write ``key`` (checked by ``verify``, and recorded): again under the lock, the room
        and the duplicate, since another may have been kept meanwhile."""
        with self._lock:
            kept = self.keys()
            self._check_room(kept, key)
            self._write([*kept, key])

    def finish(self, session_id: str, answer: object, name: object) -> Passkey:
        """``verify`` and ``keep`` in one (the tests'; the service records in between)."""
        key = self.verify(session_id, answer, name)
        self.keep(key)
        return key


def describe(key: Passkey) -> dict[str, Any]:
    """What may be shown or recorded of a key: its name, the tail of its id and when."""
    return {"name": key.name, "tail": key.tail, "added": key.added}


__all__ = [
    "CHALLENGE_SECONDS",
    "MAX_KEYS",
    "RP_ID",
    "Passkey",
    "PasskeyError",
    "Passkeys",
    "describe",
    "name_problem",
    "origin_for",
    "path_of",
]
