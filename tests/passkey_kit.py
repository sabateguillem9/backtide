"""A passkey in software for the tests (T26-3b-2, T26-3c): what a browser's
``navigator.credentials.create`` and ``get`` answer, made with a real P-256 key, attestation
"none"."""

import base64
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.count = 0

    def create(
        self,
        options_json: str,
        origin: str,
        *,
        verified: bool = True,
        rp_id: str | None = None,
        challenge: str | None = None,
        kind: str = "webauthn.create",
        fmt: str = "none",
        statement: dict | None = None,
    ) -> str:
        """The browser's answer to ``options_json`` from ``origin``. The keyword arguments bend
        it the ways an attacker would (another site's origin or relying party, an old challenge,
        no user verification, the wrong ceremony)."""
        options = json.loads(options_json)
        client_data = json.dumps(
            {
                "type": kind,
                "challenge": challenge or options["challenge"],
                "origin": origin,
                "crossOrigin": False,
            }
        ).encode()
        numbers = self.key.public_key().public_numbers()
        cose = cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )
        flags = 0x01 | (0x04 if verified else 0) | 0x40  # present, verified, attested data
        attested = (
            bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose
        )
        auth_data = (
            hashlib.sha256((rp_id or options["rp"]["id"]).encode()).digest()
            + bytes([flags])
            + (0).to_bytes(4, "big")
            + attested
        )
        attestation = cbor2.dumps({"fmt": fmt, "attStmt": statement or {}, "authData": auth_data})
        return json.dumps(
            {
                "id": b64url(self.credential_id),
                "rawId": b64url(self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64url(client_data),
                    "attestationObject": b64url(attestation),
                },
            }
        )

    def get(
        self,
        options_json: str,
        origin: str,
        *,
        verified: bool = True,
        rp_id: str | None = None,
        challenge: str | None = None,
        kind: str = "webauthn.get",
        bad_signature: bool = False,
    ) -> str:
        """The browser's answer to ``options_json`` from ``origin``, bent the same ways."""
        options = json.loads(options_json)
        client_data = json.dumps(
            {
                "type": kind,
                "challenge": challenge or options["challenge"],
                "origin": origin,
                "crossOrigin": False,
            }
        ).encode()
        auth_data = (
            hashlib.sha256((rp_id or options["rpId"]).encode()).digest()
            + bytes([0x01 | (0x04 if verified else 0)])
            + self.count.to_bytes(4, "big")
        )
        signed = auth_data + hashlib.sha256(client_data).digest()
        signature = self.key.sign(
            signed + (b"x" if bad_signature else b""), ec.ECDSA(hashes.SHA256())
        )
        return json.dumps(
            {
                "id": b64url(self.credential_id),
                "rawId": b64url(self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64url(client_data),
                    "authenticatorData": b64url(auth_data),
                    "signature": b64url(signature),
                },
            }
        )
