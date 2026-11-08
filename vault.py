"""Encrypted, profile-scoped stable alias storage for privacy-gateway."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import sqlite3
import threading
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_ALIAS_RE = re.compile(r"\[[A-Z][A-Z0-9_]*_[0-9A-F]{32}\]")


def alias_ranges(text: str) -> list[tuple[int, int]]:
    """Return character ranges occupied by already-issued aliases."""
    return [(match.start(), match.end()) for match in _ALIAS_RE.finditer(text)]


def _decode_master_key(encoded: str) -> bytes:
    if not encoded:
        raise RuntimeError("HERMES_PRIVACY_GATEWAY_KEY is required")

    try:
        # Accept URL-safe base64 with or without trailing padding.
        padded = encoded + ("=" * (-len(encoded) % 4))
        master = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # pragma: no cover - defensive boundary
        raise RuntimeError(
            "HERMES_PRIVACY_GATEWAY_KEY must be URL-safe base64"
        ) from exc

    if len(master) != 32:
        raise RuntimeError(
            "HERMES_PRIVACY_GATEWAY_KEY must decode to exactly 32 bytes"
        )

    return master


def _derive(master: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(master)


def _normalize(value: str) -> str:
    # Stable aliases across common whitespace/casing differences.
    return " ".join(value.split()).casefold()


def _safe_kind(kind: str) -> str:
    cleaned = re.sub(r"[^A-Z0-9_]", "_", kind.upper())
    return cleaned or "PII"


def _hermes_plugin_db() -> sqlite3.Connection:
    # Import lazily so vault unit tests can run outside a Hermes checkout.
    from plugins.plugin_storage import plugin_db

    return plugin_db("privacy-gateway")


class AliasVault:
    """Persist stable aliases while encrypting their original values locally."""

    def __init__(
        self,
        env_name: str = "HERMES_PRIVACY_GATEWAY_KEY",
        *,
        connection: sqlite3.Connection | None = None,
        encoded_key: str | None = None,
    ) -> None:
        encoded = encoded_key if encoded_key is not None else os.environ.get(env_name, "")
        master = _decode_master_key(encoded)

        self._lookup_key = _derive(
            master,
            b"hermes-privacy-gateway/lookup/v1",
        )
        encryption_key = _derive(
            master,
            b"hermes-privacy-gateway/encryption/v1",
        )
        self._fernet = Fernet(base64.urlsafe_b64encode(encryption_key))
        self._db = connection if connection is not None else _hermes_plugin_db()
        # One connection is shared by every agent thread (check_same_thread=False); serialize all use.
        self._lock = threading.RLock()
        with self._lock:
            self._init_db()

    def _init_db(self) -> None:
        with self._db:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS aliases (
                    alias TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    lookup BLOB NOT NULL UNIQUE,
                    ciphertext BLOB NOT NULL
                )
                """
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

            key_check = hmac.new(
                self._lookup_key,
                b"privacy-gateway-key-check-v1",
                hashlib.sha256,
            ).hexdigest()

            row = self._db.execute(
                "SELECT value FROM metadata WHERE key = 'key_check'"
            ).fetchone()

            if row is None:
                self._db.execute(
                    "INSERT INTO metadata(key, value) VALUES('key_check', ?)",
                    (key_check,),
                )
            elif not hmac.compare_digest(row[0], key_check):
                raise RuntimeError(
                    "privacy-gateway master key does not match the existing alias vault"
                )

    def alias(self, kind: str, value: str) -> str:
        """Return a deterministic alias for an exact normalized entity value."""
        safe_kind = _safe_kind(kind)
        normalized = _normalize(value)
        digest = hmac.new(
            self._lookup_key,
            (safe_kind + "\0" + normalized).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        lookup = digest
        candidate_alias = f"[{safe_kind}_{digest.hex()[:32].upper()}]"
        with self._lock:
            return self._alias_locked(lookup, candidate_alias, safe_kind, value)

    def _alias_locked(self, lookup: bytes, candidate_alias: str, safe_kind: str, value: str) -> str:
        row = self._db.execute(
            "SELECT alias FROM aliases WHERE lookup = ?",
            (lookup,),
        ).fetchone()
        if row:
            return row[0]

        ciphertext = self._fernet.encrypt(value.encode("utf-8"))
        with self._db:
            self._db.execute(
                """
                INSERT OR IGNORE INTO aliases(alias, kind, lookup, ciphertext)
                VALUES (?, ?, ?, ?)
                """,
                (candidate_alias, safe_kind, lookup, ciphertext),
            )

        row = self._db.execute(
            "SELECT alias FROM aliases WHERE lookup = ?",
            (lookup,),
        ).fetchone()
        if not row:  # pragma: no cover - defensive storage boundary
            raise RuntimeError("failed to persist alias")
        return row[0]

    def resolve(self, alias: str) -> Optional[str]:
        """Resolve one known alias. Unknown aliases return None."""
        with self._lock:
            row = self._db.execute(
                "SELECT ciphertext FROM aliases WHERE alias = ?",
                (alias,),
            ).fetchone()
        if not row:
            return None

        try:
            return self._fernet.decrypt(row[0]).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("alias vault decryption failed") from exc

    def rehydrate(self, text: str) -> str:
        """Replace known aliases with local plaintext values."""

        def replace(match: re.Match[str]) -> str:
            original = self.resolve(match.group(0))
            return original if original is not None else match.group(0)

        return _ALIAS_RE.sub(replace, text)
