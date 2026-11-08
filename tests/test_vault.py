import base64
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from vault import AliasVault


def make_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def make_vault(key: str | None = None):
    conn = sqlite3.connect(":memory:")
    return AliasVault(connection=conn, encoded_key=key or make_key()), conn


def test_alias_is_stable_for_case_and_whitespace():
    vault, _ = make_vault()
    a = vault.alias("PERSON", "John   Smith")
    b = vault.alias("PERSON", " john smith ")
    assert a == b
    assert a.startswith("[PERSON_")


def test_different_entity_types_get_different_aliases():
    vault, _ = make_vault()
    assert vault.alias("PERSON", "Acme") != vault.alias("ORGANIZATION", "Acme")


def test_rehydrate_known_alias():
    vault, _ = make_vault()
    alias = vault.alias("EMAIL_ADDRESS", "john@example.com")
    assert vault.rehydrate(f"Send to {alias}") == "Send to john@example.com"


def test_unknown_alias_is_left_alone():
    vault, _ = make_vault()
    text = "[PERSON_0123456789ABCDEF0123456789ABCDEF]"
    assert vault.rehydrate(text) == text


def test_plaintext_is_not_stored_in_alias_table():
    vault, conn = make_vault()
    vault.alias("PERSON", "Sensitive Person")
    row = conn.execute("SELECT ciphertext FROM aliases").fetchone()
    assert row is not None
    assert b"Sensitive Person" not in row[0]


def test_wrong_key_refuses_existing_vault():
    conn = sqlite3.connect(":memory:")
    AliasVault(connection=conn, encoded_key=make_key())
    with pytest.raises(RuntimeError, match="master key"):
        AliasVault(connection=conn, encoded_key=make_key())


def test_shared_connection_is_safe_across_threads():
    # Hermes hands every agent/subagent thread the same plugin_db connection.
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    vault = AliasVault(connection=conn, encoded_key=make_key())
    errors = []

    def work(worker: int) -> None:
        for i in range(200):
            value = f"Person {worker}-{i % 37}"
            try:
                alias = vault.alias("PERSON", value)
                assert vault.resolve(alias) == value
            except Exception as exc:  # collected so the main thread can report it
                errors.append(repr(exc))

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(work, range(32)))

    assert errors == []
