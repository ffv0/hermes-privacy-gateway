from types import SimpleNamespace
import base64
import secrets
import sqlite3

import pytest

pytest.importorskip("presidio_analyzer")

from privacy import (
    BLOCKED_REQUEST,
    PrivacyEngine,
    blocked_content_for_key,
    contains_non_text_model_content,
    select_non_overlapping_results,
    walk_model_text,
    walk_strings,
)
from vault import AliasVault


def test_walk_strings_preserves_structure():
    value = {"a": ["john@example.com", {"b": "John"}], "n": 4}
    out = walk_strings(value, lambda s: f"<{s}>")
    assert out == {"a": ["<john@example.com>", {"b": "<John>"}], "n": 4}


def test_model_text_walk_preserves_protocol_ids_and_sanitizes_content():
    value = [
        {
            "type": "message",
            "id": "person_911469234FCA8DD79AE3CE8306D7ED40",
            "role": "user",
            "content": [
                {"type": "input_text", "text": "Alice Example"},
            ],
        },
        {
            "type": "function_call",
            "id": "fc_123",
            "call_id": "call_456",
            "name": "lookup_customer",
            "arguments": {"customer_id": "Alice Example"},
        },
    ]

    out = walk_model_text(value, lambda text: f"<{text}>")

    assert out[0]["id"] == value[0]["id"]
    assert out[0]["type"] == "message"
    assert out[0]["role"] == "user"
    assert out[0]["content"][0]["type"] == "input_text"
    assert out[0]["content"][0]["text"] == "<Alice Example>"
    assert out[1]["id"] == "fc_123"
    assert out[1]["call_id"] == "call_456"
    assert out[1]["name"] == "lookup_customer"
    assert out[1]["arguments"]["customer_id"] == "<Alice Example>"


def test_model_text_walk_preserves_unknown_scalar_metadata():
    value = {
        "metadata": {
            "opaque_reference": "Alice Example",
            "ids": ["Alice Example", "Bob Example"],
        },
        "content": "Alice Example",
    }

    out = walk_model_text(value, lambda text: f"<{text}>")

    assert out["metadata"] == value["metadata"]
    assert out["content"] == "<Alice Example>"


def test_detects_image_payload():
    payload = [{"type": "image_url", "image_url": {"url": "data:image/png;base64,abc"}}]
    assert contains_non_text_model_content(payload)


def test_plain_text_payload_not_flagged_as_non_text():
    payload = [{"role": "user", "content": "hello"}]
    assert not contains_non_text_model_content(payload)


def test_blocked_messages_shape():
    assert blocked_content_for_key("messages") == [
        {"role": "user", "content": BLOCKED_REQUEST}
    ]


def test_secret_filter_removes_authorization_header():
    text = "Authorization: Bearer secret-token\nHello"
    out = PrivacyEngine.remove_high_confidence_secrets(text)
    assert "secret-token" not in out
    assert "[SECRET_REMOVED]" in out


def test_overlapping_results_prefer_confidence_then_longer_span():
    results = [
        SimpleNamespace(start=0, end=5, score=0.70),
        SimpleNamespace(start=0, end=11, score=0.70),
        SimpleNamespace(start=20, end=24, score=0.99),
        SimpleNamespace(start=21, end=25, score=0.50),
    ]
    selected = select_non_overlapping_results(results)
    assert [(item.start, item.end) for item in selected] == [(0, 11), (20, 24)]


def test_overlapping_ties_use_entity_type_deterministically():
    results = [
        SimpleNamespace(start=0, end=5, score=0.70, entity_type="ZETA"),
        SimpleNamespace(start=0, end=5, score=0.70, entity_type="ALPHA"),
    ]
    selected = select_non_overlapping_results(results)
    assert [item.entity_type for item in selected] == ["ALPHA"]


def test_sanitize_preserves_offsets_and_existing_aliases():
    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    vault = AliasVault(connection=sqlite3.connect(":memory:"), encoded_key=key)
    existing_alias = vault.alias("PERSON", "Alice Example")

    engine = object.__new__(PrivacyEngine)
    engine.language = "en"
    engine.score_threshold = 0.55
    engine.vault = vault

    class FakeAnalyzer:
        def analyze(self, *, text, language, score_threshold, entities=None):
            alias_start = text.index(existing_alias)
            email_start = text.index("alice@example.com")
            return [
                SimpleNamespace(
                    start=alias_start,
                    end=alias_start + len(existing_alias),
                    score=0.99,
                    entity_type="PERSON",
                ),
                SimpleNamespace(
                    start=email_start,
                    end=email_start + len("alice@example.com"),
                    score=0.90,
                    entity_type="EMAIL_ADDRESS",
                ),
            ]

    engine.analyzer = FakeAnalyzer()
    FakeAnalyzer.get_supported_entities = lambda self, language=None: ["PERSON", "EMAIL_ADDRESS"]
    source = f"Contact {existing_alias} at alice@example.com."
    sanitized = engine.sanitize(source)

    assert sanitized.startswith(f"Contact {existing_alias} at ")
    assert "alice@example.com" not in sanitized
    assert engine.rehydrate(sanitized) == f"Contact Alice Example at alice@example.com."


def test_missing_spacy_model_is_refused_not_downloaded(monkeypatch):
    import spacy.cli
    import spacy.util
    from pathlib import Path

    def no_download(*args, **kwargs):
        raise AssertionError("spaCy model download attempted at runtime")

    monkeypatch.setattr(spacy.util, "is_package", lambda name: False)
    monkeypatch.setattr(spacy.cli, "download", no_download)
    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    vault = AliasVault(connection=sqlite3.connect(":memory:"), encoded_key=key)

    with pytest.raises(RuntimeError, match="en_core_web_lg"):
        PrivacyEngine(Path(__file__).resolve().parent.parent / "nlp.yaml", vault=vault)


def test_secret_filter_removes_common_tokens_and_assignments():
    text = "key sk-or-v1-abcdefghijklmnopqrstuvwx ghp_" + "a" * 36 + " password=hunter2secret ok"
    out = PrivacyEngine.remove_high_confidence_secrets(text)
    assert "abcdefghijklmnop" not in out and "hunter2secret" not in out
    assert out.endswith("ok")


def test_portuguese_nif_checksum():
    from privacy import _nif_valid

    assert _nif_valid("123456789")
    assert not _nif_valid("123456788")
    assert not _nif_valid("12345678")


def test_portuguese_text_is_pseudonymized():
    from pathlib import Path

    pytest.importorskip("spacy")
    import spacy.util

    if not spacy.util.is_package("pt_core_news_lg"):
        pytest.skip("pt_core_news_lg not installed")
    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    vault = AliasVault(connection=sqlite3.connect(":memory:"), encoded_key=key)
    engine = PrivacyEngine(
        Path(__file__).resolve().parent.parent / "nlp.yaml", languages=["en", "pt"], vault=vault
    )
    out = engine.sanitize("João Silva, NIF 123456789, tel 912 345 678, joao@exemplo.pt")
    for leaked in ("João", "123456789", "912 345 678", "joao@exemplo.pt"):
        assert leaked not in out


def test_urls_orgs_dates_and_postcodes_are_not_aliased():
    from pathlib import Path

    import spacy.util

    if not (spacy.util.is_package("en_core_web_lg") and spacy.util.is_package("pt_core_news_lg")):
        pytest.skip("spaCy models not installed")
    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    vault = AliasVault(connection=sqlite3.connect(":memory:"), encoded_key=key)
    engine = PrivacyEngine(
        Path(__file__).resolve().parent.parent / "nlp.yaml", languages=["en", "pt"], vault=vault
    )
    text = "Nizoral na Auchan (https://www.auchan.pt/x?q=a%20b) a 2026-11-08, entrega em Portugal, código postal 4000-001 Porto."
    assert engine.sanitize(text) == text
    out = engine.sanitize("Moro na Rua das Flores 12, joao@exemplo.pt")
    assert "Rua das Flores" not in out and "joao@exemplo.pt" not in out
