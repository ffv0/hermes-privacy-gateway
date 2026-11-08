"""Hermes privacy-gateway plugin registration."""

from __future__ import annotations

import copy
import importlib.util
import logging
import threading
from pathlib import Path
from typing import Any


log = logging.getLogger("hermes.plugin.privacy-gateway")
_PLUGIN_DIR = Path(__file__).resolve().parent
_ENGINE: Any = None
_ENGINE_ERROR: Exception | None = None
_ENGINE_LOCK = threading.Lock()


def _config(ctx, key: str, default: Any) -> Any:
    return ctx.get_config(key, default=default)


def _get_engine(ctx):
    """Lazily import/load Presidio so plugin discovery remains lightweight."""
    global _ENGINE, _ENGINE_ERROR
    if _ENGINE is not None:
        return _ENGINE
    if _ENGINE_ERROR is not None:
        raise RuntimeError("privacy engine initialization previously failed") from _ENGINE_ERROR

    with _ENGINE_LOCK:
        if _ENGINE is not None:
            return _ENGINE
        if _ENGINE_ERROR is not None:
            raise RuntimeError("privacy engine initialization previously failed") from _ENGINE_ERROR

        try:
            if __package__:
                from .privacy import PrivacyEngine
            else:  # direct development import outside Hermes package loader
                from privacy import PrivacyEngine

            _ENGINE = PrivacyEngine(
                nlp_config_path=_PLUGIN_DIR / "nlp.yaml",
                language=str(_config(ctx, "language", "en")),
                languages=list(_config(ctx, "languages", ["en", "pt"]) or ["en", "pt"]),
                score_threshold=float(_config(ctx, "score_threshold", 0.55)),
                enable_langextract=bool(_config(ctx, "enable_langextract", False)),
                langextract_config_path=str(
                    _config(ctx, "langextract_config_path", "")
                ),
            )
        except Exception as exc:
            _ENGINE_ERROR = exc
            log.exception("privacy engine initialization failed")
            raise

        return _ENGINE


def register(ctx) -> None:
    """Register redaction middleware and local rehydration hooks."""

    # Constants/helpers are local imports so `hermes plugins doctor` can report
    # dependency issues cleanly after PM preparation, and basic source tests can
    # import this module without eagerly loading a large NLP stack. `.privacy`
    # does not import Presidio at module level, so the middleware below is
    # always registered; a missing Presidio blocks requests via _get_engine.
    if importlib.util.find_spec("presidio_analyzer") is None:
        log.error(
            "presidio-analyzer is not installed; privacy-gateway will block "
            "every model request until it is"
        )
    if __package__:
        from .privacy import (
            BLOCKED_TOOL_RESULT,
            blocked_content_for_key,
            contains_non_text_model_content,
        )
    else:  # direct development import outside Hermes package loader
        from privacy import (
            BLOCKED_TOOL_RESULT,
            blocked_content_for_key,
            contains_non_text_model_content,
        )

    def on_llm_request(**kwargs):
        content_keys = ("messages", "input", "instructions", "prompt")

        try:
            request = copy.deepcopy(kwargs["request"])
            engine = _get_engine(ctx)
            block_non_text = bool(_config(ctx, "block_non_text_content", True))
            found_content_root = False

            for key in content_keys:
                if key not in request:
                    continue
                found_content_root = True
                value = request[key]
                if block_non_text and contains_non_text_model_content(value):
                    request[key] = blocked_content_for_key(key)
                else:
                    request[key] = engine.sanitize_model_content(value)

            # An unfamiliar request shape cannot be sanitized safely: walking every
            # string can corrupt protocol IDs, while preserving unknown strings can
            # leak PII. Block it instead.
            if not found_content_root:
                request = {"messages": [{"role": "user", "content": "[PRIVACY_GATEWAY_BLOCKED_REQUEST]"}]}

        except Exception:
            # Best effort to fail closed inside our callback. Hermes itself documents
            # middleware failures as fail-open, which is why the README requires a
            # separate egress proxy/network policy for a hard boundary. Keep this
            # error path deliberately independent of Presidio/the vault.
            log.exception("privacy redaction failed; replacing model-bound content")
            try:
                raw = kwargs.get("request") or {}
                request = dict(raw) if isinstance(raw, dict) else {}
            except Exception:
                request = {}

            replaced = False
            for key in content_keys:
                if key in request:
                    request[key] = blocked_content_for_key(key)
                    replaced = True
            if not replaced:
                request = {"messages": [{"role": "user", "content": "[PRIVACY_GATEWAY_BLOCKED_REQUEST]"}]}

        return {
            "request": request,
            "source": "privacy-gateway",
            "reason": "local PII pseudonymization before provider execution",
        }

    def on_tool_request(**kwargs):
        tool_name = str(kwargs.get("tool_name", ""))
        allowlist = set(_config(ctx, "rehydrate_tool_allowlist", []) or [])

        # Secure default: no external/local tool receives plaintext merely because
        # the model emitted an alias. Users must name trusted tools explicitly.
        if tool_name not in allowlist:
            return None

        try:
            args = copy.deepcopy(kwargs["args"])
            engine = _get_engine(ctx)
            args = engine.rehydrate_tree(args)
        except Exception:
            # Leave aliases unresolved rather than sending guessed/partial plaintext.
            log.exception("tool argument rehydration failed; leaving aliases intact")
            try:
                args = copy.deepcopy(kwargs.get("args") or {})
            except Exception:
                args = {}

        return {
            "args": args,
            "source": "privacy-gateway",
            "reason": "locally resolve aliases for an explicitly allowlisted tool",
        }

    def on_tool_result(result: str, **kwargs):
        if not isinstance(result, str):
            return None
        try:
            return _get_engine(ctx).sanitize(result)
        except Exception:
            log.exception("tool-result redaction failed; withholding tool result")
            return BLOCKED_TOOL_RESULT

    def on_llm_output(response_text: str, **kwargs):
        if not isinstance(response_text, str):
            return None
        try:
            return _get_engine(ctx).rehydrate(response_text)
        except Exception:
            # The user seeing aliases is safer than a partial/incorrect reconstruction.
            log.exception("output rehydration failed; leaving aliases intact")
            return None

    ctx.register_middleware("llm_request", on_llm_request)
    ctx.register_middleware("tool_request", on_tool_request)
    ctx.register_hook("transform_tool_result", on_tool_result)
    ctx.register_hook("transform_llm_output", on_llm_output)
