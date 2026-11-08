#!/usr/bin/env python3
"""Fail-closed local PII proxy for OpenAI-compatible APIs (e.g. OpenRouter).

Point the client at http://127.0.0.1:PORT (same path as upstream). Requests are
pseudonymized with PrivacyEngine before leaving the machine; aliases in responses
are restored locally. If sanitizing fails for any reason the request is NOT
forwarded (HTTP 502). Stdlib HTTP only, binds to 127.0.0.1.

Env: HERMES_PRIVACY_GATEWAY_KEY (required), PRIVACY_PROXY_PORT (8788),
PRIVACY_PROXY_UPSTREAM (https://openrouter.ai), PRIVACY_PROXY_DB, PRIVACY_PROXY_LANGUAGES (en,pt).
"""
from __future__ import annotations

import http.client
import json
import os
import re
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from privacy import contains_non_text_model_content

CONTENT_KEYS = ("messages", "input", "instructions", "prompt", "system")
FORWARD_HEADERS = {"authorization", "content-type", "accept", "user-agent", "http-referer", "x-title"}
_MAX_PARTIAL_ALIAS = 80  # "[" + kind + "_" + 32 hex + "]" stays well below this


class Rehydrator:
    """Restores aliases in a text stream, holding back a possibly split alias."""

    def __init__(self, rehydrate):
        self._rehydrate, self._pending = rehydrate, ""

    def feed(self, text: str) -> str:
        text = self._pending + text
        cut = text.rfind("[")
        if cut != -1 and "]" not in text[cut:] and len(text) - cut < _MAX_PARTIAL_ALIAS:
            text, self._pending = text[:cut], text[cut:]
        else:
            self._pending = ""
        return self._rehydrate(text)

    def flush(self) -> str:
        text, self._pending = self._pending, ""
        return self._rehydrate(text)


def make_server(engine, upstream: str, port: int = 8788, host: str = "127.0.0.1"):
    up = urlsplit(upstream)
    lock = threading.Lock()  # one analysis at a time: bounds spaCy memory

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # never log bodies
            sys.stderr.write("%s %s\n" % (self.command, self.path.split("?")[0]))

        def _fail(self, code: int, msg: str):
            body = json.dumps({"error": {"message": msg, "type": "privacy_proxy"}}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _sanitize(self, raw: bytes) -> bytes:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("body is not a JSON object")
            roots = [k for k in CONTENT_KEYS if k in data]
            if not roots:
                raise ValueError("unrecognized request shape")
            for key in roots:
                if contains_non_text_model_content(data[key]):
                    raise ValueError("non-text content (image/audio/file) is not allowed")
                with lock:
                    data[key] = engine.sanitize_model_content(data[key])
            return json.dumps(data).encode()

        def _forward(self, body: bytes | None):
            headers = {k: v for k, v in self.headers.items() if k.lower() in FORWARD_HEADERS}
            headers["Accept-Encoding"] = "identity"
            conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(up.netloc, timeout=600)
            try:
                conn.request(self.command, self.path, body=body, headers=headers)
                resp = conn.getresponse()
            except Exception:
                conn.close()
                return self._fail(502, "upstream unreachable")
            try:
                ctype = resp.getheader("Content-Type", "")
                self.send_response(resp.status)
                self.send_header("Content-Type", ctype)
                self.send_header("Connection", "close")
                if "text/event-stream" in ctype:
                    self.end_headers()
                    self._stream(resp)
                else:
                    payload = self._rehydrate_json(resp.read())
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
            finally:
                conn.close()

        def _rehydrate_json(self, raw: bytes) -> bytes:
            try:
                data = json.loads(raw)
                for choice in data.get("choices", []):
                    msg = choice.get("message") or {}
                    for f in ("content", "reasoning"):
                        if isinstance(msg.get(f), str):
                            msg[f] = engine.vault.rehydrate(msg[f])
                return json.dumps(data).encode()
            except Exception:
                return raw  # aliases stay visible; nothing private is sent upstream

        def _stream(self, resp):
            bufs: dict = {}  # (choice index, field) -> Rehydrator
            for line in resp:
                if line.startswith(b"data:") and b"[DONE]" not in line:
                    try:
                        chunk = json.loads(line[5:])
                        for choice in chunk.get("choices", []):
                            delta, idx = choice.get("delta") or {}, choice.get("index", 0)
                            for f in ("content", "reasoning"):
                                rb = bufs.setdefault((idx, f), Rehydrator(engine.vault.rehydrate))
                                text = rb.feed(delta[f]) if isinstance(delta.get(f), str) else ""
                                if choice.get("finish_reason"):
                                    text += rb.flush()
                                if f in delta or text:
                                    delta[f] = text
                            choice["delta"] = delta
                        line = b"data: " + json.dumps(chunk).encode() + b"\n"
                    except Exception:
                        pass
                self.wfile.write(line)
                self.wfile.flush()

        def do_GET(self):
            self._forward(None)

        def do_POST(self):
            try:
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                body = self._sanitize(raw)
            except Exception as exc:
                sys.stderr.write("BLOCKED: %s\n" % type(exc).__name__)
                return self._fail(502, "privacy filter failed or rejected the request; nothing was sent")
            self._forward(body)

    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    from privacy import PrivacyEngine
    from vault import AliasVault

    here = Path(__file__).resolve().parent
    db = Path(os.environ.get("PRIVACY_PROXY_DB", "~/.hermes/privacy-proxy/vault.db")).expanduser()
    db.parent.mkdir(parents=True, exist_ok=True)
    langs = [s for s in os.environ.get("PRIVACY_PROXY_LANGUAGES", "en,pt").split(",") if s]
    engine = PrivacyEngine(
        here / "nlp.yaml",
        language=langs[0],
        languages=langs,
        vault=AliasVault(connection=sqlite3.connect(db, check_same_thread=False)),
    )
    engine.sanitize("warm up: John Smith")  # fail at startup, not on the first request
    port = int(os.environ.get("PRIVACY_PROXY_PORT", "8788"))
    server = make_server(engine, os.environ.get("PRIVACY_PROXY_UPSTREAM", "https://openrouter.ai"), port)
    sys.stderr.write("privacy-proxy on 127.0.0.1:%d\n" % port)
    server.serve_forever()


if __name__ == "__main__":
    main()
