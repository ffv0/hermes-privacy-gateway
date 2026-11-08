import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

from proxy import Rehydrator, make_server

ALIAS = "[PERSON_" + "A" * 32 + "]"


class Engine:
    fail = False
    vault = SimpleNamespace(rehydrate=lambda t: t.replace(ALIAS, "Alice"))

    def sanitize_model_content(self, value):
        if self.fail:
            raise RuntimeError("boom")
        return json.loads(json.dumps(value).replace("Alice", ALIAS))


def start(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def setup(stream=False):
    seen = []

    class Up(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_POST(self):
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            if stream:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for part in ["Hi [PER", "SON_" + "A" * 32, "] ok"]:
                    self.wfile.write(b"data: " + json.dumps({"choices": [{"index": 0, "delta": {"content": part}}]}).encode() + b"\n\n")
                self.wfile.write(b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n')
            else:
                body = json.dumps({"choices": [{"message": {"content": f"Hi {ALIAS}"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

    up, engine = start(Up), Engine()
    proxy = make_server(engine, f"http://127.0.0.1:{up.server_port}", 0)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    return seen, engine, f"http://127.0.0.1:{proxy.server_port}"


def post(url, payload):
    req = urllib.request.Request(url + "/v1/chat/completions", json.dumps(payload).encode(), {"Content-Type": "application/json"})
    return urllib.request.urlopen(req)


def test_sanitizes_request_and_rehydrates_response():
    seen, _, url = setup()
    out = json.load(post(url, {"messages": [{"role": "user", "content": "I am Alice"}]}))
    assert ALIAS in seen[0]["messages"][0]["content"] and "Alice" not in json.dumps(seen[0])
    assert out["choices"][0]["message"]["content"] == "Hi Alice"


def test_fail_closed_when_filter_fails():
    seen, engine, url = setup()
    engine.fail = True
    try:
        post(url, {"messages": [{"role": "user", "content": "I am Alice"}]})
        raise AssertionError("request should have been blocked")
    except urllib.error.HTTPError as e:
        assert e.code == 502
    assert seen == []


def test_unknown_shape_and_images_are_blocked():
    seen, _, url = setup()
    for bad in ({"foo": "Alice"}, {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}]}):
        try:
            post(url, bad)
            raise AssertionError("should be blocked")
        except urllib.error.HTTPError as e:
            assert e.code == 502
    assert seen == []


def test_streaming_alias_split_across_chunks():
    _, _, url = setup(stream=True)
    text = ""
    for line in post(url, {"messages": [{"role": "user", "content": "x"}], "stream": True}):
        if line.startswith(b"data: {"):
            text += "".join(c["delta"].get("content", "") for c in json.loads(line[5:])["choices"])
    assert text == "Hi Alice ok"


def test_rehydrator_flushes_unterminated_bracket():
    r = Rehydrator(lambda t: t)
    assert r.feed("see [abc") == "see " and r.flush() == "[abc"
