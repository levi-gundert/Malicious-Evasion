import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
from extractor.triage.transport import bounded_request


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        try:
            if self.path == "/retry":
                self.send_response(503)
                self.end_headers()
                return
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            if self.path == "/slow":
                for _ in range(40):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.1)
            elif self.path == "/large":
                self.wfile.write(b"a" * 4096)
            else:
                self.wfile.write(b'{"ok":true}')
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass


@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()
    thread.join()


def test_normal_response(server):
    assert bounded_request("GET", server + "/ok", {}, timeout=5).json() == {"ok": True}


@pytest.mark.parametrize("path", ["/slow", "/retry"])
def test_total_deadline_includes_streaming_and_retries(server, path):
    start = time.monotonic()
    with pytest.raises(requests.Timeout):
        bounded_request("GET", server + path, {}, timeout=0.7, retries=5)
    assert time.monotonic() - start < 2


def test_streamed_size_limit_without_content_length(server):
    with pytest.raises(requests.RequestException):
        bounded_request("GET", server + "/large", {}, timeout=5, max_bytes=1024)


def test_redirect_does_not_forward_credentials(server):
    with pytest.raises(requests.RequestException):
        bounded_request(
            "GET", server + "/redirect", {"Authorization": "synthetic"}, timeout=5
        )
