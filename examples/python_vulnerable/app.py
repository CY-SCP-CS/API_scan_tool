"""Deliberately vulnerable local demo. Never deploy this code."""
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


class ApiHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if self.path.startswith("/fetch"):
            url = query.get("url", [""])[0]
            # Intentional SSRF for scanner demonstration.
            with urllib.request.urlopen(url, timeout=3) as response:
                body = response.read().decode("utf-8", errors="replace")
            self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
            return
        self.send_response(404); self.end_headers()

    def log_message(self, *_):
        pass


class MarkerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"api_scan_marker_9f3a")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    threading.Thread(target=HTTPServer(("127.0.0.1", 9199), MarkerHandler).serve_forever, daemon=True).start()
    HTTPServer(("127.0.0.1", 9101), ApiHandler).serve_forever()
