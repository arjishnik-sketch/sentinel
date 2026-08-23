"""
Offline (loopback-only) proof that recon mines API routes out of a JavaScript
bundle even when the route is built from a TEMPLATE LITERAL that interpolates a
host prefix and/or a parameter value — the shape real single-page apps use:

    this.http.get(`${this.hostServer}/rest/products/search?q=${term}`)

Before, any captured string containing ``${…}`` was discarded wholesale, so the
one genuinely injectable Juice-Shop route was invisible to zero-oracle
discovery. The materializer now collapses the interpolation tokens and keeps the
static path skeleton, which is exactly what lets ``discover <url>`` reach an
SPA's real query surface. A stub HTTP server serves the bundle on loopback; no
external network is touched.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from app.security_graph.graph import SecurityGraph
from app.security_graph.recon.ingest import (
    _materialize_javascript_api_observations,
)


_JS_BUNDLE = b"""
class ProductService {
  constructor(){ this.hostServer = ''; }
  search(term){ return this.http.get(`${this.hostServer}/rest/products/search?q=${term}`); }
  plain(){ return this.http.get(`/rest/continue-code`); }
  external(){ return fetch(`https://evil.example.com/steal`); }
}
"""


class _JsBundleHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        return

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", str(len(_JS_BUNDLE)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(_JS_BUNDLE)


def _paths(graph):
    out = set()
    for endpoint in graph.endpoints.values():
        out.add(urlsplit(endpoint.url).path or "/")
    return out


def test_template_literal_route_is_materialized_same_origin_only():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JsBundleHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        js_url = f"{base}/main.js"
        graph = SecurityGraph()
        _materialize_javascript_api_observations(graph, base, [js_url])

        paths = _paths(graph)
        # The interpolated template-literal route is recovered...
        assert "/rest/products/search" in paths
        # ...alongside the plain root-relative route...
        assert "/rest/continue-code" in paths
        # ...and the cross-origin fetch is NOT materialized (same-origin guard).
        assert not any("evil.example.com" in e.url for e in graph.endpoints.values())

        # The recovered search route still carries its query parameter, so
        # injection discovery can harvest 'q' as an observed candidate.
        search = next(
            e.url for e in graph.endpoints.values()
            if urlsplit(e.url).path == "/rest/products/search"
        )
        assert "q=" in urlsplit(search).query
    finally:
        server.shutdown()
        server.server_close()
