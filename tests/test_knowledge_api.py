from __future__ import annotations

import json
import http.client
import threading
import unittest
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import tests.test_coding_retrieval as fixtures
from rabanito.indexer import index_all
from rabanito.security import index_security_catalog
from rabanito.server import RabanitoHandler


class KnowledgeApiTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CodingMemoryTests()
        self.fixture.setUp()
        self.fixture.memory()
        index_all(self.fixture.settings)
        project = Path(__file__).resolve().parents[1]
        for folder in ("config", "web"):
            (self.fixture.root / folder).mkdir(exist_ok=True)
        (self.fixture.root / "config/security_catalog.json").write_bytes((project / "config/security_catalog.json").read_bytes())
        for name in ("cyber.js", "knowledge.js"):
            (self.fixture.root / "web" / name).write_bytes((project / "web" / name).read_bytes())
        index_security_catalog(self.fixture.settings)

    def tearDown(self):
        self.fixture.tearDown()

    @contextmanager
    def server(self):
        class Handler(RabanitoHandler):
            settings = self.fixture.settings
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def post(self, origin, path, payload, extra=None):
        headers = {"Origin": origin, "Content-Type": "application/json"} | (extra or {})
        return urlopen(Request(origin + path, data=json.dumps(payload).encode(), headers=headers, method="POST"), timeout=10)

    def test_api_recovers_actual_fixture_experience_and_security_catalog_with_citations(self):
        with self.server() as origin:
            with self.post(origin, "/api/coding/similar", {"q": "rollback", "technology": "Python", "max_chars": 900}) as response:
                result = json.load(response)
            self.assertEqual(len(result["results"]), 1)
            self.assertLessEqual(result["used_chars"], 900)
            self.assertNotIn(str(self.fixture.root), json.dumps(result))
            with self.post(origin, "/api/security/search", {"q": "MFA"}) as response:
                catalog = json.load(response)
            self.assertIn("NIST-800-63B-4", {r["id"] for r in catalog["results"]})
            with self.post(origin, "/api/coding/patterns", {}) as response:
                self.assertEqual(json.load(response)["patterns"], [])

    def test_private_queries_require_post_same_origin_and_strict_types(self):
        with self.server() as origin:
            cases = [("GET", "/api/coding/similar?q=private", {}, {}, 405),
                     ("POST", "/api/coding/similar", {"q": "rollback"}, {"Origin": "https://external.invalid"}, 403),
                     ("POST", "/api/coding/similar", {"q": None}, {}, 400),
                     ("POST", "/api/coding/similar", {"q": "rollback", "max_chars": None}, {}, 400),
                     ("POST", "/api/coding/patterns", {"project": ["invalid"]}, {}, 400)]
            for method, path, payload, headers, expected in cases:
                with self.subTest(path=path, payload=payload), self.assertRaises(HTTPError) as caught:
                    response = urlopen(origin + path) if method == "GET" else self.post(origin, path, payload, headers)
                    response.close()
                self.assertEqual(caught.exception.code, expected)
                caught.exception.close()

    def test_typed_graph_rejects_query_parameters_and_fragments(self):
        with self.server() as origin:
            port = int(origin.rsplit(":", 1)[1])
            for target in ("/api/knowledge-graph?private=1", "/api/knowledge-graph;private", "/api/knowledge-graph#private"):
                with self.subTest(target=target):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                    try:
                        connection.request("POST", target, body=b"{}", headers={
                            "Origin": origin,
                            "Content-Type": "application/json",
                            "Content-Length": "2",
                        })
                        response = connection.getresponse()
                        self.assertEqual(response.status, 400)
                        self.assertEqual(json.loads(response.read()), {"error": "invalid_graph_request_url"})
                    finally:
                        connection.close()

    def test_module_asset_is_fixed_local_javascript_and_traversal_is_not_served(self):
        with self.server() as origin:
            with urlopen(origin + "/assets/knowledge.js") as response:
                self.assertIn("text/javascript", response.headers["Content-Type"])
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertIn(b"startKnowledge", response.read())
            with self.assertRaises(HTTPError) as caught:
                urlopen(origin + "/assets/%2e%2e/config/settings.json")
            self.assertEqual(caught.exception.code, 404)
            caught.exception.close()


if __name__ == "__main__":
    unittest.main()
