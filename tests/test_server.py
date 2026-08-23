"""Unit tests for FastAPI REST API endpoints."""
import os
import tempfile
import unittest
from PIL import Image

try:
    from fastapi.testclient import TestClient
    from lensint.server import app
    # Test instantiating client to verify httpx is functional
    _test_client = TestClient(app)
    HAS_SERVER_TEST_DEPS = True
except Exception:
    HAS_SERVER_TEST_DEPS = False
    TestClient = None
    app = None


@unittest.skipUnless(HAS_SERVER_TEST_DEPS, "FastAPI or TestClient (httpx) dependencies not available")
class TestServerModule(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.tmp_dir = tempfile.mkdtemp()
        self.img_path = os.path.join(self.tmp_dir, "test.png")
        img = Image.new("RGB", (64, 64), color=(50, 100, 150))
        img.save(self.img_path, format="PNG")

    def tearDown(self):
        if os.path.exists(self.img_path):
            try:
                os.remove(self.img_path)
            except OSError:
                pass
        if os.path.exists(self.tmp_dir):
            try:
                os.rmdir(self.tmp_dir)
            except OSError:
                pass

    def test_healthcheck(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("config", data)

    def test_serve_ui(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

    def test_analyze_image_json_endpoint(self):
        with open(self.img_path, "rb") as f:
            resp = self.client.post(
                "/api/analyze?geo_lookup=false&use_cache=false",
                files={"file": ("test.png", f, "image/png")}
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("overall_risk_level", data)
        self.assertIn("integrity", data)

    def test_cache_stats_and_delete(self):
        resp = self.client.get("/api/cache/stats")
        self.assertEqual(resp.status_code, 200)

        del_resp = self.client.delete("/api/cache")
        self.assertEqual(del_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
