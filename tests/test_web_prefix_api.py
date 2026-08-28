import unittest

from web_app import app


class WebPrefixApiTests(unittest.TestCase):
    def test_web_prefix_is_optional(self):
        client = app.test_client()
        response = client.post("/api/scan", json={"category": "web", "url": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn("job_id", response.get_json())

    def test_invalid_web_prefix_is_rejected(self):
        client = app.test_client()
        response = client.post("/api/scan", json={
            "category": "web", "url": "http://127.0.0.1:1", "prefix": "bad prefix!"
        })
        self.assertEqual(response.status_code, 200)
        job_id = response.get_json()["job_id"]
        status = client.get(f"/api/status/{job_id}").get_json()
        self.assertIn("Prefix must look like", status["error"])


if __name__ == "__main__":
    unittest.main()
