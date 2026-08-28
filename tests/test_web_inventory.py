import unittest

from modules.web.parameter_inventory import inventory


class WebInventoryTests(unittest.TestCase):
    def test_html_forms_and_query_params(self):
        result = inventory(
            '<form action="/login" method="post"><input name="user">'
            '<input name="pass"></form><a href="/view?id=3">x</a>',
            "text/html", "http://target/")
        self.assertEqual(result["kind"], "html")
        self.assertEqual(result["forms"][0]["method"], "POST")
        self.assertIn("user", result["field_names"])
        self.assertIn("id", result["query_params"])

    def test_json_nested_fields(self):
        result = inventory('{"data":{"nonce":"abc","items":[{"id":1}]}}',
                           "application/json", "http://target/api")
        names = {field["name"] for field in result["fields"]}
        self.assertIn("nonce", names)
        self.assertIn("id", names)

    def test_javascript_params(self):
        result = inventory('fetch("/api?q=test&token=x")', "application/javascript")
        self.assertIn("q", result["field_names"])
        self.assertIn("token", result["field_names"])


if __name__ == "__main__":
    unittest.main()
