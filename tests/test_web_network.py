import io
import unittest

from modules.network import nmap
from modules.web.response_diff import fingerprint


NMAP_XML = b'''<?xml version="1.0"?>
<nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="box.local"/></hostnames><ports>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Werkzeug" version="3.0"/>
<script id="http-title" output="CTF service"/></port>
<port protocol="tcp" portid="22"><state state="closed"/></port>
</ports></host></nmaprun>'''


class WebNetworkTests(unittest.TestCase):
    def test_nmap_xml_inventory(self):
        result = nmap.scan_xml(io.BytesIO(NMAP_XML))
        self.assertIn(8080, result)
        self.assertEqual(result[8080]["service"], "http")
        self.assertIn("Werkzeug", result[8080]["info"])
        self.assertEqual(result[8080]["scripts"][0]["id"], "http-title")
        self.assertNotIn(22, result)

    def test_fingerprint_is_stable_for_dynamic_values(self):
        class Response:
            status = 200
            body = b"<title>OK</title> user 12345 token abcdef0123456789"
            headers = {"content-type": "text/html; charset=utf-8"}
            text = body.decode()

        first = fingerprint(Response())
        Response.body = b"<title>OK</title> user 67890 token fedcba9876543210"
        Response.text = Response.body.decode()
        second = fingerprint(Response())
        self.assertEqual(first["hash"], second["hash"])


if __name__ == "__main__":
    unittest.main()
