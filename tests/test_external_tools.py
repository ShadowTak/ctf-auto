import json
import unittest
from unittest.mock import patch

from core import external_tools


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="fixture" version="1.2"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class ExternalToolTests(unittest.TestCase):
    def test_normalize_tools_is_allowlisted_and_deterministic(self):
        self.assertEqual(
            external_tools.normalize_tools("ffuf, nmap,ffuf,sqlmap,r2,7z"),
            ("ffuf", "nmap", "sqlmap", "radare2", "7zz"),
        )

    def test_nmap_command_and_xml_evidence(self):
        mocked = {
            "status": "completed",
            "stdout": NMAP_XML,
            "stderr": "",
            "elapsed_ms": 12.3,
        }
        with patch("core.external_tools.shutil.which", return_value="/bin/nmap"), \
                patch("core.external_tools._run", return_value=mocked) as run:
            result = external_tools.run_nmap(
                "127.0.0.1", ports="80,8000-8010", service=True,
                scripts="http-title", timeout=5)
        command = run.call_args.args[0]
        self.assertIn("-oX", command)
        self.assertIn("80,8000-8010", command)
        self.assertEqual(result["services"][8080]["service"], "http")
        self.assertEqual(result["hosts"][0]["addresses"], ["127.0.0.1"])

    def test_ffuf_json_is_normalized_to_directory_results(self):
        payload = {
            "results": [{
                "input": {"FUZZ": "admin"},
                "url": "http://127.0.0.1:8080/admin",
                "status": 200,
                "length": 42,
                "words": 4,
                "lines": 2,
                "content-type": "text/html",
            }]
        }
        mocked = {"status": "completed", "stdout": json.dumps(payload),
                  "stderr": "", "elapsed_ms": 8.0}
        with patch("core.external_tools.shutil.which", return_value="/bin/ffuf"), \
                patch("core.external_tools.Path.is_file", return_value=True), \
                patch("core.external_tools._run", return_value=mocked) as run:
            result = external_tools.run_ffuf("http://127.0.0.1:8080")
        command = run.call_args.args[0]
        self.assertIn("FUZZ", command[command.index("-u") + 1])
        self.assertEqual(result["hits"][0]["path"], "admin")
        self.assertEqual(external_tools.ffuf_dir_results(result),
                         [("admin", 200, 42, "")])

    def test_missing_ffuf_is_a_reported_capability_not_a_crash(self):
        with patch("core.external_tools.shutil.which", return_value=None):
            result = external_tools.run_ffuf("http://127.0.0.1:8080")
        self.assertEqual(result["status"], "missing")
        self.assertEqual(result["hits"], [])

    def test_sqlmap_is_low_risk_and_shell_free(self):
        mocked = {"status": "completed", "stdout": "ok", "stderr": "",
                  "elapsed_ms": 4.0}
        with patch("core.external_tools.shutil.which", return_value="/bin/sqlmap"), \
                patch("core.external_tools._run", return_value=mocked) as run:
            result = external_tools.run_external_tool(
                "sqlmap", "http://127.0.0.1:8080", timeout=5)
        command = run.call_args.args[0]
        self.assertIn("--batch", command)
        self.assertIn("--level=1", command)
        self.assertIn("--risk=1", command)
        self.assertEqual(result["tool"], "sqlmap")
        self.assertNotIn(" ", command[0])

    def test_file_tool_dispatch_uses_argument_list(self):
        mocked = {"status": "completed", "stdout": "symbols", "stderr": "",
                  "elapsed_ms": 3.0}
        with patch("core.external_tools.shutil.which", return_value="/bin/r2"), \
                patch("core.external_tools.Path.is_file", return_value=True), \
                patch("core.external_tools._run", return_value=mocked) as run:
            result = external_tools.run_external_tool("r2", "fixture.bin", timeout=5)
        command = run.call_args.args[0]
        self.assertEqual(result["tool"], "radare2")
        self.assertIn("aaa;afl;izz;ii", command)
        self.assertEqual(command[-1], "fixture.bin")


if __name__ == "__main__":
    unittest.main()
