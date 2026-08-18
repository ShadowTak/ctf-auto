"""Exercise the network -> web auto chain against the in-process server."""
import sys
import threading
import time

sys.path.insert(0, ".")
import test_server as ts
import modules.network.nmap as nmap_mod
from modules.network.scanner import run_network
from modules.web.scanner import run_web

httpd = ts.ThreadingHTTPServer((ts.HOST, ts.PORT), ts.Handler)
t = threading.Thread(target=httpd.serve_forever, daemon=True)
t.start()
time.sleep(0.5)

# simulate a port scan result including the test port
orig = nmap_mod.scan_host

def fake_scan(host, ports=None, workers=256):
    return {ts.PORT: {"service": "http", "info": "test server"}}

nmap_mod.scan_host = fake_scan

flags = run_network("127.0.0.1", chain_to_web=run_web)
print()
print("=== CHAIN FLAGS ===")
for f in flags:
    print("FLAG:", f)
httpd.shutdown()
