"""Run the local test server in a thread, then exercise the web scanner."""
import sys
import threading
import time

sys.path.insert(0, ".")
import test_server as ts
from modules.web.scanner import run_web

httpd = ts.ThreadingHTTPServer((ts.HOST, ts.PORT), ts.Handler)
t = threading.Thread(target=httpd.serve_forever, daemon=True)
t.start()
time.sleep(0.5)

flags = run_web(f"http://{ts.HOST}:{ts.PORT}")
print()
print("=== RESULT FLAGS ===")
for f in flags:
    print("FLAG:", f)
httpd.shutdown()
