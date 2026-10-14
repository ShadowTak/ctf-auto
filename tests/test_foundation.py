"""Foundation guarantees: target routing and the hard no-hang watchdog.

These cover the two pieces that make ``--category auto`` cover both the
"unpack an artifact" and the "scan a live service" sides of a competition,
and the deadline that stops a single direct scan from running forever.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import routing


def test_classify_existing_path(tmp_path):
    f = tmp_path / "challenge.bin"
    f.write_bytes(b"\x00\x01flag")
    assert routing.classify_target(str(f)) == "path"
    assert routing.classify_target(str(tmp_path)) == "path"


def test_classify_url():
    assert routing.classify_target("http://10.10.10.5:8080/") == "url"
    assert routing.classify_target("https://ctf.example/chal") == "url"
    assert routing.classify_target("HTTP://Example.com") == "url"


def test_classify_host_ip_and_name():
    assert routing.classify_target("10.10.10.5") == "host"
    assert routing.classify_target("10.10.10.5:1337") == "host"
    assert routing.classify_target("scanme.nmap.org") == "host"
    assert routing.classify_target("target.htb:9001") == "host"


def test_classify_text_not_mistaken_for_host():
    # A crypto blob and a mistyped filename must not become a network scan.
    assert routing.classify_target("VlFTeFFSeVdSUmlC") == "text"
    assert routing.classify_target("cipher.txt") == "text"
    assert routing.classify_target("flag.enc") == "text"
    assert routing.classify_target("U2FsdGVkX1+ab/cd==") == "text"


def test_category_for_target_mapping(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    assert routing.category_for_target(str(f)) == ("batch", "path")
    assert routing.category_for_target("http://x/")[0] == "web"
    assert routing.category_for_target("10.0.0.1:22")[0] == "full"
    assert routing.category_for_target("AAAA")[0] == "crypto"


# --- watchdog -------------------------------------------------------------

def test_watchdog_default_deadlines():
    from core import watchdog
    # Network categories get a finite default; local compute stays uncapped
    # unless the operator sets one explicitly.
    assert watchdog.default_deadline("web", 0) > 0
    assert watchdog.default_deadline("full", 0) > 0
    assert watchdog.default_deadline("crypto", 0) == 0
    assert watchdog.default_deadline("crypto", 120) == 120
    assert watchdog.default_deadline("web", 30) == 30


def test_watchdog_raises_in_main_thread():
    from core import watchdog
    if os.name != "posix":
        pytest.skip("SIGALRM path is posix-only")
    start = time.monotonic()
    with pytest.raises(watchdog.Deadline):
        watchdog.arm(1, label="test")
        try:
            # A cooperative-free blocking wait: SIGALRM must break it.
            time.sleep(10)
        finally:
            watchdog.disarm()
    assert time.monotonic() - start < 5


def test_watchdog_disarm_prevents_backstop():
    # Arming then disarming must not force-exit the interpreter later.
    from core import watchdog
    watchdog.arm(1, label="test", grace=1)
    watchdog.disarm()
    time.sleep(2.5)  # past deadline+grace; a live backstop would os._exit here
    assert True


def test_watchdog_backstop_hard_exits_without_sigalrm():
    # Armed off the main thread, the SIGALRM layer is intentionally skipped, so
    # only the daemon backstop is in play. It must still force-exit a blocked
    # process. Run in a child so pytest survives the os._exit.
    script = (
        "import sys; sys.path.insert(0, %r)\n" % str(ROOT) +
        "import threading, time\n"
        "from core import watchdog\n"
        "def worker():\n"
        "    watchdog.arm(1, label='backstop', grace=1)\n"
        "    time.sleep(30)\n"
        "threading.Thread(target=worker).start()\n"
        "time.sleep(30)\n"
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True,
                          timeout=20)
    assert proc.returncode == 124, (proc.returncode, proc.stderr[-400:])
