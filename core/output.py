"""Output helpers — colors, sections, and a Report collector."""
import os
import sys
import time
from datetime import datetime

try:
    _IS_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
except Exception:
    _IS_TTY = False


def _c(code, text):
    if not _IS_TTY:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def dim(t):   return _c("90", str(t))
def bold(t):  return _c("1", str(t))
def info(t):  return _c("96", str(t))    # cyan
def ok(t):    return _c("92", str(t))    # green
def warn(t):  return _c("93", str(t))    # yellow
def fail(t):  return _c("91", str(t))    # red
def flag(t):  return _c("95;1", str(t))  # magenta bold
def head(t):  return _c("1;94", str(t))  # bold blue


def section(title):
    print("\n" + head("═" * 58))
    print(head(f"  {title}"))
    print(head("═" * 58))


def ok_line(msg):
    print("  " + ok("[+]") + " " + msg)


def warn_line(msg):
    print("  " + warn("[!]") + " " + msg)


def fail_line(msg):
    print("  " + fail("[-]") + " " + msg)


def info_line(msg):
    print("  " + info("[*]") + " " + msg)


def flag_line(msg):
    print("  " + flag("🏁") + " " + flag(str(msg)))


class Report:
    """Collects everything printed into a timestamped report file."""

    def __init__(self):
        self.lines = []
        self.started = datetime.now()

    def add(self, line=""):
        # strip ANSI codes for the file copy
        import re
        clean = re.sub(r"\x1b\[[0-9;]*m", "", str(line))
        self.lines.append(clean)

    def save(self, outdir="reports"):
        os.makedirs(outdir, exist_ok=True)
        path = os.path.join(outdir, self.started.strftime("%Y%m%d_%H%M%S") + ".txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.lines))
        return path


class Progress:
    """Minimal threaded progress counter."""

    def __init__(self, total, desc="", width=40):
        self.total = max(total, 1)
        self.done = 0
        self.desc = desc
        self.width = width
        self._last_len = 0

    def tick(self, n=1):
        self.done += n
        self.render()

    def render(self):
        if not _IS_TTY:
            return
        pct = min(self.done / self.total, 1.0)
        filled = int(self.width * pct)
        bar = "#" * filled + "." * (self.width - filled)
        line = f"\r  {self.desc} [{bar}] {self.done}/{self.total}"
        sys.stdout.write(line + " " * max(self._last_len - len(line), 0))
        sys.stdout.flush()
        self._last_len = len(line)

    def finish(self):
        if _IS_TTY:
            sys.stdout.write("\n")
            sys.stdout.flush()


def spinner_ctx(desc):
    """Context manager that shows a spinner while a task runs."""
    import threading

    if not _IS_TTY:
        print(f"  {desc} ...")
        class _N:
            def __enter__(self): return self
            def __exit__(self, *a): pass
        return _N()

    stop = threading.Event()
    chars = "|/-\\"

    def _spin():
        i = 0
        while not stop.is_set():
            sys.stdout.write(f"\r  {desc} {chars[i % 4]} ")
            sys.stdout.flush()
            i += 1
            time.sleep(0.1)

    t = threading.Thread(target=_spin, daemon=True)
    t.start()

    class _Ctx:
        def __enter__(self): return self
        def __exit__(self, *a):
            stop.set()
            sys.stdout.write("\r" + " " * (len(desc) + 6) + "\r")
            sys.stdout.flush()

    return _Ctx()
