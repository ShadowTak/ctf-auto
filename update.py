#!/usr/bin/env python3
"""Safe project updater and optional capability installer.

Examples:
    python3 update.py --check
    python3 update.py --update --deps
    python3 update.py --all --pro
    python3 update.py --tools
    python3 update.py --browser

Git updates are fast-forward-only and refuse to overwrite a dirty worktree.
Optional OS tools are installed only when ``--install-tools`` is requested.
"""
import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable
TOOL_COMMANDS = {
    "exiftool": "exiftool",
    "identify": "identify",
    "zbarimg": "zbarimg",
    "tesseract": "tesseract",
    "steghide": "steghide",
    "zsteg": "zsteg",
    "binwalk": "binwalk",
    "nmap": "nmap",
    "tshark": "tshark",
}
BREW_PACKAGES = {
    "exiftool": "exiftool",
    "identify": "imagemagick",
    "zbarimg": "zbar",
    "steghide": "steghide",
    "binwalk": "binwalk",
}
PYTHON_MODULES = {
    "Crypto": "pycryptodome",
    "PIL": "Pillow",
    "playwright": "playwright",
    "sympy": "sympy",
    "fpylll": "fpylll",
    "z3": "z3-solver",
}


def command(args, check=False, capture=False):
    print("$ " + " ".join(args))
    return subprocess.run(args, cwd=ROOT, check=check,
                          text=True, capture_output=capture)


def git(*args, check=False, capture=True):
    return command(["git", *args], check=check, capture=capture)


def git_text(*args):
    result = git(*args)
    return result.stdout.strip() if result.returncode == 0 else ""


def repo_status():
    branch = git_text("branch", "--show-current") or "detached"
    commit = git_text("rev-parse", "--short", "HEAD") or "unknown"
    dirty = bool(git_text("status", "--porcelain"))
    return branch, commit, dirty


def check_python():
    print(f"Python: {sys.version.split()[0]} ({PYTHON})")
    for module, package in PYTHON_MODULES.items():
        state = "installed" if importlib.util.find_spec(module) else "missing"
        print(f"  {module:<12} {state:<9} ({package})")


def check_tools():
    print("External tools:")
    for label, binary in TOOL_COMMANDS.items():
        path = shutil.which(binary)
        print(f"  {label:<12} {'installed' if path else 'missing'}"
              + (f" ({path})" if path else ""))


def install_dependencies(pro=False):
    files = [ROOT / "requirements.txt"]
    if pro:
        files.append(ROOT / "requirements-pro.txt")
    for filename in files:
        if not filename.is_file():
            print(f"skip missing {filename}")
            continue
        result = command([PYTHON, "-m", "pip", "install", "-r", str(filename)],
                         capture=False)
        if result.returncode != 0:
            return False
    return True


def install_tools():
    """Best-effort Homebrew/Gem installer; never runs shell strings."""
    brew = shutil.which("brew")
    if brew and getattr(os, "geteuid", lambda: 1)() != 0:
        missing_packages = []
        for binary, package in BREW_PACKAGES.items():
            if not shutil.which(binary):
                missing_packages.append(package)
        if missing_packages:
            for package in sorted(set(missing_packages)):
                result = command([brew, "install", package])
                if result.returncode != 0:
                    print(f"warning: could not install Homebrew package {package}")
    elif brew:
        print("warning: Homebrew refuses root installs; run update.py as your normal user")
    else:
        print("warning: Homebrew not found; skipping OS packages")
    gem = shutil.which("gem")
    if gem and not shutil.which("zsteg") and getattr(os, "geteuid", lambda: 1)() != 0:
        result = command([gem, "install", "zsteg", "--no-document"])
        if result.returncode != 0:
            print("warning: zsteg installation failed")
    check_tools()


def install_browser():
    result = command([PYTHON, "-m", "playwright", "install", "chromium"])
    if result.returncode != 0:
        print("warning: Playwright Chromium installation failed")
    return result.returncode == 0


def update_git():
    branch, commit, dirty = repo_status()
    if dirty:
        print("refusing git update: worktree has local changes")
        print("commit/stash them first; update.py never overwrites local work")
        return False
    if branch == "detached":
        print("refusing git update: HEAD is detached")
        return False
    remote = f"origin/{branch}"
    fetched = git("fetch", "--prune", "origin")
    if fetched.returncode != 0:
        return False
    remote_commit = git_text("rev-parse", remote)
    if not remote_commit:
        print(f"no remote branch found: {remote}")
        return False
    if remote_commit == git_text("rev-parse", "HEAD"):
        print(f"already up to date: {branch} {commit}")
        return True
    result = git("merge", "--ff-only", remote)
    if result.returncode != 0:
        print("fast-forward update unavailable; resolve branch history manually")
        return False
    print(f"updated {branch}: {commit} -> {git_text('rev-parse', '--short', 'HEAD')}")
    return True


def verify():
    files = [str(path) for path in ROOT.rglob("*.py")
             if ".git" not in path.parts and "__pycache__" not in path.parts]
    result = command([PYTHON, "-m", "py_compile", *files])
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Safely update CTF Auto")
    parser.add_argument("--check", action="store_true", help="show repo/dependency/tool status")
    parser.add_argument("--update", action="store_true", help="fast-forward from origin/<branch>")
    parser.add_argument("--deps", action="store_true", help="install requirements.txt")
    parser.add_argument("--pro", action="store_true", help="also install requirements-pro.txt")
    parser.add_argument("--tools", action="store_true", help="show external tool status")
    parser.add_argument("--install-tools", action="store_true", help="install optional OS tools")
    parser.add_argument("--browser", action="store_true", help="install Playwright Chromium")
    parser.add_argument("--all", action="store_true", help="update, install deps/tools and verify")
    args = parser.parse_args()
    if not any(vars(args).values()):
        args.check = True

    branch, commit, dirty = repo_status()
    print(f"Project: {ROOT}")
    print(f"Git: {branch} {commit} {'DIRTY' if dirty else 'clean'}")
    success = True
    if args.check or args.all:
        check_python()
        check_tools()
    if args.update or args.all:
        success = update_git() and success
    if args.deps or args.all:
        success = install_dependencies(pro=args.pro) and success
    if args.install_tools or args.all:
        install_tools()
    if args.browser or args.all:
        success = install_browser() and success
    if args.all:
        success = verify() and success
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
