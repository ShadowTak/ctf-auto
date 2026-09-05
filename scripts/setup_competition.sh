#!/usr/bin/env bash
set -euo pipefail
CTF_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$CTF_ROOT"
if command -v uv >/dev/null 2>&1; then
  [[ -x .venv/bin/python ]] || uv venv --python 3.12 .venv
  uv pip install --python .venv/bin/python -r requirements-competition.lock.txt
else
  [[ -x .venv/bin/python ]] || python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements-competition.lock.txt
fi
.venv/bin/python -m playwright install chromium
./ctf doctor
