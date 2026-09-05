#!/usr/bin/env bash
set -euo pipefail

# Install only optional competition tooling. Run as the normal user; Homebrew
# intentionally refuses root installs on macOS.
MODE="${1:-check}"
TOOLS=(nmap tshark exiftool binwalk 7zz zbarimg tesseract magick john sqlmap)

if [[ "$MODE" == "check" ]]; then
  for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then printf '[+] %s\n' "$tool"; else printf '[-] %s\n' "$tool"; fi
  done
  exit 0
fi

[[ "$MODE" == "install" ]] || { echo "Usage: $0 [check|install]" >&2; exit 2; }

if [[ "$(uname -s)" == "Darwin" ]]; then
  command -v brew >/dev/null 2>&1 || { echo "Homebrew is required: https://brew.sh" >&2; exit 1; }
  [[ "$(id -u)" -ne 0 ]] || { echo "Run this script as your normal user, not root." >&2; exit 1; }
  brew install nmap wireshark exiftool binwalk sevenzip zbar tesseract imagemagick john-jumbo sqlmap
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y nmap tshark libimage-exiftool-perl binwalk 7zip zbar-tools tesseract-ocr imagemagick john sqlmap
else
  echo "Unsupported package manager; install optional tools manually." >&2
  exit 1
fi

"$0" check
