#!/usr/bin/env bash
set -euo pipefail

# Install only optional competition tooling. Run as the normal user; Homebrew
# intentionally refuses root installs on macOS.
MODE="${1:-check}"
# steghide is no longer packaged for current Homebrew; stegseek is a
# maintained steghide fork that extracts and cracks the same payloads.
TOOLS=(nmap tshark exiftool binwalk foremost 7zz zbarimg tesseract magick john
       sqlmap ffuf gobuster steghide stegseek zsteg ffmpeg radare2)

if [[ "$MODE" == "check" ]]; then
  for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then printf '[+] %s\n' "$tool"; else printf '[-] %s\n' "$tool"; fi
  done
  exit 0
fi

if [[ "$MODE" == "install-steghide" ]]; then
  # Build stegseek (steghide-compatible) into a user prefix: libmcrypt is gone
  # from Homebrew, so it is built first, then stegseek is linked against it.
  PREFIX="${PREFIX:-$HOME/.local/ctf-tools}"
  command -v brew >/dev/null 2>&1 || { echo "Homebrew is required" >&2; exit 1; }
  brew install mhash jpeg-turbo zlib cmake >/dev/null
  WORK="$(mktemp -d)"; mkdir -p "$PREFIX"
  ( cd "$WORK"
    curl -sSL -o mcrypt.tgz https://downloads.sourceforge.net/project/mcrypt/Libmcrypt/2.5.8/libmcrypt-2.5.8.tar.gz
    tar xzf mcrypt.tgz && cd libmcrypt-2.5.8
    # Old config.sub cannot name modern Apple triples; take automake's copy.
    cp "$(ls /opt/homebrew/Cellar/automake/*/share/automake-*/config.sub | head -1)" config.sub
    cp "$(ls /opt/homebrew/Cellar/automake/*/share/automake-*/config.guess | head -1)" config.guess
    chmod +x config.sub config.guess
    ./configure --prefix="$PREFIX" --disable-posix-threads --build="$(./config.guess)" \
      --host="$(./config.guess)" \
      CFLAGS="-O2 -Wno-implicit-function-declaration -Wno-int-conversion \
-Wno-incompatible-pointer-types -Wno-pointer-sign -Wno-implicit-int -Wno-return-type -Wno-format"
    make -j4 && make install
    cd "$WORK" && git clone --depth 1 https://github.com/RickdeJager/stegseek.git
    cd stegseek && mkdir -p build && cd build
    cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="-I/opt/homebrew/include -I$PREFIX/include" \
      -DCMAKE_C_FLAGS="-I/opt/homebrew/include -I$PREFIX/include" \
      -DCMAKE_EXE_LINKER_FLAGS="-L/opt/homebrew/lib -L$PREFIX/lib" ..
    make -j4
  )
  cp "$WORK/stegseek/build/src/stegseek" "$PREFIX/bin/stegseek"
  ln -sf "$PREFIX/bin/stegseek" /opt/homebrew/bin/stegseek 2>/dev/null || true
  rm -rf "$WORK"
  echo "stegseek installed: $PREFIX/bin/stegseek"
  "$0" check
  exit 0
fi

[[ "$MODE" == "install" ]] || { echo "Usage: $0 [check|install|install-steghide]" >&2; exit 2; }

if [[ "$(uname -s)" == "Darwin" ]]; then
  command -v brew >/dev/null 2>&1 || { echo "Homebrew is required: https://brew.sh" >&2; exit 1; }
  [[ "$(id -u)" -ne 0 ]] || { echo "Run this script as your normal user, not root." >&2; exit 1; }
  brew install nmap wireshark exiftool binwalk foremost sevenzip zbar tesseract \
    imagemagick john-jumbo sqlmap ffuf gobuster stegseek radare2
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y nmap tshark libimage-exiftool-perl binwalk foremost 7zip \
    zbar-tools tesseract-ocr imagemagick john sqlmap ffuf gobuster radare2
else
  echo "Unsupported package manager; install optional tools manually." >&2
  exit 1
fi

"$0" check
