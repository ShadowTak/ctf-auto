# 🚩 CTF Auto Recon & Solver

เครื่องมืออัตโนมัติสำหรับ CTF — สแกน เจาะ และหา **flag** ครอบคลุม 3 หมวดหลัก
+ **โหมด Auto Lab** สำหรับสแกนแลปใน redacted stack อัตโนมัติ

| หมวด | ความสามารถ |
|------|-----------|
| 🌐 **Web** | recon (headers/robots/tech), **keep-alive HTTP pool + retry** (dirbust เร็วหลายเท่า, ทน connection reset), directory brute-force (threaded, 545+ paths + API/actuator), SQLi / XSS / LFI / SSTI / Command Injection / open-redirect / SSRF fuzz (**fuzz ทุก endpoint + ลิงก์ที่มี query param**), **form POST fuzz** (SQLi auth-bypass / CMDi / SSTI / XSS ในทุก field), **blind boolean-based SQLi extraction** (extract flag ทีละตัวอักษรผ่าน oracle), **login brute-force** (THCTT WebAccessControl: common creds + 4-digit PIN 0000-9999, form + JSON endpoint, detect success จาก baseline), **asset & JS crawl**, **error-trigger 500 leak hunt**, **AES-CTR bit-flip attack**, **GraphQL introspection**, **JSON mass-assignment / NoSQLi probe** (`$ne`/`$gt` + token follow-up), **cookie forge**, **IDOR enumeration**, JWT attack, backup file & source disclosure (.git/.env/.bak), **shared soft-404 calibration**, flag scan |
| 🔐 **Crypto** | auto-detect & decode ทุกวิธี (base16/32/45/58/62/64/85, hex, binary, octal, morse, brainfuck, Ook!, **Malbolge**, ROT13/47, leet, gzip/zlib, file-magic sniff) + **beam-search chain-decode หลายชั้น** (แตกทุกเส้นทาง เก็บทุก flag — ผ่าน TCTT base85→base45 chain) + **custom-alphabet base-N** (Thai alphabet `ก-ฮ+๐-๙+0-9` แบบ THCTT New Base64, emoji base-100) + **emoji solver** (2-state → binary, unicode-offset 0x1F3F7, substitution word-matching) + **base62 case-recovery** (THCTT Bad62: enumerate case variants ต่อ chunk + flag-body scoring) + payload extraction หลัง label (`cipher:`/`cipher_hex:`) + classic ciphers (Caesar, **Vigenere auto-key: sweep + flag-prefix crib + per-char indexing**, Affine, Atbash, Railfence, **Bacon 0/1**, Playfair, Hill, Columnar, substitution solver ด้วย quadgram annealing) + RSA attacks (**auto-detect ไฟล์ n/e/c**, small-e, Wiener, Fermat, PEM/DER parser, **integer-only iroot**) + XOR (single/multi-byte, flag-prefix crib, **wordlist-key crib** แบบ THCTT) + **hash identify/crack + flag-template** (อ่าน prefix จากโจทย์ เช่น `picoCTF{<password>}` ได้) + **SHA-256 length extension attack** — เก็บ flag จาก **ทุก** ผล decode (ไม่ตัดด้วย ranking) |
| 🌍 **Network** | nmap port scan (socket fallback), banner grabbing, **pure-Python pcap/pcapng analyzer** (TCP reassembly, HTTP extraction, flag hunt ใน UDP/ICMP exfil), DNS recon (records / zone transfer / subdomain brute) |

### อัปเกรดล่าสุดสำหรับแลป

- Web เพิ่ม JWT `alg=none`/public-key confusion/embedded-JWK probes, GraphQL alias batching, numeric REST IDOR, internal SSRF/header-routing probes, archive upload traversal และ race-flow probe
- Web เพิ่ม XXE external-entity probe, JSON prototype-pollution follow-up และ CORS sensitive-endpoint check
- Crypto เพิ่ม structured JSON dispatcher สำหรับ RSA broadcast/common-modulus/CRT fault, ECDSA nonce reuse, DH/Pohlig–Hellman, LCG stream, stream/CTR/GCM nonce-reuse recovery, matrix autokey และ Playfair artifacts
- `lab_session.py` เลือกพอร์ต local จาก Colima เมื่อ API ส่ง vanity URL ที่เครื่องนี้เข้าถึงไม่ได้

### 🆕 รอบอัปเกรดล่าสุด (แข่งจริง edition)

**Crypto เพิ่มใหม่**
- **Factoring ladder**: trial division → Pollard p-1 → Pollard rho → FactorDB lookup (auto) — เสียบเข้า `crack_rsa` อัตโนมัติ
- **ECDLP solver**: point arithmetic เต็มรูปแบบ + **Smart's attack** (anomalous curve, p-adic lift บน Jacobian Z/p^2) + **singular curve DLP** (node/cusp) + BSGS fallback — เทส exhaustive 57k+ เคสผ่านหมด
- **TEA / XTEA / XXTEA** decryptors + key-sweep cracker (wordlist / repeated-byte / small-int keys)
- **Fernet token brute** (pure stdlib: HMAC verify -> AES-CBC)
- **PRNG recovery**: java.util.Random (2 outputs), glibc random() TYPE_3 seed brute, xorshift128+ (ใช้ z3 เมื่อลง `pip install z3-solver`), Python MT19937 timestamp-seed brute
- **Length extension ครบ MD5 / SHA-1 / SHA-256** (pure implementations, self-verified กับ stdlib)
- Classic เพิ่ม **Beaufort / Variant Beaufort / Gronsfeld** (hill-climb + simulated annealing + beam), **keyboard-shift**, **T9 multi-tap**, **Polybius**
- Structured JSON dispatcher เพิ่ม ECC fields (`p,a,b,gx,gy,qx,qy`) และ `{algorithm:"xtea",key,ciphertext}`
- **ไม่ force flag prefix ใดๆ** — decode ได้อะไรโชว์อย่างนั้น prefix ใช้เฉพาะเมื่อ artifact ระบุ format มาเอง
- **XOR crib แสดง plaintext ที่ถอดได้ตรงตัว** — ไม่ตัด/เติม `CTF{}` หรือ wrapper เอง; ผล crib แบบ heuristic จะแสดงเป็น `DECODE` และจะไม่ถูกนับเป็น flag จนกว่าจะยืนยัน prefix/key-period ได้
- **Evidence mode** — Web UI แยก `VERIFIED FLAG`, `CANDIDATE` และ raw `DECODE` พร้อม source, confidence และ evidence; legacy CLI/API ยังคืน `list[str]` ได้เหมือนเดิม
- **Decode trace** — ผลที่ได้จากการถอดจะแสดง method/path ที่ใช้ เช่น `base64 -> hex -> rot13`; solver จะตัดงาน classic/annealing ที่ไม่เกี่ยวกับ JSON/KDF/RSA parameter dump เพื่อให้ deterministic inputs เร็วขึ้น

**Crypto เพิ่มเติม**

- Finite-field math: CRT, Tonelli–Shanks, BSGS, Pohlig–Hellman และ DH private/shared-secret recovery พร้อม verification
- RSA: Franklin–Reiter related-message และ bounded univariate Coppersmith/small-root สำหรับ artifact ที่ระบุ polynomial หรือ known prefix
- Signatures: DER ECDSA/DSA parsing และ reused-nonce/private-key recovery
- Modern symmetric: AES CTR/CFB/OFB/GCM/EAX/CCM/OCB/SIV decryption เมื่อมี PyCryptodome, stream nonce reuse และ one-block GCM H/mask recovery
- Hash/KDF: PBKDF2 Django/modular format parsing และ bounded wordlist cracking; raw decoded plaintext ยังแสดงตรงตามผลจริง ไม่เติม prefix ใหม่

**Image forensics เพิ่มใหม่**

- `python3 run.py --category image --target suspicious.png` (ใช้ `picture` หรือ `pic` ก็ได้)
- ตรวจ magic/file-type mismatch, hash/entropy, PNG/JPEG/GIF/BMP/WebP/TIFF metadata, EXIF/XMP/comments/chunks, ASCII/UTF-16 strings, trailing/polyglot signatures และ raw embedded text
- ถอด candidate ที่เป็น base/hex/Unicode/chain ต่อจากข้อความในภาพ พร้อมแยก `VERIFIED` / `CANDIDATE` / raw decode ตามหลักฐาน
- ลอง LSB bit-plane จาก PNG/BMP และใช้ `exiftool`, `identify`, `strings`, `zbarimg`, `tesseract`, `steghide`, `zsteg`, `binwalk` เมื่อเครื่องมี โดยจะรายงานเครื่องมือที่ใช้และ output ดิบ
- Web UI มีแท็บ **Image** สำหรับอัปโหลดและดูผลแบบละเอียด; ไฟล์อัปโหลดถูกตั้งชื่อชั่วคราวแบบสุ่ม ไม่ใช้ชื่อไฟล์จากผู้ใช้เป็น path ตรงๆ

**Web เพิ่มใหม่**
- **Session controls**: `--cookie "k=v"`, `--header "K: V"` (ใส่ซ้ำได้), `--proxy http://127.0.0.1:8080`, `--timeout`, `--user-agent` — scan โจทย์ที่ต้อง login ก่อน / ผ่าน Burp ได้
- **UNION-based SQLi automation**: หา param -> นับ column (ORDER BY sweep) -> หา echo column -> exfil version/tables/flag columns + time-based blind probe
- **Flask session takeover**: decode -> brute `SECRET_KEY` (รองรับทั้ง Flask salt `cookie-session` และ raw itsdangerous salt, hmac/django-concat derivation) -> forge admin cookie -> hit protected paths (flask-unsign โดยไม่ต้อง pip)
- **CBC padding oracle** (Vaudenay + last-byte disambiguation) + IV bit-flip — หา encrypt/decrypt endpoints อัตโนมัติ
- **Deserialization probes**: Python pickle `__reduce__` payload + PHP object property tampering
- **403 bypass module**: XFF/X-Originating-IP/X-Remote-Addr/X-Custom-IP-Authorization + path tricks (`..;/`, `%2e`, `//`, trailing dot)
- **Upload bypass**: double extension, `.phtml/.phar/.php5`, GIF magic bytes -> webshell probe -> flag readout
- **SSTI -> RCE ladder**: Jinja2/Twig/Mako/ERB payloads หลังยืนยัน `{{7*7}}`
- **Cloud metadata SSRF**: AWS/GCP/Azure instance-metadata targets
- LFI เพิ่ม **php://filter** wrapper (base64 source read) และ data://

**รอบล่าสุด: nested-chain decoder + multithreaded crypto pipeline**
- Chain decode ถอดซ้อนได้ลึกขึ้น: เพิ่ม **XOR single-byte ใน chain** (hexxor / b64xor / xor1 layers) — `base64>hex>xor1>base64` แกะอัตโนมัติ
- Decoders เพิ่มใหม่: UUencode, quoted-printable, base32hex, ascii85, A1Z26, NATO phonetic, tap code, JWT payload layer
- **Multithread ทั้ง pipeline**: encodings (8 workers), chain beam expansion (parallel per branch), classic solver families (7 jobs concurrent), analyze_file (10 sections concurrent), TEA key sweep (16 workers), FactorDB lookup แท็กซ้อนกับ local factoring
- Speed fix หลังโปรไฟล์: `score_bytes` memoized + chi-square ผ่าน bytes.count (crib_attack 6.4M calls -> cache hit), repeating-XOR keylen cap, thread pool tuning — nested battery **101s -> 8s (14x)** 6/6 layers

**Fix สำคัญ**: pure-Python AES fallback เขียน key schedule ผิดตั้งแต่ต้น (RCON off-by-one + round key ใช้ word เดียว + padding ไม่มีเงื่อนไข) — pycryptodome ที่ install ไว้บัง bug นี้ไว้ทั้งหมด; ตอนนี้ pure path ผ่าน NIST FIPS-197 vectors ครบ AES-128/192/256

---

## 📦 ติดตั้ง (Installation)

### สิ่งที่ต้องมีก่อน (Prerequisites)

| ของ | ขั้นต่ำ | หมายเหตุ |
|-----|--------|---------|
| **Python** | 3.8+ (แนะนำ 3.10+) | ไม่ต้องติดตั้ง dependency ใดๆ — ใช้ stdlib ล้วน |
| **git** (optional) | — | ใช้ clone โค้ดจาก GitHub |
| **nmap** (optional) | — | ถ้าไม่มี โมดูล network จะใช้ socket scan ในตัวแทน |
| **pycryptodome** (optional) | — | ถ้าไม่มี โมดูล crypto สมัยใหม่ใช้ pure-Python แทน |

> ตรวจเวอร์ชัน Python:
> ```bash
> python3 --version   # ต้อง >= 3.8
> ```

### 🍎 macOS

**วิธีที่ 1 — ติดตั้ง Python (ถ้ายังไม่มี):**

```bash
# ตรวจก่อนว่ามี python3 ไหม
python3 --version

# ถ้าไม่มี → ติดตั้งผ่าน Homebrew (ต้องลง Homebrew ก่อน: https://brew.sh)
brew install python

# หรือดาวน์โหลดตัวติดตั้งจาก https://www.python.org/downloads/macos/ แล้วคลิกติดตั้ง
```

**วิธีที่ 2 — โคลนโปรเจกต์:**

```bash
git clone https://github.com/ShadowTak/ctf-auto.git
cd ctf-auto
```

**วิธีที่ 3 — ทดสอบว่าทำงาน:**

```bash
python3 run.py --category crypto --target "VlFTeFFSeVdSUmlCQlFTeVNCU0JDQVJRQUFJ"
# ควรเห็นผล decode + flag (ถ้าเป็น CTF จริง)
```

> ถ้า macOS บล็อกโปรแกรม (Gatekeeper) — เป็นเพราะยังไม่ได้ลงนาม ใช้ `right-click → Open` หรือรันใน Terminal ตามปกติได้เลย

### 🪟 Windows

**วิธีที่ 1 — ติดตั้ง Python:**

```powershell
# ตรวจก่อนว่ามี python ไหม (PowerShell)
python --version

# ถ้าไม่มี → ติดตั้งผ่าน winget (Windows 10/11)
winget install Python.Python.3.12

# หรือดาวน์โหลดจาก https://www.python.org/downloads/windows/
# ⚠️ สำคัญ: ตอนติดตั้งให้ติ๊ก "Add python.exe to PATH" ด้วย
```

**วิธีที่ 2 — โคลนโปรเจกต์:**

```powershell
git clone https://github.com/ShadowTak/ctf-auto.git
cd ctf-auto
```

**วิธีที่ 3 — ทดสอบว่าทำงาน:**

```powershell
python run.py --category crypto --target "VlFTeFFSeVdSUmlCQlFTeVNCU0JDQVJRQUFJ"
```

> ถ้าเจอ `'python' is not recognized` → เปิด PowerShell ใหม่ (ให้ PATH อัปเดต) หรือใช้ `py` แทน: `py run.py ...`

### ⚡ ทางเลือก: ติดตั้ง nmap (ทำให้ network scan ลึกขึ้น)

- **macOS**: `brew install nmap`
- **Windows**: `winget install Insecure.Nmap` หรือโหลดจาก https://nmap.org/download.html

### ✅ ตรวจสอบว่าทุกอย่างพร้อม (รันบนทั้ง 2 OS)

```bash
python3 run.py                # ควรขึ้นเมนูหลัก
python3 verify_vectors.py     # ควร PASS ทุกตัว (25+)
```

---

## วิธีรัน

```bash
cd ctf-auto
python3 run.py                # เมนู
python3 run.py --category web --target http://target:8080
python3 run.py --category crypto --target "encoded_string"   # หรือ path ไฟล์
python3 run.py --category network --target 10.10.10.5
python3 run.py --category network --target capture.pcap      # ไฟล์ pcap
python3 run.py --category full --target 10.10.10.5           # auto chain

# สแกนแลปใน redacted stack (ต้องรัน docker compose อยู่แล้ว)
python3 run.py --auto-lab web          # ทุกแลป web
python3 run.py --auto-lab crypto       # หมวด crypto (static files + web lab)
python3 run.py --auto-lab all --limit 3   # จำกัดจำนวนแลป

# เปิดตรวจ optional capabilities (Z3, SymPy, browser tooling ฯลฯ)
python3 run.py --pro --category crypto --target "encoded_string"
```

ไม่ต้องติดตั้ง dependency ใดๆ (stdlib ล้วน) — ถ้ามี `nmap`, `pycryptodome` จะทำงานได้ลึกขึ้น

สำหรับโหมด Pro ที่ใช้ constraint/lattice/browser tooling:

```bash
python3 -m pip install -r requirements-pro.txt
python3 -m playwright install chromium
```

`--pro` จะตรวจ capability ก่อนรันและแจ้งรายการที่ไม่มี โดยไม่ทำให้โหมด stdlib ล้มเหลว

### 🌐 Web UI (Beautiful dark-themed interface)

```bash
pip install flask          # ติดตั้งครั้งเดียว
python3 web_app.py         # เปิด http://localhost:8088
python3 web_app.py --port 9000  # custom port
```

- **Web tab**: ใส่ URL → auto-scan (recon, dirbust, SQLi, XSS, LFI, SSTI, CMDi, SSRF, IDOR, JWT, cookie forge, flag scan)
- **Crypto tab**: ใส่ ciphertext หรือ upload ไฟล์ → auto-decode (base64 chain, RSA, XOR, Vigenère, hash crack, brainfuck, etc.)
- **Network tab**: upload .pcap/.pcapng → auto-analyze (TCP reassembly, HTTP extraction, flag hunt)
- Real-time progress, flag highlighting, decode ranking

---

## โครงสร้าง

```
ctf-auto/
├── run.py                 # entry + เมนู + --auto-lab
├── autolab.py             # โหมด auto-lab (drive redacted API)
├── lab_session.py         # helper: login/start lab/download files
├── core/                  # flag detect, threading, output, HTTP client, 404 calibration
├── modules/
│   ├── crypto/            # encodings, classic, rsa, xor, hashes, modern, autodetect, length_ext
│   ├── web/               # recon, dirbust, injections, blind_sqli, interact, graphql,
│   │                      # ctr_bitflip, jwt, cookies(forge), backups, assets, errors
│   └── network/           # nmap, pcap, dns, services
├── wordlists/             # dirs / subdomains / passwords
├── data/english_quadgrams.txt   # quadgram model (สำหรับ substitution solver)
└── reports/               # ผลลัพธ์ (auto-create)
```

## ทดสอบ (ไม่ต้องมีเป้าหมายจริง)

```bash
python3 verify_vectors.py        # ตรวจ AES/ChaCha20/RC4/MT19937/RSA/classic/XOR/HLE กับ test vector มาตรฐาน
python3 test_tctt_vectors.py     # ตรวจ decoder แบบ TCTT: base45/58/62+Bad62/36, Thai custom-base64,
                                 #   emoji (bits/offset/base100/subst), Ook!, Malbolge (Hello World)
python3 -m unittest -q test_structured_crypto.py  # regression tests สำหรับ structured crypto attacks
python3 test_login.py            # login brute-force กับ server จำลอง (NCSA + PIN 4 หลัก)
python3 run_web_test.py          # รัน test server ใน thread + web scan จริง
python3 run_chain_test.py        # ทดสอบ auto chain network -> web
```

## 🎯 คู่มือใช้แข่ง CTF (ฉบับมือใหม่ → โปร)

### 1) เริ่มต้น: รันเลย ไม่ต้องคิดเยอะ

```bash
cd ctf-auto
python3 run.py --category crypto --target "ไฟล์หรือสตริงที่โจทย์ให้มา"
python3 run.py --category web --target http://<ip>:<port>
python3 run.py --category network --target 10.10.10.5
```

### 2) 🔐 ข้อ Crypto — เข้ารหัสซ้อนหลายชั้น

โจทย์สาย crypto ชอบเอา encoding มาซ้อนกันหลายชั้น (เช่น `base64(binary(hex(x)))`
หรือ `b64(rot13(b64(x)))`). Tool นี้มี **beam-search chain decoder** ที่ไม่ใช่แค่
ถอดทีละชั้นแบบตรงๆ แต่ **แตกกิ่งทุกตัวเลือก** แล้วให้คะแนนทุกเส้นทาง —
เจอ path ที่ถูกต้องแม้ชั้นกลางจะดูเหมือน garbage:

```bash
# ถอดเองทุกชั้นอัตโนมัติ
python3 run.py --category crypto --target cipher.txt
python3 run.py --category crypto --target "U2FsdGVkX1+..."

# ใช้เมนูเข้า chain decode โดยตรง:
# 1) เลือกหมวด crypto → 2) เลือก [7] Chain decode
```

เคล็ดลับ: ถ้าโจทย์ให้ไฟล์ที่มี header ภาษาไทย/อังกฤษปน (`cipher: <data>`, `enc = ...`),
tool จะ **extract payload หลัง label** อัตโนมัติ แล้วรัน pipeline ย่อยกับของจริง.

เคสที่ tool จัดการได้เอง:
- `base64` / `base32` / `base16` / `base85` / `hex` / `binary` / `octal` / `decimal` / `morse` / `brainfuck` / `gzip/zlib` / `rot13/rot47` / `leet`
- **RSA**: ให้ไฟล์ `n/e/c` มา → auto-detect → small-e / Wiener / Fermat
- **XOR**: single / repeating-key (Kasiski + annealing) / flag-prefix crib
- **Classic**: Caesar, Vigenere (auto-key ด้วย sweep + crib), Affine, Atbash, Bacon (0/1), Playfair, Hill, Columnar, substitution solver
- **Hash**: identify + wordlist crack → ต่อ flag-template เอง (`redactedCTF{<password>}`)
- **SHA-256 length extension**: forge MAC จาก (msg, mac) คู่เดียว
- **AES/ChaCha20/RC4/MT19937**: มี solver + test vector ในตัว

### 3) 🌐 ข้อ Web — สแกนลึกอัตโนมัติ

```bash
python3 run.py --category web --target http://10.10.11.123:8080
```

ลำดับอัตโนมัติ:
1. **Recon** — headers, robots.txt, sitemap, tech stack
2. **Dirbust** — 545+ paths (รวม api/v1/v2, actuator, swagger, graphql, console, flag.txt ในทุกโฟลเดอร์) ด้วยเธรด + keep-alive + 404-calibration
3. **Fuzz ทุก endpoint + ลิงก์ที่มี query param** — SQLi, XSS, LFI, SSTI, Command Injection, open-redirect, SSRF (รวม `/tmp/flag.txt`, internal `/flag`)
4. **Form POST fuzz** — SQLi auth-bypass (`' OR 1=1--`), CMDi, SSTI, XSS ทุก field
5. **Deep attacks** — IDOR enum (id=1,2,3...), GraphQL introspection, JSON mass-assignment (`role:admin`) / NoSQLi (`$ne`/`$gt`), AES-CTR bit-flip, cookie forge (base64-JSON → role=admin), JWT crack/forge, **blind SQLi extraction**
6. **Leak hunt** — backup files (.bak/.env/.git), asset/JS crawl (secret ใน script), error-trigger 500

> ⚡ ทุกเฟสหลัง dirbust รัน **พร้อมกัน (concurrent)** — เวลารวม = เฟสที่ช้าที่สุด ไม่ใช่ผลรวม

### 4) 🌍 ข้อ Network / Forensics

```bash
python3 run.py --category network --target 10.10.10.5   # port scan + banner
python3 run.py --category network --target dump.pcap    # วิเคราะห์ pcap — หา flag ใน HTTP, UDP/ICMP exfil
python3 run.py --category full --target 10.10.10.5      # auto: scan → เจอ web → รัน web module ต่อ
```

### 5) ขั้นตอนแนะนำต่อโจทย์แต่ละข้อ

| ข้อ CTF | คำสั่ง |
|--------|--------|
| ให้ string แปลกๆ มา | `--category crypto --target "<string>"` |
| ให้ไฟล์ n/e/c (RSA) | `--category crypto --target rsa.txt` |
| ให้ไฟล์ .pcap | `--category network --target capture.pcap` |
| หน้าเว็บมีช่องค้นหา/ส่งฟอร์ม | `--category web --target <url>` (fuzz form อัตโนมัติ) |
| โดนบล็อก payload (WAF) | เติม `--category web` แล้วดู hint ใน reports/ — tool มี payload หลายชุด |
| ต้องใช้ dictionary เต็ม | `ROCKYOU=/path/rockyou.txt python3 run.py ...` |

### 6) อ่านผล

- flag ทุกตัวที่เจอขึ้นที่หน้าจอ + บันทึกใน `reports/<timestamp>/`
- รู้จัก prefix ของหลายเวที (picoCTF, HTB, THCTT, NCSA, redacted และอื่นๆ) + generic candidate เช่น `customEvent{...}`
- ถ้าโจทย์ระบุ `prefix=` หรือ `flag_format=` จะใช้ prefix นั้นกับ solver ที่ต้องสร้าง flag; ถ้าไม่ระบุจะคืน plaintext/candidate โดยไม่เดาเป็น `redactedCTF{...}`
- ผล decode ที่เป็นข้อความเพี้ยนยังแสดงตาม raw output เพื่อให้ตรวจสอบเองได้; ระบบไม่ห่อข้อความนั้นเป็น flag อัตโนมัติ

## อ้างอิง / แรงบันดาลใจ

- **ctf-party** (Orange-Cyberdefense) — รายการ cipher/decoder
- **CTF-CryptoTool** (karma9874) — แนวคิด bruteforce ทุก decoder
- **awesome-ctf / CTF-tool** — รายการเครื่องมือแต่ละหมวด
- `english_quadgrams.txt` จาก practicalcryptography.com (mirror: gibsjose/statistical-attack)

## หมายเหตุ

- ใช้กับ **เป้าหมายที่คุณได้รับอนุญาตเท่านั้น** (CTF, lab ของตัวเอง)
- ถ้าไม่มี `nmap` โมดูล network จะใช้ socket scan แบบเบาๆ แทน
- `ROCKYOU=/path/rockyou.txt` เพื่อเพิ่ม wordlist ให้ hash crack
- บน Windows ใช้ `python` แทน `python3` ในทุกคำสั่ง (หรือ `py`)
