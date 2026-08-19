# 🚩 CTF Auto Recon & Solver

เครื่องมืออัตโนมัติสำหรับ CTF — สแกน เจาะ และหา **flag** ครอบคลุม 3 หมวดหลัก
+ **โหมด Auto Lab** สำหรับสแกนแลปใน Aegis stack อัตโนมัติ

| หมวด | ความสามารถ |
|------|-----------|
| 🌐 **Web** | recon (headers/robots/tech), **keep-alive HTTP pool + retry** (dirbust เร็วหลายเท่า, ทน connection reset), directory brute-force (threaded, 545+ paths + API/actuator), SQLi / XSS / LFI / SSTI / Command Injection / open-redirect / SSRF fuzz (**fuzz ทุก endpoint + ลิงก์ที่มี query param**), **form POST fuzz** (SQLi auth-bypass / CMDi / SSTI / XSS ในทุก field), **blind boolean-based SQLi extraction** (extract flag ทีละตัวอักษรผ่าน oracle), **login brute-force** (THCTT WebAccessControl: common creds + 4-digit PIN 0000-9999, form + JSON endpoint, detect success จาก baseline), **asset & JS crawl**, **error-trigger 500 leak hunt**, **AES-CTR bit-flip attack**, **GraphQL introspection**, **JSON mass-assignment / NoSQLi probe** (`$ne`/`$gt` + token follow-up), **cookie forge**, **IDOR enumeration**, JWT attack, backup file & source disclosure (.git/.env/.bak), **shared soft-404 calibration**, flag scan |
| 🔐 **Crypto** | auto-detect & decode ทุกวิธี (base16/32/45/58/62/64/85, hex, binary, octal, morse, brainfuck, Ook!, **Malbolge**, ROT13/47, leet, gzip/zlib, file-magic sniff) + **beam-search chain-decode หลายชั้น** (แตกทุกเส้นทาง เก็บทุก flag — ผ่าน TCTT base85→base45 chain) + **custom-alphabet base-N** (Thai alphabet `ก-ฮ+๐-๙+0-9` แบบ THCTT New Base64, emoji base-100) + **emoji solver** (2-state → binary, unicode-offset 0x1F3F7, substitution word-matching) + **base62 case-recovery** (THCTT Bad62: enumerate case variants ต่อ chunk + flag-body scoring) + payload extraction หลัง label (`cipher:`/`cipher_hex:`) + classic ciphers (Caesar, **Vigenere auto-key: sweep + flag-prefix crib + per-char indexing**, Affine, Atbash, Railfence, **Bacon 0/1**, Playfair, Hill, Columnar, substitution solver ด้วย quadgram annealing) + RSA attacks (**auto-detect ไฟล์ n/e/c**, small-e, Wiener, Fermat, PEM/DER parser, **integer-only iroot**) + XOR (single/multi-byte, flag-prefix crib, **wordlist-key crib** แบบ THCTT) + **hash identify/crack + flag-template** (`AegisCTF{<password>}` → เติมค่าที่ crack ได้) + **SHA-256 length extension attack** — เก็บ flag จาก **ทุก** ผล decode (ไม่ตัดด้วย ranking) |
| 🌍 **Network** | nmap port scan (socket fallback), banner grabbing, **pure-Python pcap/pcapng analyzer** (TCP reassembly, HTTP extraction, flag hunt ใน UDP/ICMP exfil), DNS recon (records / zone transfer / subdomain brute) |

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

# สแกนแลปใน Aegis stack (ต้องรัน docker compose อยู่แล้ว)
python3 run.py --auto-lab web          # ทุกแลป web
python3 run.py --auto-lab crypto       # หมวด crypto (static files + web lab)
python3 run.py --auto-lab all --limit 3   # จำกัดจำนวนแลป
```

ไม่ต้องติดตั้ง dependency ใดๆ (stdlib ล้วน) — ถ้ามี `nmap`, `pycryptodome` จะทำงานได้ลึกขึ้น

---

## 🔍 ตอนนี้แก้อะไรได้บ้าง (สรุปความสามารถ)

### 🎯 ภาพรวม: แลปเทสจริง Web 14/14 + Crypto 14/14 disk-tested ผ่าน

### 🌐 Web — 14 เทคนิคสแกน/เจาะอัตโนมัติ

| # | เทคนิค | เจออะไร | แลปที่ผ่าน |
|---|--------|--------|-----------|
| 1 | **Recon** — headers, robots.txt, sitemap, tech stack | ข้อมูลเว็บ, path ที่ hint | ทุกแลป |
| 2 | **Dirbust** — 545+ paths (threaded + keep-alive + 404-calibration) | hidden dir, flag.txt, .git/.env | idor-101, path-traversal |
| 3 | **SQLi fuzz** — boolean/time/error/union | login bypass, data leak | sqli-101 |
| 4 | **Blind SQLi extraction** — boolean oracle, extract ทีละตัวอักษร (parallel) | flag จาก DB โดยไม่เห็นผลลัพธ์ | blind-sqli |
| 5 | **XSS / SSTI fuzz** | reflected payload | xss-reflected |
| 6 | **LFI / path traversal** — ทุก payload + `/tmp/flag.txt` | อ่านไฟล์บน server | lfi-file-read, path-traversal |
| 7 | **Command injection** — form + GET param | รันคำสั่งบน server | command-injection-basic |
| 8 | **SSRF** — loopback / metadata / internal `/flag` | อ่าน service ภายใน | ssrf-basics |
| 9 | **IDOR enum** — id=1,2,3... + path ids | ข้อมูล user อื่น | idor-101 |
| 10 | **GraphQL introspection** — enumerate fields → query flag | flag จาก schema | graphql-introspection |
| 11 | **Mass-assignment / NoSQLi** — `role:admin`, `$ne`/`$gt` | ขึ้นสิทธิ์ admin, bypass auth | mass-assignment, nosql-injection |
| 12 | **Cookie forge** — base64-JSON → role=admin | ขึ้นสิทธิ์ | cookie-manipulation |
| 13 | **AES-CTR bit-flip** — keystream จาก plaintext echo → forge cookie | ปลอม session | aes-ctr-bitflip |
| 14 | **Login brute** — common creds + PIN 4 หลัก, JWT crack/forge, backup leak, 500 error leak, asset/JS crawl | credential, secret ใน script | file-upload-basic, ... |

### 🔐 Crypto — ถอดได้ทุกรูปแบบ

| กลุ่ม | ถอด/แก้ได้ |
|------|-----------|
| **Encoding** | base16/32/45/58/62/64/85, hex, binary, octal, decimal, morse, brainfuck, Ook!, Malbolge, ROT13/47, leet, gzip/zlib, custom-alphabet (Thai `ก-ฮ+๐-๙+0-9`, emoji base-100), base62 case-recovery (Bad62) |
| **Chain ซ้อนหลายชั้น** | beam-search แตกทุกเส้นทาง — `base64(binary(hex))`, `b64(rot13(b64))`, `base85→base45→Malbolge` (TCTT 2025) — เก็บ flag จากทุกชั้น |
| **Classic cipher** | Caesar, Vigenere (auto-key: sweep + flag-prefix crib + per-char), Affine, Atbash, Railfence, Bacon (0/1), Playfair, Hill, Columnar, substitution (quadgram annealing) |
| **RSA** | auto-detect ไฟล์ n/e/c → small-e (cube root), Wiener (small d), Fermat (ใกล้กัน), **shared-prime** (gcd สองตัวเลข), PEM/DER parser, integer-only iroot |
| **XOR** | single-byte brute, repeating-key (Kasiski + annealing), flag-prefix crib, wordlist-key crib (THCTT), **two-time-pad crib-drag** (OTP reuse — phrase-based, auto-recover key) |
| **Hash** | identify (md5/sha1/sha256/...), wordlist crack + mutation, flag-template ต่อเอง (`AegisCTF{<password>}` → `AegisCTF{chocolate}`) |
| **Modern** | AES (ECB/CBC), ChaCha20, RC4, MT19937 — solver + test vectors ในตัว |
| **อื่นๆ** | **SHA-256 length extension** (forge MAC จาก (msg, mac) คู่เดียว), **KLG3 ledger solver** (SHA-256 + Base85 + XOR position-bound), **LCG custom cipher** (auto-detect + decrypt), payload หลัง label (`cipher:`/`cipher_hex:`) |

### 🌍 Network / Forensics

- **nmap port scan** (หรือ socket scan ในตัว), banner grabbing
- **pcap/pcapng analyzer** — TCP reassembly, HTTP extraction, flag ใน UDP/ICMP exfil
- **DNS recon** — records, zone transfer, subdomain brute (64 threads)

### 🏁 Flag detection

- รู้จัก prefix 150+ (FLAG{}, picoCTF{}, AEGIS{}, HTB{}, THCTT{}, scriptCTF{}, NCSA{}...) + generic fallback (จับ prefix อะไรก็ได้ที่มี `{...}`)
- **wrap แบบไม่มีปีกกา**: `AEGISCTFsecret` → `AEGISCTF{secret}` (รวม lowercase-body variant: `SCRIPTCTFNOTWHATITSEEMS` → `scriptCTF{notwhatitseems}`)

---

## โครงสร้าง

```
ctf-auto/
├── run.py                 # entry + เมนู + --auto-lab
├── autolab.py             # โหมด auto-lab (drive Aegis API)
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
python3 test_login.py            # login brute-force กับ server จำลอง (NCSA + PIN 4 หลัก)
python3 run_web_test.py          # รัน test server ใน thread + web scan จริง
python3 run_chain_test.py        # ทดสอบ auto chain network -> web
```

## ผลลัพธ์จากการเทสกับแลปจริง

**Crypto: 14/14 ผ่าน (disk-tested)**
- rsa-small-e (`AegisCTF{small_e_cube_root_strikes_again}`)
- rsa-wiener (`AegisCTF{wiener_attack_small_d}`)
- rsa-mistake / shared-prime (`AegisCTF{shared_prime_is_a_fatal_flaw}`)
- bacon-cipher (`scriptCTF{notwhatitseems}`)
- vigenere-basic (`AegisCTF{vigenere_is_just_caesar_plus_key}`)
- base64-trap (`AegisCTF{base64_is_not_encryption}`)
- hash-crack (`AegisCTF{chocolate}`)
- single-byte-xor (`AegisCTF{single_byte_xor_bruteforce}`)
- repeating-xor (`AegisCTF{known_plaintext_beats_xor}`)
- xor-reuse / two-time-pad (`AegisCTF{xor_key_reuse_crib_drag}`)
- custom-cipher / LCG (`AegisCTF{lcg_keystream_is_weak}`)
- brainfuck (`AegisCTF{brainfuck_esoteric_joy}`)
- crypto-ledger-quorum / KLG3 (`AegisCTF{ledger_quorum_rejects_the_pretty_decoy}`)
- xored-flag (`AegisCTF{read_the_checker_trace_the_xor}`)
- hash-length-extension (forge MAC สำเร็จ, flag อยู่ฝั่ง server)

**Web: 14/14 ผ่าน** — idor-101, file-upload-basic, cookie-manipulation,
path-traversal, graphql-introspection, command-injection-basic, mass-assignment,
sqli-101, xss-reflected, aes-ctr-bitflip, lfi-file-read, **blind-sqli**
(boolean-oracle extraction), ssrf-basics, nosql-injection

## 🇹🇭 แนวข้อ Thailand Cyber Top Talent (TCTT)

Tool นี้ปรับตาม writeup TCTT หลายปี (2021-2025) — pattern ที่เจอบ่อยและวิธีใช้ tool:

| ปี/หมวด | โจทย์ที่เจอ | วิธีใช้ tool |
|--------|-----------|-------------|
| 2025 Crypto | **Advanced Strings Secret** — base85 → base45 → **Malbolge** | `--category crypto --target file` → chain-decode แตกอัตโนมัติ + Malbolge interpreter ในตัว |
| 2025 Crypto | **New Base64** — custom alphabet ภาษาไทย `ก-ฮ+๐-๙+0-9` (UTF-16, `==` pad) | custom-base decoder รู้จัก construction นี้ → ถอดได้เอง |
| 2025 Crypto | **Bad62** — base62 ที่ alphabet โดน lowercase | base62 case-recovery: enumerate case variants ต่อ chunk + flag-body scoring |
| 2024 Crypto | **emoBit** — 😺/😸 = binary → emoji → ลบ offset 0x1F3F7 | emoji solver: 2-state → bits → emoji-offset |
| 2024 Crypto | **Easy1/2, Programming** — base32→base64 chain, hex+reverse, emoji substitution → md5 flag | chain-decode + emoji-subst (word-matching) |
| 2024 Prog. | **XOR + wordlist** — key เป็นคำใน list, ผลมีคำนั้น | `xor-wordlist` crib: ลองทุกคำใน wordlist เป็น repeating key |
| 2021 Web | **WebAccessControl** — login brute PIN 4 หลัก (username เริ่มต้น NCSA) | `login brute-force`: common creds + PIN 0000-9999 อัตโนมัติ |
| 2022 Web | **Web-challenge04** — dirbust หา `/s/e/c/r/e/t/`, PHP `.inc` โชว์ secret | dirbust 545+ paths + backup/source leak checks |
| 2021 Web | **WebSecretKey** — hidden directory + secret | dirbust + recon |

Flag format ที่รู้จักแล้ว: `THCTT{...}`, `THCTT24{...}`, `THCTT2024{...}`, `tctt2022{...}`, `TCTT{...}`, `NCSA{...}`, `WTCTT{...}`

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
- **Hash**: identify + wordlist crack → ต่อ flag-template เอง (`AegisCTF{<password>}`)
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
- flag ที่ไม่รู้จัก prefix (เช่น `AEGISCTFsecret`) จะถูก **wrap เอง** เป็น `AEGISCTF{secret}`
- ใช้ flag format ของเวทีนั้นๆ ได้เลย (picoCTF, HTB, Aegis, ...)

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
