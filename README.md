# 🚩 CTF Auto Recon & Solver

เครื่องมืออัตโนมัติสำหรับ CTF — สแกน เจาะ และหา **flag** ครอบคลุม 3 หมวดหลัก
+ **โหมด Auto Lab** สำหรับสแกนแลปใน Aegis stack อัตโนมัติ

| หมวด | ความสามารถ |
|------|-----------|
| 🌐 **Web** | recon (headers/robots/tech), **keep-alive HTTP pool + retry** (dirbust เร็วหลายเท่า, ทน connection reset), directory brute-force (threaded, 545+ paths + API/actuator), SQLi / XSS / LFI / SSTI / Command Injection / open-redirect / SSRF fuzz (**fuzz ทุก endpoint + ลิงก์ที่มี query param**), **form POST fuzz** (SQLi auth-bypass / CMDi / SSTI / XSS ในทุก field), **asset & JS crawl**, **error-trigger 500 leak hunt**, **AES-CTR bit-flip attack** (auto-detect `/encrypt`+`/decrypt`), **GraphQL introspection** (enumerate fields → query flag), **JSON mass-assignment / NoSQLi probe** (`$ne`/`$gt` + token follow-up), **cookie forge** (base64-JSON → role=admin), **IDOR enumeration** (numeric param + path ids), JWT attack, backup file & source disclosure (.git/.env/.bak), **shared soft-404 calibration** (ตัด false positive), flag scan |
| 🔐 **Crypto** | auto-detect & decode ทุกวิธี (base16/32/64/85, hex, binary, octal, morse, brainfuck, ROT13/47, leet, gzip/zlib, file-magic sniff) + **chain-decode หลายชั้น** + **payload extraction หลัง label** (`cipher:`/`cipher_hex:`) + classic ciphers (Caesar, **Vigenere auto-key: sweep + flag-prefix crib + per-char indexing**, Affine, Atbash, Railfence, **Bacon 0/1**, Playfair, Hill, Columnar, substitution solver ด้วย quadgram annealing) + RSA attacks (**auto-detect ไฟล์ n/e/c**, small-e, Wiener, Fermat, PEM/DER parser, **integer-only iroot**) + XOR (single/multi-byte, flag-prefix crib) + **hash identify/crack + flag-template** (`AegisCTF{<password>}` → เติมค่าที่ crack ได้) + **SHA-256 length extension attack** (forge MAC จาก (msg, mac) คู่เดียว) — เก็บ flag จาก **ทุก** ผล decode (ไม่ตัดด้วย ranking) |
| 🌍 **Network** | nmap port scan (socket fallback), banner grabbing, **pure-Python pcap/pcapng analyzer** (TCP reassembly, HTTP extraction, flag hunt ใน UDP/ICMP exfil), DNS recon (records / zone transfer / subdomain brute) |

คุณสมบัติ:
- **เมนูเลือกหมวด** → ใส่ URL / host / ไฟล์ → รันอัตโนมัติ
- **⚡ Auto Full**: สแกน network ก่อน → เจอ web service → รัน web module ต่อทันที
- **⚡ Auto Lab** (`--auto-lab`): ต่อ API ของ Aegis stack (localhost:3001) — start แลป, โหลด static files, สแกนอัตโนมัติ, สรุปว่าแลปไหนเจอ flag (จัดการ rate limit 4 start/นาที + stop แลปค้างอัตโนมัติ)
- **มัลติเธรด** ทุกงาน (dirbust, decode, port scan, fuzz, subdomain)
- **Flag detection อัตโนมัติ** — รู้จักรูปแบบ flag 150+ (FLAG{}, picoCTF{}, AEGIS{}, HTB{}, scriptCTF{}, ...) + **wrap แบบไม่มีปีกกา** (`AEGISCTFsecret` → `AEGISCTF{secret}`)
- รายงานผลบันทึกที่ `reports/` อัตโนมัติ

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

## โครงสร้าง

```
ctf-auto/
├── run.py                 # entry + เมนู + --auto-lab
├── autolab.py             # โหมด auto-lab (drive Aegis API)
├── lab_session.py         # helper: login/start lab/download files
├── core/                  # flag detect, threading, output, HTTP client, 404 calibration
├── modules/
│   ├── crypto/            # encodings, classic, rsa, xor, hashes, modern, autodetect, length_ext
│   ├── web/               # recon, dirbust, injections, interact, graphql, ctr_bitflip,
│   │                      # jwt, cookies(forge), backups, assets, errors
│   └── network/           # nmap, pcap, dns, services
├── wordlists/             # dirs / subdomains / passwords
├── data/english_quadgrams.txt   # quadgram model (สำหรับ substitution solver)
└── reports/               # ผลลัพธ์ (auto-create)
```

## ทดสอบ (ไม่ต้องมีเป้าหมายจริง)

```bash
python3 verify_vectors.py        # ตรวจ AES/ChaCha20/RC4/MT19937/RSA/classic/XOR/HLE กับ test vector มาตรฐาน
python3 run_web_test.py          # รัน test server ใน thread + web scan จริง
python3 run_chain_test.py        # ทดสอบ auto chain network -> web
```

## ผลลัพธ์จากการเทสกับแลปจริง (Aegis stack)

**Crypto: 8/8 ผ่าน** — rsa-small-e, bacon-cipher, vigenere-basic, base64-trap,
hash-crack (`AegisCTF{chocolate}`), single-byte-xor, **aes-ctr-bitflip**
(bit-flip attack อัตโนมัติ), hash-length-extension (forge MAC สำเร็จ)

**Web (14 แลป)**: idor-101, file-upload-basic, path-traversal, graphql-introspection,
command-injection-basic, sqli-101, xss-reflected, aes-ctr-bitflip ✅ —
ที่เหลือ (cookie-manipulation, blind-sqli, ssrf-basics, nosql-injection,
mass-assignment) ยังต้องเพิ่มเทคนิคเฉพาะ

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
5. **Deep attacks** — IDOR enum (id=1,2,3...), GraphQL introspection, JSON mass-assignment (`role:admin`) / NoSQLi (`$ne`/`$gt`), AES-CTR bit-flip, cookie forge (base64-JSON → role=admin), JWT crack/forge
6. **Leak hunt** — backup files (.bak/.env/.git), asset/JS crawl (secret ใน script), error-trigger 500

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
