# Competition workspace — 2026-09-05

## ใช้งานบน Mac

```bash
bash scripts/setup_competition.sh
bash scripts/install_ctf_tools.sh install  # optional native tools
./ctf doctor
./ctf webui --host 127.0.0.1 --port 8088
```

ตัว launcher ใช้ `.venv` ของโปรเจกต์และเพิ่มเครื่องมือใน virtualenv เข้า PATH ให้ subprocess ด้วย Python 3.12 เป็น environment ที่ใช้ตรวจรอบนี้ ตัวเว็บใช้ฟอนต์ Space Grotesk / IBM Plex Mono ที่เก็บไว้ใน `static/fonts` พร้อม OFL license ไม่ต้องโหลดฟอนต์จากภายนอกขณะแข่ง

## หน้าเว็บแยก 5 หมวด

| หมวด | รับข้อมูล | วิธีทำงาน |
| --- | --- | --- |
| Auto CTF | ไฟล์หรือ archive ของโจทย์ | ตรวจ magic bytes, แตกชั้น archive, เลือก pipeline |
| Crypto | ข้อความ / JSON / PEM / ไฟล์หรือ archive | ทางด่วน decode 64 ชั้นก่อนค้นหา cipher ที่ซับซ้อน; RSA ข้ามไฟล์ |
| Web | URL ของโจทย์ | recon, routes, sessions, deep CTF workflows ภายใต้งบ request/time |
| Network | PCAP / PCAPNG | packet analysis และข้อมูลที่กู้คืนได้ |
| Image | ภาพที่ตรวจ format ได้ | metadata, file structure, steganography และ optional tools |

แต่ละหมวดมีคิว ผลลัพธ์ และสถิติของตัวเอง; **Findings** รวมผลทั้ง session การเลือกหลายไฟล์หมายถึงหลายโจทย์ แพ็กไฟล์ที่ต้องวิเคราะห์ร่วมกันไว้ใน ZIP เดียว เช่น RSA ciphertext หลายชุด เมื่อเปลี่ยนหมวด งานที่เริ่มแล้วทำต่อเบื้องหลัง ประวัติอยู่ในแท็บนี้เท่านั้น: Export JSON ก่อน reload/ปิดแท็บ

ตัวเว็บและ CLI เลือกจำนวนงานตาม CPU โดยตั้งเพดานเริ่มต้น 4 process; M5 10 คอร์ / RAM 16 GB ในการตรวจนี้ใช้ 4 งาน ส่วน Web ใช้ session lock ให้ credential ของแต่ละเป้าหมายแยกกัน ภายในแต่ละ Web scan มี HTTP keep-alive และงาน I/O ขนาน การเพิ่มจำนวนคอร์ไม่สามารถลด latency ของเซิร์ฟเวอร์โจทย์ได้ทั้งหมด

ปุ่มหยุดเก็บผลบางส่วนไว้ ไฟล์/ข้อความในโหมด competition มี deadline จริง 60 วินาทีพร้อมหยุด process group; งบ Web และการหยุด Web เป็น cooperative ค่าเริ่มต้น Web จบหลังขั้นค้นพบ flag candidate; phase ขนานที่เริ่มไปแล้วอาจยังต้องรอจบ เปิดตัวเลือกตรวจต่อได้ถ้าโจทย์มีหลายคำตอบ

## คิว CLI และ resume

```bash
./ctf --batch ./challenges --jobs 4 --job-seconds 90 --output ./results --resume
./ctf --category auto --target ./one-challenge --job-seconds 180 --output ./one-result
./ctf --category dircrypto --target ./rsa-files
.venv/bin/python scripts/benchmark_competition.py --repeat 3
```

แต่ละไฟล์/โฟลเดอร์ที่อยู่ใต้ `--batch` โดยตรงคือหนึ่งโจทย์; โฟลเดอร์ที่ส่งผ่าน `--category auto --target` คือโจทย์ที่มีหลายไฟล์ ผลอยู่ใน `results.json` และ `results.md` อัปเดตหลังแต่ละงาน `--resume` ใช้ผลเดิมเฉพาะงาน completed ที่ hash ของข้อมูล โค้ด ตัวเลือกและ dependency ตรงกัน Output ต้องอยู่นอก input

มีเพดาน 64 ไฟล์ต่อโจทย์, 16 MiB ต่อไฟล์, 64 MiB รวม inventory, archive 256 nodes / depth 4 / 64 MiB expanded ต่อไฟล์, 128 MiB expanded ต่อโจทย์ และ 256 โจทย์ต่อ batch การค้นหาทางด่วนจำกัด 64 ชั้น / 512 nodes / 16 MiB / 1 วินาที ก่อนส่งต่อ fallback ตัวทั่วไป เพดานเหล่านี้ไม่ใช่ security sandbox

## Crypto และหลักฐาน

- ทางด่วนเก็บข้อมูลเป็น bytes ผ่าน Hex/Base64/Base32/Base85/URL/HTML/compression ได้โดยไม่ทำ binary intermediate สูญหาย; ค่อยใช้ graph/statistical search เมื่อทางด่วนยังไม่ได้คำตอบ
- Common modulus, shared prime และ Hastad ข้ามไฟล์/สมาชิก archive ตรวจ `pow(m, e, n) == c` กับ record ที่รองรับคำตอบ และคืน plaintext + hex ตามจริง
- แยก **verified / candidate / decode**: ค่าที่รู้ prefix และได้จาก transport ที่ตรวจตรงตัวใช้หลักฐานในเครื่อง; prefix ใหม่ที่ยังไม่ได้ระบุ และผลจาก ROT/XOR/heuristic อยู่เป็น candidate ห้ามตีความว่า scoreboard รับแล้ว
- เก็บหลักฐานก่อนทำขั้นที่อาจช้า; มี regression สำหรับข้อมูล ZIP เสีย/เข้ารหัส, compression bomb, gzip/bz2/xz หลาย stream, endianness และ process ที่มี subprocess ค้าง
- ELF เป็น static triage ของ header/symbol/mitigation และ PDF เป็น metadata/text extraction ไม่ได้รัน binary ของโจทย์ และไม่อ้างว่า exploit Pwn อัตโนมัติทุกแบบ

Native dependencies ที่ติดตั้งและตรวจ import ใน environment นี้: PyCryptodome, fpylll + cysignals, Z3, SymPy, Pwntools, pyelftools, Capstone, pypdf, Pillow และ Playwright Chromium เครื่องมือภาพมี ExifTool, sevenzip, zbar, ImageMagick, binwalk; ติดตั้ง John Jumbo 1.9.0 และ sqlmap 1.10.9 เพิ่มสำหรับใช้งานจาก CLI ด้วย; ดูสถานะปัจจุบันด้วย `./ctf doctor` หรือ Tool arsenal เครื่องมือที่ตรวจพบไม่ได้แปลว่าถูกเรียกอัตโนมัติทุกตัว บาง solver เดิมอาจติดต่อ FactorDB; ทางด่วน decode และ RSA bundle ทำงาน offline

## ผลวัดบน M5

ใช้ fixture สังเคราะห์และตรวจคำตอบตรงตัว รวม startup ของ worker, deadline 6 วินาที วัดก่อน/หลังอย่างละหนึ่งรอบต่อเคส ตัวเลขใช้เปรียบเทียบเส้นทางที่แก้ ไม่ใช่อัตราชนะโจทย์จริงทุกแบบ รายละเอียดเครื่องและตัวเลขอยู่ใน [performance-m5.json](performance-m5.json)

| Fixture | ก่อน | หลัง | ผลหลัง |
| --- | --- | --- | --- |
| Base64 8 ชั้น | 0.816 s | 0.165 s | ตรงคำตอบ |
| Base64 16 ชั้น | timeout 6.043 s | 0.169 s | ตรงคำตอบ |
| Base64 24 ชั้น | 5.118 s แต่ไม่ตรงคำตอบ | 0.224 s | ตรงคำตอบ |
| Hex → Base64 → Gzip รวม 9 ชั้น | 0.914 s | 0.162 s | ตรงคำตอบ |

## Research ที่ใช้ตัดสินใจ

| แหล่งต้นทาง | สิ่งที่นำมาปรับ / ขอบเขต |
| --- | --- |
| [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) | อ้างอิงกลุ่ม RSA relationships; เพิ่ม bundle และตรวจสมการเองโดยมี budget |
| [picoCTF 2024 participant writeup — endianness-v2](https://warlocksmurf.github.io/posts/picoctf2024/) | เพิ่มการซ่อมลำดับ byte 16/32/64-bit ที่มี recognized file magic; ใช้ fixture ของเราในการตรวจ |
| [BuckeyeCTF 2025 — zip2john2zip](https://ctftime.org/writeup/40488) | การกู้รหัส archive ไม่เท่ากับพบ flag; แยกสมาชิกเสีย/เข้ารหัสจากสมาชิกที่อ่านได้ ไม่ได้อ้างว่าทำโจทย์ต้นฉบับนี้สำเร็จ |
| [Google CTF Postviewer v5 author writeup](https://gist.github.com/terjanq/e66c2843b5b73aa48405b72f4751d5f8) | ใช้ประเมินความซับซ้อนของ browser/session/race; คง browser discovery และหลักฐานเป็นขั้นตอน ไม่ได้เพิ่มหรืออ้าง solver เฉพาะ Postviewer |
| [Google CTF 2025 official challenges](https://github.com/google/google-ctf/tree/main/2025), [DUCTF 2025 official challenges](https://github.com/DownUnderCTF/Challenges_2025_Public) | สำรวจรูปแบบโจทย์และการจัดไฟล์; ไม่ใช้เป็นตัวเลข benchmark หรืออ้างว่าแก้ทุกโจทย์ได้ |
| [Pwntools installation](https://docs.pwntools.com/en/stable/install.html), [Python ZIP documentation](https://docs.python.org/3/library/zipfile.html) | การติดตั้งเครื่องมือและขอบเขต parser/archive |

## ตรวจซ้ำ

```bash
.venv/bin/python -m pytest tests --ignore=tests/test_all_categories.py -q --timeout=45
.venv/bin/python tests/test_all_categories.py
node --check static/console.js
```

`test_all_categories.py` เป็น standalone smoke script ที่พิมพ์ผล ต้องดูจำนวนผ่านใน log แยกจาก pytest; ไม่ใช่ pytest test function ปกติ

แผนผัง [competition architecture](../diagrams/ctf-auto.competition.html) ผ่าน Archify showcase 9/9 และตรวจภาพ desktop คำอธิบายเป็นภาษาไทย ส่วนปุ่ม Viewer และ `html lang` ใช้ English fallback ของ Archify
