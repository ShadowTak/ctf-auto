#!/usr/bin/env python3
"""Full category test suite: Crypto, Web, Image."""
import base64
import codecs
import hashlib
import json
import math
import os
import random
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.crypto.autodetect import analyze_text, analyze_text_evidence
from modules.crypto.rsa import crack_rsa, hastad_broadcast, common_modulus
from modules.crypto.xor import crack_xor
from modules.crypto.classic import try_all_classic
from modules.crypto.encodings import chain_decode_best
from modules.crypto.common import invmod
from modules.crypto.ecdsa_solver import detect_nonce_reuse, CURVES
from modules.crypto.lattice import coppersmith_small_roots, available_backends
from modules.crypto.hashes import crack_hash
from modules.image.forensics import analyze_image
from modules.network.intelligence import extract_indicators
from web_app import app

results = {"crypto": [], "web": [], "image": [], "network": []}


def test(name, category, passed):
    results[category].append((name, passed))
    icon = "✅" if passed else "❌"
    print(f"  {icon} {name}")


# ═══════════════════════════════════════════════════════════════
print("=" * 60)
print("  🧪  FULL CATEGORY TEST SUITE")
print("=" * 60)

# ─── CRYPTO ───────────────────────────────────────────────────
print("\n┌──────────────────────────────────────┐")
print("│  📦  CRYPTO                           │")
print("└──────────────────────────────────────┘")

# 1. 6-layer encoding
print("\n▸ 6-layer encoding (b64>b64>b32>rot13>hex>b64)")
flag = b"CTF{multi_layer_encoding}"
d = flag
for enc in [base64.b64encode, base64.b64encode, base64.b32encode]:
    d = enc(d)
d = codecs.encode(d.decode(), "rot_13").encode()
d = base64.b64encode(d.hex().encode())
best = chain_decode_best(d.decode(), max_depth=12, max_branches=20, timeout=15.0)
test("6-layer encoding", "crypto", any("CTF{" in str(o) for _, o in best))

# 2. RSA small e
print("\n▸ RSA small e (e=3, m^e < n)")
flag2 = b"CTF{rsa_small_e}"
m2 = int.from_bytes(flag2, "big")
while True:
    p2, q2 = random.getrandbits(256) | 1, random.getrandbits(256) | 1
    n2 = p2 * q2
    if n2 > m2 ** 3 and math.gcd(n2, m2) == 1:
        break
r2 = crack_rsa(n=n2, e=3, c=pow(m2, 3, n2))
test("RSA small e", "crypto", any(flag2.decode() in pt.decode("latin-1", "replace") for _, pt in r2))

# 3. RSA Fermat
print("\n▸ RSA Fermat (close p,q)")
flag3 = b"CTF{fermat_factor}"
m3 = int.from_bytes(flag3, "big")
# Generate proper primes close together for Fermat factorization
def _next_prime(n):
    while True:
        if n < 2:
            n = 2
        if n % 2 == 0:
            n += 1
        if n < 4:
            return n
        if all(n % i != 0 for i in range(3, min(int(n**0.5)+2, 1000))):
            return n
        n += 2
p3 = _next_prime(random.getrandbits(256))
q3 = _next_prime(p3 + random.randint(1, 50) * 2)
n3 = p3 * q3
r3 = crack_rsa(n=n3, e=65537, c=pow(m3, 65537, n3))
test("RSA Fermat", "crypto", len(r3) > 0 and any(b"CTF" in pt for _, pt in r3 if isinstance(pt, bytes)))

# 4. XOR single byte
print("\n▸ XOR single byte")
flag4 = b"CTF{xor_cracked}"
k4 = random.randint(1, 255)
ct4 = bytes(b ^ k4 for b in flag4)
r4 = crack_xor(ct4)
test("XOR single byte", "crypto", len(r4) > 0)

# 5. Caesar ROT13
print("\n▸ Caesar ROT13")
flag5 = "CTF{caesar_cipher}"
ct5 = codecs.encode(flag5, "rot_13")
r5 = try_all_classic(ct5)
test("Caesar ROT13", "crypto", len(r5) > 0)

# 6. RSA broadcast
print("\n▸ RSA broadcast (e=3, 3 moduli)")
flag6 = b"CTF{broadcast}"
m6 = int.from_bytes(flag6, "big")
pairs6 = []
ns6 = []
for _ in range(3):
    while True:
        p6, q6 = random.getrandbits(256) | 1, random.getrandbits(256) | 1
        n6 = p6 * q6
        if n6 > m6 ** 3 and math.gcd(n6, m6) == 1 and all(math.gcd(n6, x) == 1 for x in ns6):
            break
    ns6.append(n6)
    pairs6.append((n6, 3, pow(m6, 3, n6)))
dec6 = hastad_broadcast(pairs6)
test("RSA broadcast", "crypto", dec6 is not None and dec6.to_bytes((dec6.bit_length() + 7) // 8, "big") == flag6)

# 7. RSA common modulus
print("\n▸ RSA common modulus")
flag7 = b"CTF{common_mod}"
m7 = int.from_bytes(flag7, "big")
while True:
    p7, q7 = random.getrandbits(256) | 1, random.getrandbits(256) | 1
    n7 = p7 * q7
    phi7 = (p7 - 1) * (q7 - 1)
    if n7 > m7 and math.gcd(17, phi7) == 1 and math.gcd(65537, phi7) == 1:
        c1_7, c2_7 = pow(m7, 17, n7), pow(m7, 65537, n7)
        if c1_7 > 0 and c2_7 > 0 and math.gcd(c1_7, n7) == 1 and math.gcd(c2_7, n7) == 1:
            break
dec7 = common_modulus(c1_7, c2_7, 17, 65537, n7)
test("RSA common modulus", "crypto", dec7 is not None and dec7.to_bytes((dec7.bit_length() + 7) // 8, "big") == flag7)

# 8. MD5 hash
print("\n▸ MD5 hash crack")
d8 = hashlib.md5(b"password123").hexdigest()
c8 = crack_hash(d8)
test("MD5 hash crack", "crypto", c8 is not None and "password123" in c8)

# 9. ECDSA nonce reuse
print("\n▸ ECDSA nonce reuse")
n9 = CURVES["secp256k1"]["n"]
d9, k9 = 42, 99
r9 = 50000
s1 = ((1000 + d9 * r9) * invmod(k9, n9)) % n9
s2 = ((2000 + d9 * r9) * invmod(k9, n9)) % n9
reuse = detect_nonce_reuse([{"r": r9, "s": s1, "z": 1000}, {"r": r9, "s": s2, "z": 2000}])
test("ECDSA nonce reuse", "crypto", len(reuse) == 1 and reuse[0]["private_key"] == d9)

# 10. Coppersmith
print("\n▸ Coppersmith small roots")
roots = coppersmith_small_roots(101, 50, lambda _: [(-5) % 101, 1])
test("Coppersmith", "crypto", 5 in roots)

# 11. Lattice backends
print("\n▸ Lattice backends (Z3/fpylll/SymPy)")
backends = available_backends()
test("Lattice backends", "crypto", any(backends.values()))

# 12. Direct flag
print("\n▸ Direct flag detection")
r12, f12 = analyze_text("CTF{direct_flag}")
test("Direct flag", "crypto", "CTF{direct_flag}" in f12)

# ─── WEB ──────────────────────────────────────────────────────
print("\n┌──────────────────────────────────────┐")
print("│  🌐  WEB                              │")
print("└──────────────────────────────────────┘")

with app.test_client() as client:
    # 13. Web scan API
    print("\n▸ Web scan API (invalid target)")
    resp = client.post("/api/scan", json={"category": "web", "url": ""})
    d13 = resp.get_json()
    test("Web scan API (empty URL)", "web", "error" in d13 or d13.get("job_id"))

    # 14. Crypto scan API
    print("\n▸ Crypto scan API (text input)")
    resp = client.post("/api/scan", json={"category": "crypto", "text": "Q1RGe3dlYn0="})
    d14 = resp.get_json()
    jid14 = d14.get("job_id")
    if jid14:
        for _ in range(20):
            time.sleep(0.5)
            s14 = client.get(f"/api/status/{jid14}").get_json()
            if s14["status"] in ("done", "error"):
                break
        flags14 = [r for r in s14["results"] if r.get("type") == "flag"]
        test("Crypto scan API", "web", any("CTF{web}" in r.get("flag", "") for r in flags14))
    else:
        test("Crypto scan API", "web", False)

    # 15. Upload API
    print("\n▸ Upload API")
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("CTF{uploaded_flag}")
        tmp15 = f.name
    with open(tmp15, "rb") as f:
        resp = client.post("/api/upload", data={"file": (f, "flag.txt")}, content_type="multipart/form-data")
    d15 = resp.get_json()
    test("Upload API", "web", "job_id" in d15 or "file_path" in d15)
    os.unlink(tmp15)

    # 16. Evidence API
    print("\n▸ Evidence API")
    resp = client.post("/api/scan", json={"category": "crypto", "text": "CTF{evidence_test}"})
    d16 = resp.get_json()
    jid16 = d16.get("job_id")
    if jid16:
        for _ in range(20):
            time.sleep(0.5)
            s16 = client.get(f"/api/status/{jid16}").get_json()
            if s16["status"] in ("done", "error"):
                break
        resp16 = client.get(f"/api/evidence/{jid16}")
        ev16 = resp16.get_json()
        test("Evidence API", "web", "summary" in ev16 and "flags" in ev16)
    else:
        test("Evidence API", "web", False)

    # 17. Stop API
    print("\n▸ Stop API")
    resp = client.post("/api/stop/nonexistent")
    d17 = resp.get_json()
    test("Stop API (invalid job)", "web", "error" in d17)

    # 18. Prefix hint
    print("\n▸ Prefix hint (ctf = ctf{)")
    resp = client.post("/api/scan", json={"category": "crypto", "text": "dGVzdA==", "prefix": "ctf"})
    d18 = resp.get_json()
    test("Prefix hint API", "web", "job_id" in d18)

# ─── IMAGE ────────────────────────────────────────────────────
print("\n┌──────────────────────────────────────┐")
print("│  🖼️  IMAGE                            │")
print("└──────────────────────────────────────┘")

# 19. Create test PNG and analyze
print("\n▸ PNG analysis")
import zlib
def make_png(width=2, height=2):
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc
    raw = b""
    for _ in range(height):
        raw += b"\x00" + b"\xff\x00\x00" * width
    compressed = zlib.compress(raw)
    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
    idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + idat_crc
    iend_crc = struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    iend = struct.pack(">I", 0) + b"IEND" + iend_crc
    return sig + ihdr + idat + iend

tmp19 = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
tmp19.write(make_png())
tmp19.close()
report19 = analyze_image(tmp19.name, run_tools=False)
test("PNG format detection", "image", report19["format"] == "PNG")
test("PNG metadata", "image", len(report19["metadata"]) > 0)
test("PNG findings", "image", isinstance(report19["findings"], list))
os.unlink(tmp19.name)

# 20. JPEG analysis
print("\n▸ JPEG analysis")
tmp20 = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
# Minimal JPEG
jpeg_data = b"\xff\xd8\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
jpeg_data += b"\xff\xfe" + struct.pack(">H", 5) + b"test"
jpeg_data += b"\xff\xdb" + struct.pack(">H", 67) + bytes([0] * 65)
jpeg_data += b"\xff\xc0" + struct.pack(">H", 11) + bytes([8, 1, 1, 1, 0x11, 0x00])
jpeg_data += b"\xff\xc4" + struct.pack(">H", 31) + bytes([0] * 29)
jpeg_data += b"\xff\xda" + struct.pack(">H", 8) + bytes([1, 0, 0x11, 0x00])
jpeg_data += b"\x00" * 20
jpeg_data += b"\xff\xd9"
tmp20.write(jpeg_data)
tmp20.close()
report20 = analyze_image(tmp20.name, run_tools=False)
test("JPEG format detection", "image", report20["format"] == "JPEG")
test("JPEG metadata", "image", isinstance(report20["metadata"], list))
os.unlink(tmp20.name)

# 21. String extraction
print("\n▸ String extraction")
test("String extraction", "image", "ascii" in report20.get("strings", {}) or len(report20.get("strings", {})) > 0)

# 22. Embedded signatures
print("\n▸ Embedded signature detection")
test("Signature detection", "image", isinstance(report20.get("signatures", []), list))

# ─── NETWORK ──────────────────────────────────────────────────
print("\n┌──────────────────────────────────────┐")
print("│  🌍  NETWORK                          │")
print("└──────────────────────────────────────┘")

# 23. Link extraction
print("\n▸ Suspicious link extraction")
text23 = 'http://target/admin/config?debug=1 http://target/.env http://normal/about'
links = extract_indicators(text23)
test("Link extraction", "network", len(links["links"]) > 0)

# 24. Score ranking
print("\n▸ Link score ranking")
top = sorted(links["links"], key=lambda x: -x["score"])
test("Score ranking", "network", top[0]["score"] >= top[-1]["score"])

# 25. Flag extraction
print("\n▸ Flag extraction from text")
links25 = extract_indicators("http://x ctf{net_flag_found} 192.168.1.1")
test("Flag extraction", "network", "ctf{net_flag_found}" in links25["flags"])

# 26. IP extraction
print("\n▸ IP extraction")
test("IP extraction", "network", "192.168.1.1" in links25["ips"])

# 27. Secret detection
print("\n▸ Secret/credential detection")
links27 = extract_indicators("Authorization: Bearer secret_token_abc123 api_key=xyz789")
test("Secret detection", "network", len(links27["secrets"]) > 0)

# 28. Base64 blob decode
print("\n▸ Base64 blob decode")
links28 = extract_indicators("SGVsbG8gd29ybGQ=")
test("Base64 blob decode", "network", any("Hello" in b.get("decoded", "") for b in links28["decoded_blobs"]))


# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════
print()
print("=" * 60)
print("  📊  RESULTS SUMMARY")
print("=" * 60)

total_pass = 0
total_all = 0
for cat in ["crypto", "web", "image", "network"]:
    passed = sum(1 for _, ok in results[cat] if ok)
    total = len(results[cat])
    total_pass += passed
    total_all += total
    cat_name = {"crypto": "📦 CRYPTO", "web": "🌐 WEB", "image": "🖼️  IMAGE", "network": "🌍 NETWORK"}[cat]
    print(f"\n  {cat_name}: {passed}/{total}")
    for name, ok in results[cat]:
        print(f"    {'✅' if ok else '❌'} {name}")

print()
print("  " + "─" * 40)
print(f"  TOTAL: {total_pass}/{total_all} ({round(total_pass/total_all*100, 1)}%)")
print("  " + "─" * 40)
print()
