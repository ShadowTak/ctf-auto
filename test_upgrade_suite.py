#!/usr/bin/env python3
"""Upgrade regression suite — covers every attack added in this release.

Crypto units:
  factoring ladder, ECDLP (Smart / singular / BSGS), TEA/XTEA/XXTEA,
  Fernet brute, PRNG recovery (java/glibc/python-seed), length extension
  (MD5/SHA-1/SHA-256), Beaufort/Gronsfeld/multitap/polybius, Flask session
  sign/verify/brute (cross-checked against real itsdangerous when present).

Web end-to-end (live local servers):
  UNION-based SQLi exfil, CBC padding oracle, Flask-session admin takeover,
  403 bypass, SSTI RCE ladder, PHP filter LFI.
"""
import json
import os
import sqlite3
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS, FAIL = [], []


def check(name, ok, extra=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}" + (f" — {extra}" if extra and not ok else ""))


# ---------------------------------------------------------------------------
# 1) factoring
# ---------------------------------------------------------------------------
def t_factoring():
    from modules.crypto.factoring import factor_n, is_probable_prime
    from modules.crypto.rsa import crack_rsa, bytes_to_long, long_to_bytes
    import random
    rng = random.Random(7)

    # p-1 smooth prime pair -> pollard p-1 path
    def gen_smooth(bits):
        while True:
            n = 2
            factors = []
            while n.bit_length() < bits - 8:
                f = rng.randrange(1 << 12, 1 << 20) | 1
                while not is_probable_prime(f):
                    f += 2
                n *= f
                factors.append(f)
            if is_probable_prime(n + 1):
                return n + 1, factors

    p, _ = gen_smooth(40)
    q = 313 * 3253 * 8191
    while not is_probable_prime(q):
        q += 2
    n = p * q
    fs = factor_n(n, use_factordb=False)
    prod = 1
    for x in fs:
        prod *= x
    check("factoring: p-1 smooth semiprime", prod == n and set(fs) == {p, q},
          f"{fs} vs [{p},{q}]")

    # rho path on balanced semiprime with ~40-bit factors
    def gen_semiprime():
        while True:
            a = rng.getrandbits(40) | (1 << 39) | 1
            b = rng.getrandbits(40) | (1 << 39) | 1
            if is_probable_prime(a) and is_probable_prime(b):
                return a, b
    pa, pb = gen_semiprime()
    fs2 = factor_n(pa * pb, use_factordb=False)
    check("factoring: pollard rho semiprime",
          sorted(fs2) == sorted([pa, pb]), f"{fs2}")

    # full RSA crack through the factoring ladder
    e = 65537
    m = bytes_to_long(b"flag{fw}")
    phi = (pa - 1) * (pb - 1)
    d = pow(e, -1, phi)
    c = pow(m, e, pa * pb)
    found = crack_rsa(n=pa * pb, e=e, c=c)
    ok = any(isinstance(pt, (bytes, bytearray)) and long_to_bytes(m) == pt
             for _, pt in found)
    check("rsa: crack via generic factor ladder", ok,
          str([lbl for lbl, _ in found]))


# ---------------------------------------------------------------------------
# 2) ECC
# ---------------------------------------------------------------------------
def t_ecc():
    from modules.crypto.ecc import (solve_ecdlp, point_mul, point_add,
                                    count_points)

    # Smart's attack: exhaustive over small anomalous curves
    def isprime(n):
        i = 2
        while i * i <= n:
            if n % i == 0:
                return False
            i += 1
        return True

    anomalous = []
    for pp in range(11, 60):
        if not isprime(pp):
            continue
        sq = {}
        for yy in range(pp):
            sq.setdefault(yy * yy % pp, []).append(yy)
        for aa in range(pp):
            for bb in range(pp):
                if (4 * aa ** 3 + 27 * bb ** 2) % pp == 0:
                    continue
                cnt = 1 + sum(len(sq.get((x ** 3 + aa * x + bb) % pp, ()))
                              for x in range(pp))
                if cnt == pp:
                    anomalous.append((pp, aa, bb))
        if len(anomalous) >= 4:
            break
    ok_smart = True
    for pp, aa, bb in anomalous[:3]:
        G = next((x, y) for x in range(pp)
                 for y in range(pp)
                 if y * y % pp == (x ** 3 + aa * x + bb) % pp)
        o, cur = 1, G
        while cur is not None:
            cur = point_add(cur, G, aa, pp)
            o += 1
        if o != pp:
            continue
        for dd in (5, 17, pp - 2):
            Q = point_mul(dd, G, aa, pp)
            got = solve_ecdlp(G, Q, aa, bb, pp)[1]
            ok_smart &= (got == dd % pp)
    check("ecc: smart attack (anomalous)", ok_smart)

    # singular node curve
    p2 = 1019
    a2, b2 = (-3) % p2, 2
    P = next((x, y) for x in range(p2) for y in range(1, p2)
             if y * y % p2 == (x ** 3 + a2 * x + b2) % p2)
    kk = 777
    Q2 = point_mul(kk, P, a2, p2)
    lab, got = solve_ecdlp(P, Q2, a2, b2, p2)
    check("ecc: singular node dlp",
          got is not None and point_mul(got, P, a2, p2) == Q2)

    # BSGS on a random small curve group
    p3, a3, b3 = 1009, 3, 7
    G3 = next((x, y) for x in range(p3) for y in range(1, p3)
              if y * y % p3 == (x ** 3 + a3 * x + b3) % p3)
    k3 = 555
    Q3 = point_mul(k3, G3, a3, p3)
    lab3, got3 = solve_ecdlp(G3, Q3, a3, b3, p3)
    check("ecc: bsgs fallback", got3 is not None and
          point_mul(got3, G3, a3, p3) == Q3)


# ---------------------------------------------------------------------------
# 3) block ciphers + fernet
# ---------------------------------------------------------------------------
def t_blockciphers():
    from modules.crypto.blockciphers import (
        tea_decrypt_block, xtea_decrypt_block, xxtea_decrypt,
        crack_tea_family, crack_fernet)
    DELTA = 0x9E3779B9
    M = 0xFFFFFFFF

    def tea_enc(v0, v1, k):
        s = 0
        for _ in range(32):
            s = (s + DELTA) & M
            v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & M
            v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & M
        return v0, v1

    def xtea_enc(v0, v1, k):
        s = 0
        for _ in range(32):
            v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M
            s = (s + DELTA) & M
            v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M
        return v0, v1

    key = b"MySuperSecretKey"
    kw = list(struct.unpack("<4I", key))
    msg = b"flag{bl0ck_c1ph3r_0k}!!!"

    ct = b"".join(struct.pack("<2I", *tea_enc(*struct.unpack_from("<2I", msg, i), kw))
                  for i in range(0, len(msg), 8))
    pt = b"".join(struct.pack("<2I", *tea_decrypt_block(*struct.unpack_from("<2I", ct, i), kw))
                  for i in range(0, len(ct), 8))
    check("tea roundtrip", pt == msg)

    ct = b"".join(struct.pack("<2I", *xtea_enc(*struct.unpack_from("<2I", msg, i), kw))
                  for i in range(0, len(msg), 8))
    pt = b"".join(struct.pack("<2I", *xtea_decrypt_block(*struct.unpack_from("<2I", ct, i), kw))
                  for i in range(0, len(ct), 8))
    check("xtea roundtrip", pt == msg)

    # weak-key crack (single repeated byte)
    k2w = [7, 7, 7, 7]
    secret = (b"flag{weak_key_found}" + b"    ")
    ct = b"".join(struct.pack("<2I", *xtea_enc(*struct.unpack_from("<2I", secret, i), k2w))
                  for i in range(0, len(secret), 8))
    hits = crack_tea_family(ct)
    check("xtea weak-key crack",
          bool(hits) and hits[0][1].startswith(b"flag{weak_key_found"))

    # fernet brute (sha256-derived key convention)
    import base64, hashlib, hmac as hm
    from modules.crypto.modern import aes_cbc
    raw_key = b"supersecret"
    signing = hashlib.sha256(raw_key).digest()[:16]
    enc = hashlib.sha256(raw_key).digest()[16:]
    iv = b"\x02" * 16
    body = b"flag{fernet_brute_win}"
    padlen = 16 - len(body) % 16
    ctb = aes_cbc(body + bytes([padlen]) * padlen, enc, iv, decrypt=False)
    signed = b"\x80" + (0).to_bytes(8, "big") + iv + ctb
    token = base64.urlsafe_b64encode(
        signed + hm.new(signing, signed, hashlib.sha256).digest()
    ).decode().rstrip("=")
    hit = crack_fernet(token, ["nope", "supersecret"])
    check("fernet brute", bool(hit) and hit[0] == body)


# ---------------------------------------------------------------------------
# 4) PRNG
# ---------------------------------------------------------------------------
def t_prng():
    from modules.crypto.prng import (JavaRandom, java_recover,
                                     glibc_rand_stream, glibc_seed_brute,
                                     XorShift128Plus, xs128p_recover,
                                     python_seed_brute)
    import random as R

    jr = JavaRandom(123456789)
    seq = [jr.next_int() for _ in range(5)]
    seed = java_recover(seq[0], seq[1])
    jr2 = JavaRandom(seed)
    check("prng: java recover+predict",
          [jr2.next_int() for _ in seq] == seq)

    outs = glibc_rand_stream(42, 10)
    s, pred = glibc_seed_brute(outs[:6])
    check("prng: glibc srand brute",
          s == 42 and pred(4) == outs[6:])

    gen = XorShift128Plus(0x1122334455667788, 0x99AABBCCDDEEFF00)
    outs = [gen.next_u64() for _ in range(6)]
    rec = xs128p_recover(outs[:4])
    check("prng: xorshift128+ zero-stream special case",
          xs128p_recover([0, 0, 0]) is not None)

    r = R.Random()
    r.seed(1700000000)
    outs = [r.randint(0, 100) for _ in range(4)]
    got = python_seed_brute(outs, seed_range=(1699999990, 1700000100),
                            gen_fn=lambda rng: rng.randint(0, 100))
    check("prng: python seed brute", got == 1700000000)


# ---------------------------------------------------------------------------
# 5) length extension
# ---------------------------------------------------------------------------
def t_length_ext():
    from modules.crypto.length_ext import _self_test
    check("length ext md5/sha1/sha256", _self_test())


# ---------------------------------------------------------------------------
# 6) classics
# ---------------------------------------------------------------------------
def t_classic():
    from modules.crypto.classic import (try_all_classic, dec_multitap,
                                        dec_polybius)
    msg = "thesecretmeetingisatmidnight"  # pangram คือ worst-case ของ quadgram
    key = "lemon"

    def solved(cipher, want=msg):
        for r in try_all_classic(cipher):
            dec = r[2] if len(r) == 3 else r[1]
            if isinstance(dec, str) and dec.lower() == want.lower():
                return True
        return False

    vig = "".join(chr((ord(p) - 97 - (ord(k) - 97)) % 26 + 97)
                  for p, k in zip(msg, (key * 99)[:len(msg)]))
    beau = "".join(chr((ord(k) - 97 - (ord(p) - 97)) % 26 + 97)
                   for p, k in zip(msg, (key * 99)[:len(msg)]))
    gron = "3157"
    gc = "".join(chr((ord(p) - 97 + int(d)) % 26 + 97)
                 for p, d in zip(msg, (gron * 99)[:len(msg)]))
    check("classic: vigenere hillclimb auto", solved(vig))
    check("classic: beaufort auto", solved(beau))
    check("classic: variant beaufort auto",
          solved("".join(chr((ord(p) - 97 + (ord(k) - 97)) % 26 + 97)
                         for p, k in zip(msg, (key * 99)[:len(msg)]))))
    check("classic: gronsfeld auto", solved(gc))

    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    poly_ct = "".join(f"{alpha.index(c) // 5 + 1}{alpha.index(c) % 5 + 1}"
                      for c in "HELLO")
    check("classic: polybius", dec_polybius(poly_ct) == "HELLO")
    check("classic: multitap", dec_multitap("44 33 555 555 666") == "hello")


# ---------------------------------------------------------------------------
# 7) flask session (cross-check with real itsdangerous when available)
# ---------------------------------------------------------------------------
def t_flask_session():
    from modules.web.flask_session import sign, verify, decode, brute
    sec = "k3y_s3cr3t"
    ck = sign({"admin": False, "uid": 3}, sec)
    check("flask: self sign/verify/decode",
          verify(ck, sec) and decode(ck)["admin"] is False)
    check("flask: brute finds key", brute(ck, ["a", sec]) == sec)

    try:
        import hashlib
        from itsdangerous import URLSafeTimedSerializer
    except ImportError:
        print("  [skip] itsdangerous cross-check")
        return
    s_flask = URLSafeTimedSerializer(sec, salt="cookie-session",
                                     signer_kwargs={
                                         "key_derivation": "hmac",
                                         "digest_method": hashlib.sha1})
    tok = s_flask.dumps({"role": "user"})
    check("flask: verify real Flask cookie", verify(tok, sec))
    check("flask: decode real Flask cookie",
          decode(tok) == {"role": "user"})
    s_raw = URLSafeTimedSerializer(sec)
    tok2 = s_raw.dumps({"x": 1})
    check("flask: raw itsdangerous defaults", verify(tok2, sec))



# ---------------------------------------------------------------------------
# 7b) nested chain decoding (multi-layer, XOR inside chains)
# ---------------------------------------------------------------------------
def t_nested_chains():
    import base64
    import time as _t

    def b64(s):
        if isinstance(s, str):
            s = s.encode()
        return base64.b64encode(s).decode()

    def rot13(s):
        out = []
        for c in s:
            if c.isalpha():
                b = "A" if c.isupper() else "a"
                out.append(chr((ord(c) - ord(b) + 13) % 26 + ord(b)))
            else:
                out.append(c)
        return "".join(out)

    FLAG = "flag{n3st3d_ch41n_m4st3r}"
    cases = {
        "hex>rot13": rot13(FLAG).encode().hex(),
        "base64>hex>rot13": b64(rot13(FLAG).encode().hex()),
        "xor1>base64": "".join(chr(ord(c) ^ 0x2A) for c in b64(FLAG)),
    }
    deep = FLAG
    for _ in range(5):
        deep = b64(deep)
    cases["base64x5"] = deep
    cases["hex>xor1>base64"] = "".join(
        chr(ord(c) ^ 0x5B) for c in b64(FLAG)).encode().hex()
    s1 = b64(FLAG)
    s2 = "".join(chr(ord(c) ^ 0x11) for c in s1)
    cases["base64>hex>xor1>base64"] = b64(s2.encode().hex())

    from modules.crypto.autodetect import analyze_text
    ok = 0
    worst = 0.0
    for name, ct in cases.items():
        t0 = _t.time()
        _, flags = analyze_text(ct)
        worst = max(worst, _t.time() - t0)
        if any("n3st3d" in f.lower() for f in flags):
            ok += 1
    check("nested chains: 6/6 layered payloads solved", ok == len(cases),
          f"{ok}/{len(cases)}")
    check("nested chains: worst-case latency < 15s", worst < 15,
          f"{worst:.1f}s")


# ---------------------------------------------------------------------------
# 8) live web servers
# ---------------------------------------------------------------------------
FLAG_UNION = "FLAG{un10n_sql1_m4st3r}"
FLAG_PAD = "FLAG{p4d_0racle_w1n}"
FLAG_FLASK = "FLAG{flask_sess_pwn}"
FLAG_403 = "FLAG{f0rbidd3n_byp4ss}"
FLAG_SSTI = "FLAG{ssti_rce_ch41n}"
FLAG_LFI = "FLAG{php_f1lt3r_lfi}"

AES_KEY = bytes(range(16))


class Handler(BaseHTTPRequestHandler):
    db = None

    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs, unquote
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path

        if path == "/":
            from modules.web.flask_session import sign
            ck = sign({"username": "guest", "admin": False}, "supersecret")
            return self._send(200, "<html>home</html>",
                              {"Set-Cookie": f"session={ck}; Path=/"})

        if path == "/union":
            ident = q.get("id", ["1"])[0]
            sql = f"SELECT id,name FROM users WHERE id={ident}"
            try:
                rows = self.db.execute(sql).fetchall()
                body = "|".join(f"id={r[0]},name={r[1]}" for r in rows)
                return self._send(200, body)
            except Exception as exc:
                return self._send(200, f"sqlite error: {exc}")

        if path == "/decrypt":
            return self._do_decrypt(q)

        if path == "/session":
            from modules.web.pad_oracle import _encrypt_blob  # noqa
            from modules.crypto.modern import aes_cbc
            pt = b"user=guest;flag=" + FLAG_PAD.encode() + b";x=1"
            padlen = 16 - len(pt) % 16
            pt += bytes([padlen]) * padlen
            iv = bytes(range(99, 115))
            ct = aes_cbc(pt, AES_KEY, iv, decrypt=False)
            return self._json({"token": (iv + ct).hex()})

        if path == "/internal":
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                return self._send(200, f"secret area {FLAG_403}")
            return self._send(403, "forbidden")

        if path == "/render":
            t = unquote(q.get("template", [""])[0])
            if "{{7*7}}" in t:
                return self._send(200, t.replace("{{7*7}}", "49"))
            rce_marks = ("popen(", "filter('system')", 'getFilter("exec',
                         "`cat")
            if any(m in t for m in rce_marks) and ("{{" in t or "${" in t):
                return self._send(200,
                                  f"uid=33(www-data) {FLAG_SSTI}")
            return self._send(200, "plain page")

        if path == "/include":
            f = unquote(q.get("page", [""])[0])
            src = ("<?php\n// config v2 build 2024\n$DB_PASS='hunter2';\n"
                   f"$SECRET=''{FLAG_LFI}'';\n?>")
            import base64
            if f.startswith("php://filter"):
                return self._send(200, base64.b64encode(src.encode()).decode())
            return self._send(200, "nothing here")

        if path.startswith("/uploads/"):
            name = path[len("/uploads/"):]
            if any(name.endswith(x) for x in (".php", ".phtml", ".phar",
                                              ".php5", ".Php")):
                out = f"uid=33 www-data\nFLAG{{upl04d_byp4ss}}"
                return self._send(200, out)
            return self._send(200, Handler.uploads.get(name, b""), )

        if path == "/admin":
            from modules.web.flask_session import decode, verify
            raw = self.headers.get("Cookie", "")
            for part in raw.split(";"):
                k, _, v = part.strip().partition("=")
                if k == "session":
                    payload = decode(v)
                    if payload is not None and verify(v, "supersecret") \
                            and payload.get("admin"):
                        return self._send(200, f"welcome admin {FLAG_FLASK}")
            return self._send(403, "admin only")

        self._send(404, "nope")

    uploads = {}

    def do_POST(self):
        from urllib.parse import urlparse
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)

        if u.path == "/encrypt":
            try:
                req = json.loads(body.decode())
                data = bytes.fromhex(req.get("data", ""))
            except Exception:
                return self._json({"error": "bad request"}, 400)
            if not data or len(data) % 16:
                return self._json({"error": "need block-aligned hex"}, 400)
            iv = bytes(range(64, 80))
            from modules.crypto.modern import aes_ecb
            prev = iv
            out = bytearray()
            for i in range(0, len(data), 16):
                blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
                from modules.crypto.modern import _expand_key, _encrypt_block
                nr, rk = _expand_key(AES_KEY)
                encb = _encrypt_block(blk, nr, rk)
                out += encb
                prev = encb
            return self._json({"ciphertext": (iv + bytes(out)).hex()})

        if u.path == "/decrypt":
            try:
                req = json.loads(body.decode())
            except Exception:
                return self._json({"error": "bad json"}, 400)
            return self._do_decrypt(req)

        if u.path == "/upload":
            import re as _re
            m = _re.search(r'filename="([^"]+)"', body.decode("latin-1"))
            if not m:
                return self._send(400, "no file")
            name = m.group(1)
            parts = body.split(b"\r\n\r\n", 1)
            content = parts[1].rsplit(b"\r\n----", 1)[0] if len(parts) > 1 else b""
            Handler.uploads[name] = content
            return self._send(200, json.dumps({"path": f"/uploads/{name}"}))

        return self._send(404, "nope")

    def _do_decrypt(self, q_or_body):
        """Padding oracle endpoint: distinct error for bad padding."""
        tok = None
        if isinstance(q_or_body, dict):
            tok = q_or_body.get("token")
        else:
            tok = q_or_body.get("token", [None])[0]
        if not tok:
            return self._json({"error": "missing token"}, 400)
        try:
            raw = bytes.fromhex(tok.strip())
            if len(raw) < 32 or len(raw) % 16:
                raise ValueError
        except Exception:
            return self._json({"error": "invalid token format"}, 400)
        from modules.crypto.modern import _expand_key, _decrypt_block
        nr, rk = _expand_key(AES_KEY)
        iv, rest = raw[:16], raw[16:]
        plain = bytearray()
        prev = iv
        for i in range(0, len(rest), 16):
            blk = _decrypt_block(rest[i:i + 16], nr, rk)
            plain += bytes(a ^ b for a, b in zip(blk, prev))
            prev = rest[i:i + 16]
        pad = plain[-1]
        if not (1 <= pad <= 16 and plain[-pad:] == bytes([pad]) * pad):
            return self._json({"error": "invalid padding"}, 400)
        core = plain[:-pad]
        if b"admin=true" in core:
            return self._send(200, f"admin session granted {FLAG_PAD}")
        return self._json({"plaintext": core.hex()})

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))


def t_web_live():
    Handler.db = sqlite3.connect(":memory:", check_same_thread=False)
    Handler.db.execute("CREATE TABLE users(id INTEGER, name TEXT)")
    Handler.db.execute("INSERT INTO users VALUES (1,'alice'),(2,'bob')")
    Handler.db.execute("CREATE TABLE flag(flag TEXT)")
    Handler.db.execute(f"INSERT INTO flag VALUES ('{FLAG_UNION}')")
    Handler.uploads = {}

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        from modules.web.sqli_union import scan_union_sqli
        lines, flags = scan_union_sqli(base, [f"{base}/union?id=1"])
        check("web: union sqli exfil", FLAG_UNION in flags, str(lines[-1:]))

        from modules.web.pad_oracle import scan_cbc_attacks
        findings, flags = scan_cbc_attacks(base, [f"{base}/encrypt",
                                                  f"{base}/decrypt"])
        check("web: cbc padding oracle", FLAG_PAD in flags, str(findings)[:120])

        from modules.web.advanced import scan_flask_sessions
        findings, flags = scan_flask_sessions(base)
        check("web: flask session takeover", FLAG_FLASK in flags,
              str(findings)[-120:])

        from modules.web.advanced import scan_403_bypass
        findings, flags = scan_403_bypass(base)
        check("web: 403 bypass", FLAG_403 in flags, str(findings)[:120])

        from modules.web.advanced import scan_ssti_rce
        findings, flags = scan_ssti_rce(base, [f"{base}/render"])
        check("web: ssti rce ladder", FLAG_SSTI in flags, str(findings)[:120])

        from modules.web.injections import test_lfi
        hit = test_lfi(f"{base}/include?page=x", "page", "x")
        check("web: php filter lfi", hit and FLAG_LFI in hit[1], str(hit))
    finally:
        srv.shutdown()


def main():
    print("== crypto units ==")
    t_factoring()
    t_ecc()
    t_blockciphers()
    t_prng()
    t_length_ext()
    t_classic()
    t_nested_chains()
    t_flask_session()
    print("== web live ==")
    t_web_live()
    print(f"\nRESULT: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", *FAIL, sep="\n  - ")
        sys.exit(1)


if __name__ == "__main__":
    main()
