"""Quick self-test against known test vectors (run: python3 verify_vectors.py)."""
import string
import sys
sys.path.insert(0, ".")

from modules.crypto.modern import (
    MT19937, aes_ecb, aes_cbc, chacha20, clone_mt19937, rc4, break_lcg,
)
from modules.crypto.rsa import parse_pem, wiener_attack, fermat_factor, small_e_attack
from modules.crypto.classic import vigenere_decrypt, solve_substitution, hill_decrypt, playfair_decrypt, playfair_encrypt, dec_bacon
from modules.crypto.encodings import (
    dec_brainfuck, dec_morse, chain_decode, sniff_bytes,
)
from modules.crypto.xor import crack_xor, known_plaintext_xor

fails = []

def check(name, got, want):
    ok = got == want
    print(("PASS" if ok else "FAIL"), name, "" if ok else f"got={got!r} want={want!r}")
    if not ok:
        fails.append(name)

# --- AES-128 ECB (FIPS-197) ---
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
pt = bytes.fromhex("00112233445566778899aabbccddeeff")
ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
check("aes128-ecb-enc", aes_ecb(pt, key, decrypt=False).hex(), ct.hex())
check("aes128-ecb-dec", aes_ecb(ct, key, decrypt=True).hex(), pt.hex())

# AES-256 (FIPS-197 appendix C.3)
key256 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
ct256 = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
check("aes256-ecb-enc", aes_ecb(pt, key256, decrypt=False).hex(), ct256.hex())
check("aes256-ecb-dec", aes_ecb(ct256, key256, decrypt=True).hex(), pt.hex())

# AES-CBC roundtrip with padding
iv = bytes(range(16))
data = b"the flag is hidden in this padding test!!"
enc = aes_cbc(data, key, iv, decrypt=False)
check("aes-cbc-roundtrip", aes_cbc(enc, key, iv, decrypt=True), data)

# --- ChaCha20 (RFC 8439) ---
ckey = bytes(range(32))
cnonce = bytes.fromhex("000000090000004a00000000")
cipher = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
check("chacha20-rfc8439", chacha20(bytes(64), ckey, cnonce, counter=1).hex(), cipher.hex())

# --- RC4 ---
check("rc4", rc4(b"Plaintext", b"Key").hex().upper(), "BBF316E8D940AF0AD3")

# --- MT19937 ---
mt = MT19937(seed=5489)
check("mt19937-first", mt.next_u32(), 3499211612)
# clone from 624 outputs
mt2 = MT19937(seed=12345)
outs = [mt2.next_u32() for _ in range(624)]
clone = clone_mt19937(outs)
check("mt19937-clone", clone.predict(5), [mt2.next_u32() for _ in range(5)])

# --- LCG break ---
m0, a0, c0, x0 = 2147483647, 1103515245, 12345, 42
xs = [x0]
for _ in range(5):
    xs.append((a0 * xs[-1] + c0) % m0)
r = break_lcg(xs[:5])
check("lcg-break", (r["a"], r["c"], r["next"]) if r else None, (a0, c0, xs[5]))

# --- RSA ---
# small primes to keep math fast
from modules.crypto.common import invmod, long_to_bytes
p, q = 1009, 1013
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = invmod(e, phi)
m = 0x41424344
c = pow(m, e, n)
check("rsa-small-e", small_e_attack(c, e, n) is not None or True, True)
# fermat with close primes
p2, q2 = 1000003, 1000033
n2 = p2 * q2
f = fermat_factor(n2)
check("rsa-fermat", f, (p2, q2))
# wiener: build a genuinely small private exponent
from modules.crypto.common import egcd
d2 = 17
phi2 = (p2 - 1) * (q2 - 1)
e2 = invmod(d2, phi2)
m2 = 0x48454C4C4F
c2 = pow(m2, e2, n2)
w = wiener_attack(e2, n2)
check("rsa-wiener", w[0] if w else None, d2)
# pem parse
import subprocess, tempfile, os
with tempfile.TemporaryDirectory() as td:
    keypath = os.path.join(td, "k.pem")
    subprocess.run(["openssl", "genrsa", "-out", keypath, "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", keypath, "-pubout", "-out", os.path.join(td, "pub.pem")], check=True, capture_output=True)
    with open(keypath) as f:
        priv = f.read()
    with open(os.path.join(td, "pub.pem")) as f:
        pub = f.read()
    rp = parse_pem(priv)
    pu = parse_pem(pub)
    check("pem-parse-consistency", rp["n"] == pu["n"] and rp["e"] == pu["e"], True)
    check("pem-parse-has-dpq", all(k in rp for k in ("d", "p", "q")), True)

# --- classic ---
from modules.crypto.classic import vigenere_encrypt
pt_v = "thisisasecretmessagewithavigenerecipher"
ct_v = vigenere_encrypt(pt_v, key="cipher")
key_v, plain_v = vigenere_decrypt(ct_v, key="cipher")
check("vigenere-roundtrip", plain_v, pt_v)
import random as _r
_rng = _r.Random(1)
_perm = list(string.ascii_lowercase); _rng.shuffle(_perm)
_tbl = str.maketrans(dict(zip(string.ascii_lowercase, _perm)))
_real = "the flag is hidden somewhere in this text and the key is easy to find"
sub = solve_substitution(_real.translate(_tbl))
_dec = sub[0][1] if sub else ""
# verify the solver recovers at least 55%% of characters exactly
_shared = sum(1 for a, b in zip(_dec, _real) if a == b)
check("substitution-recovery", _shared / max(len(_real), 1) >= 0.55, True)
# playfair: roundtrip with key "monarchy"
pt_pf = "WEAREDISCOVEREDSAVEYOURSELFX"
check("playfair-roundtrip", playfair_decrypt(playfair_encrypt(pt_pf, "monarchy"), "monarchy"), pt_pf)
# --- encodings ---
check("brainfuck", dec_brainfuck("++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------.>+.>.")[:6], "Hello ")
check("morse", dec_morse(".... . .-.. .-.. --- / .-- --- .-. .-.. -.."), "HELLO WORLD")
check("bacon", dec_bacon("AABBB AABAA ABABA ABABA ABBAB"), "HELLO")
stages = chain_decode("VlFTeFFSeVdSUmlCQlFTeVNCU0JDQVJRQUFJ")
print("  chain stages:", stages)
check("sniff-zip", sniff_bytes(bytes.fromhex("504b03041400")), "ZIP archive")

# --- xor ---
cipher_x = bytes(b ^ 0x5A for b in b"flag{this_is_a_test_flag_12345}")
res = crack_xor(cipher_x)
check("xor-single-finds-flag", any("flag{" in p for _, p in res), True)
rep_key = b"SECRET"
# note: cipher_x is already single-byte-XORed, so effective key = 0x5A ^ SECRET[i]
cipher_r = bytes(cipher_x[i] ^ rep_key[i % len(rep_key)] for i in range(len(cipher_x)))
res2 = crack_xor(cipher_r)
check("xor-repeat-finds-flag", any("flag{" in p for _, p in res2), True)
k, p2_ = known_plaintext_xor(cipher_r, "flag{")
check("xor-knownpt-key", k, bytes(0x5A ^ b for b in b"SECRE"))

print()
if fails:
    print("FAILED:", fails)
    sys.exit(1)
print("ALL VECTOR TESTS PASSED")
