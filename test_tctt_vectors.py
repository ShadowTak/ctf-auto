"""TCTT-style vector tests for new decoders (base45/58/62/36, custom-base,
emoji, malbolge, ook). Run: python3 test_tctt_vectors.py"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.crypto import encodings as E

PASS = 0
FAIL = 0

def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}\n  got:  {got!r}\n  want: {want!r}")

# --- helpers (encoders for testing) ---
def _enc_base(s, alph):
    n = int.from_bytes(s if isinstance(s, bytes) else s.encode(), 'big')
    out = ''
    while n > 0:
        out = alph[n % len(alph)] + out
        n //= len(alph)
    return out

def _enc45(s):
    # RFC 9285: 2 bytes -> 3 chars, 1 byte -> 2 chars
    data = s.encode()
    out = []
    i = 0
    while i < len(data):
        if i + 1 < len(data):
            v = int.from_bytes(data[i:i+2], 'big')
            out.append(E._BASE45_ALPH[v % 45])
            out.append(E._BASE45_ALPH[(v // 45) % 45])
            out.append(E._BASE45_ALPH[v // (45*45)])
            i += 2
        else:
            v = data[i]
            out.append(E._BASE45_ALPH[v % 45])
            out.append(E._BASE45_ALPH[v // 45])
            i += 1
    return ''.join(out)

def _enc58(s):
    return _enc_base(s, E._BASE58_ALPH)

def _enc62(s):
    return _enc_base(s, E._BASE62_VARIANTS[0])

def _enc36(s):
    return _enc_base(s, E._BASE36_ALPH)

def _bf_to_ook(bf):
    m = {'>': ('.', '.'), '<': ('.', '?'), '+': ('.', '!'), '-': ('?', '.'),
         '.': ('?', '?'), ',': ('?', '!'), '[': ('!', '.'), ']': ('!', '?')}
    out = []
    for c in bf:
        if c in m:
            p1, p2 = m[c]
            out.append(f"Ook{p1} Ook{p2} ")
    return ''.join(out)

# --- base45 (RFC 9285 vectors: 'Hello!!' -> '%69 VD92EX0') ---
check("base45-rfc", E.dec_base45("%69 VD92EX0"), "Hello!!")
check("base45-roundtrip", E.dec_base45(_enc45("flag{base45}")), "flag{base45}")

# --- base58 ---
check("base58-roundtrip", E.dec_base58(_enc58(b"flag")), "flag")

# --- base62 + case-swap variant (THCTT Bad62) ---
check("base62-std", E.dec_base62(_enc62("flag{base62}")), "flag{base62}")
# Bad62: encode with standard (chunked, like python's base62 module),
# then lowercase the whole string — case-corruption needs the crib oracle
bad = E._b62_chunked_encode(b"flag{t0day_is_n07_g00d}").lower()
got = E.dec_base62_crib(bad)
print(f"  [info] Bad62 crib decode: {got!r}")
check("base62-bad62-crib", got is not None and "flag" in got, True)

# --- base36 ---
check("base36", E.dec_base36(_enc36("flag")), "flag")

# --- custom base: Thai alphabet (THCTT 2025 New Base64) ---
def thai_char_gen():
    char = [chr(i) for i in range(ord('ก'), ord('ก') + 47)]
    char += [chr(i) for i in range(ord('๐'), ord('๐') + 10)]
    char += [chr(i) for i in range(ord('0'), ord('0') + 10)]
    return char[:64]

def thai_b64encode(msg):
    char = thai_char_gen()
    hex_data = msg.encode().hex()
    msg_num = int(hex_data, 16)
    out = ''
    while msg_num > 0:
        out = char[msg_num % 64] + out
        msg_num //= 64
    return out + '=='

thai_enc = thai_b64encode("flag{thai_custom_base64}")
print(f"  [info] thai enc: {thai_enc[:30]}...")
check("custom-thai-base64", E.dec_custom_base(thai_enc), "flag{thai_custom_base64}")

# --- emoji two-state (THCTT 2024 emoBit part 1) ---
def emoji2(msg):
    bits = ''.join(format(ord(c), '08b') for c in msg)
    return ''.join('😺' if b == '1' else '😸' for b in bits)

check("emoji-2state", E.dec_emoji(emoji2("flag{emoji_bits}")), "flag{emoji_bits}")

# --- emoji offset (THCTT 2024 emoBit part 2: ord(c)-0x1F3F7) ---
def emoji_off(msg):
    return ''.join(chr(ord(c) + 0x1F3F7) for c in msg)

check("emoji-offset", E.dec_emoji_offset(emoji_off("THCTT24{emoji_offset}")),
      "THCTT24{emoji_offset}")

# --- emoji base-100 / custom alphabet (emoji as base-N digits) ---
def emoji_base100(msg):
    alph = [chr(0x1F400 + i) for i in range(100)]
    n = int.from_bytes(msg.encode(), 'big')
    out = ''
    while n > 0:
        out = alph[n % 100] + out
        n //= 100
    return out

check("emoji-base100", E.dec_emoji(emoji_base100("flag{base100}")),
      "flag{base100}")

# --- emoji substitution (THCTT 2024 Programming Easy2 style) ---
def emoji_subst(msg):
    emojis = [chr(0x1F600 + i) for i in range(26)]
    m = {chr(ord('A') + i): emojis[i] for i in range(26)}
    return ''.join(m.get(c.upper(), c) for c in msg)

es = emoji_subst("HELLO WORLD THIS IS FLAG TEST")
got = E.dec_emoji_subst(es)
print(f"  [info] emoji subst decode: {got!r}")
check("emoji-subst", got is not None and "HELLO WORLD" in got, True)

# --- Ook! ---
BF = ("++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>."
      ">---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.")
check("ook-roundtrip", (E.dec_ook(_bf_to_ook(BF)) or "").rstrip("\n"), "Hello World!")

# --- Malbolge: canonical Hello World! program ---
MAL_HELLO = "(=<`#9]~6ZY32Vx/4Rs+0No-&Jk)\"Fh}|Bcy?`=*zXKwV]U:8Wp0[A_1cdO7{InaZ#vz5B3u+7Z1hXwqK%0Fh|jN~_i!~#e<kNbD0wzX5r:0~c"
got = E.dec_malbolge(MAL_HELLO)
print(f"  [info] malbolge hello: {got!r}")
check("malbolge-hello", got == "Hello World!", got == "Hello World!")

print(f"\n== {PASS} passed, {FAIL} failed ==")
sys.exit(1 if FAIL else 0)
