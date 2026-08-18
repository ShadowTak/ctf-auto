"""Modern crypto primitives in pure Python: AES (ECB/CBC), RC4, ChaCha20,
LCG breaking and MT19937 state cloning. No third-party deps required —
pycryptodome is used automatically if installed."""
import math
import struct

try:
    from Crypto.Cipher import AES as _PyAES  # type: ignore
    _HAS_PYCRYPTODOME = True
except ImportError:
    _PyAES = None
    _HAS_PYCRYPTODOME = False

# ---------------------------------------------------------------------------
# AES (pure python)
# ---------------------------------------------------------------------------
def _xtime(a):
    return ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _gpow(a, e):
    r = 1
    for _ in range(e):
        r = _gmul(r, a)
    return r


def _affine(b):
    r = b ^ ((b << 1) | (b >> 7)) ^ ((b << 2) | (b >> 6))
    r = r ^ ((b << 3) | (b >> 5)) ^ ((b << 4) | (b >> 4))
    return (r & 0xFF) ^ 0x63


_SBOX = bytes(_affine(_gpow(x, 254)) for x in range(256))
_INV_SBOX = bytes(_SBOX.index(i) for i in range(256))
_RCON = [0x01]
for _ in range(1, 15):
    _RCON.append(_xtime(_RCON[-1]))


def _rot_word(w):
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def _sub_word(w):
    return (_SBOX[(w >> 24) & 0xFF] << 24 |
            _SBOX[(w >> 16) & 0xFF] << 16 |
            _SBOX[(w >> 8) & 0xFF] << 8 |
            _SBOX[w & 0xFF])


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1]
        if i % nk == 0:
            t = _sub_word(_rot_word(t)) ^ (_RCON[i // nk] << 24)
        elif nk > 6 and i % nk == 4:
            t = _sub_word(t)
        w.append(w[i - nk] ^ t)
    return nr, [int.to_bytes(x, 4, "big") for x in w]


def _add_round_key(state, rk):
    for i in range(4):
        state[i] ^= rk[i]


def _encrypt_block(block, nr, rk):
    state = list(block)
    _add_round_key(state, rk[0])
    for rnd in range(1, nr):
        state = [_SBOX[b] for b in state]
        state = _shift_rows(state, forward=True)
        state = _mix_columns(state, forward=True)
        _add_round_key(state, rk[rnd])
    state = [_SBOX[b] for b in state]
    state = _shift_rows(state, forward=True)
    _add_round_key(state, rk[nr])
    return bytes(state)


def _decrypt_block(block, nr, rk):
    state = list(block)
    _add_round_key(state, rk[nr])
    state = _shift_rows(state, forward=False)
    state = [_INV_SBOX[b] for b in state]
    for rnd in range(nr - 1, 0, -1):
        _add_round_key(state, rk[rnd])
        state = _mix_columns(state, forward=False)
        state = _shift_rows(state, forward=False)
        state = [_INV_SBOX[b] for b in state]
    _add_round_key(state, rk[0])
    return bytes(state)


def _shift_rows(state, forward):
    out = state[:]
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        if forward:
            row = row[r:] + row[:r]
        else:
            row = row[-r:] + row[:-r]
        for c in range(4):
            out[r + 4 * c] = row[c]
    return out


def _mix_columns(state, forward):
    out = state[:]
    for c in range(4):
        a = state[4 * c:4 * c + 4]
        if forward:
            out[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            out[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            out[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            out[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        else:
            out[4 * c + 0] = (_gmul(a[0], 14) ^ _gmul(a[1], 11) ^
                              _gmul(a[2], 13) ^ _gmul(a[3], 9))
            out[4 * c + 1] = (_gmul(a[0], 9) ^ _gmul(a[1], 14) ^
                              _gmul(a[2], 11) ^ _gmul(a[3], 13))
            out[4 * c + 2] = (_gmul(a[0], 13) ^ _gmul(a[1], 9) ^
                              _gmul(a[2], 14) ^ _gmul(a[3], 11))
            out[4 * c + 3] = (_gmul(a[0], 11) ^ _gmul(a[1], 13) ^
                              _gmul(a[2], 9) ^ _gmul(a[3], 14))
    return out


def _pkcs7_pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data):
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def aes_ecb(data, key, decrypt=True):
    """AES-128/192/256 ECB. encrypt() pads with PKCS7, decrypt() unpads
    when padding is valid."""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes")
    if _HAS_PYCRYPTODOME:
        if decrypt:
            return _pkcs7_unpad(_PyAES.new(key, _PyAES.MODE_ECB).decrypt(data))
        data = data if len(data) % 16 == 0 else _pkcs7_pad(data)
        return _PyAES.new(key, _PyAES.MODE_ECB).encrypt(data)
    nr, rk = _expand_key(key)
    if decrypt:
        data = data if len(data) % 16 == 0 else _pkcs7_pad(data)
        out = b"".join(_decrypt_block(data[i:i + 16], nr, rk)
                       for i in range(0, len(data), 16))
        return _pkcs7_unpad(out)
    data = _pkcs7_pad(data)
    return b"".join(_encrypt_block(data[i:i + 16], nr, rk)
                    for i in range(0, len(data), 16))


def aes_cbc(data, key, iv, decrypt=True):
    """AES-128/192/256 CBC. encrypt() pads with PKCS7, decrypt() unpads
    when padding is valid."""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes")
    if len(iv) != 16:
        raise ValueError("AES IV must be 16 bytes")
    if _HAS_PYCRYPTODOME:
        if decrypt:
            return _pkcs7_unpad(_PyAES.new(key, _PyAES.MODE_CBC, iv).decrypt(data))
        data = data if len(data) % 16 == 0 else _pkcs7_pad(data)
        return _PyAES.new(key, _PyAES.MODE_CBC, iv).encrypt(data)
    nr, rk = _expand_key(key)
    if decrypt:
        data = data if len(data) % 16 == 0 else _pkcs7_pad(data)
        prev = iv
        out = bytearray()
        for i in range(0, len(data), 16):
            block = _decrypt_block(data[i:i + 16], nr, rk)
            out.extend(bytes(a ^ b for a, b in zip(block, prev)))
            prev = data[i:i + 16]
        return _pkcs7_unpad(bytes(out))
    data = _pkcs7_pad(data)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _encrypt_block(block, nr, rk)
        out.extend(enc)
        prev = enc
    return bytes(out)


# ---------------------------------------------------------------------------
# RC4
# ---------------------------------------------------------------------------
def rc4(data, key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


# ---------------------------------------------------------------------------
# ChaCha20 (IETF: 32-byte key, 12-byte nonce, 32-bit counter)
# ---------------------------------------------------------------------------
def _chacha_quarter(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << 16) | (d >> 16)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ((b << 12) | (b >> 20)) & 0xFFFFFFFF
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << 8) | (d >> 24)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ((b << 7) | (b >> 25)) & 0xFFFFFFFF
    return a, b, c, d


def _chacha_block(key, counter, nonce):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state = constants + list(struct.unpack("<8I", key)) + [counter] + \
        list(struct.unpack("<3I", nonce))
    working = state[:]
    for _ in range(10):
        working[0], working[4], working[8], working[12] = _chacha_quarter(
            working[0], working[4], working[8], working[12])
        working[1], working[5], working[9], working[13] = _chacha_quarter(
            working[1], working[5], working[9], working[13])
        working[2], working[6], working[10], working[14] = _chacha_quarter(
            working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = _chacha_quarter(
            working[3], working[7], working[11], working[15])
        working[0], working[5], working[10], working[15] = _chacha_quarter(
            working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = _chacha_quarter(
            working[1], working[6], working[11], working[12])
        working[2], working[7], working[8], working[13] = _chacha_quarter(
            working[2], working[7], working[8], working[13])
        working[3], working[4], working[9], working[14] = _chacha_quarter(
            working[3], working[4], working[9], working[14])
    return b"".join(struct.pack("<I", (working[i] + state[i]) & 0xFFFFFFFF)
                    for i in range(16))


def chacha20(data, key, nonce, counter=0):
    """XOR data with ChaCha20 keystream. Returns bytes."""
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    out = bytearray()
    block_idx = counter
    for off in range(0, len(data), 64):
        ks = _chacha_block(key, block_idx, nonce)
        block_idx += 1
        chunk = data[off:off + 64]
        out.extend(bytes(a ^ b for a, b in zip(chunk, ks)))
    return bytes(out)


# ---------------------------------------------------------------------------
# LCG breaking
# ---------------------------------------------------------------------------
def break_lcg(outputs, m=None):
    """outputs: list of consecutive LCG outputs. If m is unknown it is
    recovered via the gcd of t_i*t_{i+2}-t_{i+1}^2 relations (common
    cofactors stripped). Returns {"m","a","c","next"} or None."""
    if len(outputs) < 4:
        return None
    ts = [outputs[i + 1] - outputs[i] for i in range(len(outputs) - 1)]
    pairs = [abs(ts[i] * ts[i + 2] - ts[i + 1] * ts[i + 1])
             for i in range(len(ts) - 2)]
    if m is None:
        if not pairs:
            return None
        m = 0
        for d in pairs:
            m = math.gcd(m, d)
        if m == 0:
            return None
        # strip common cofactor: true m must still divide every pair
        p = 2
        while p * p <= m:
            while m % p == 0:
                cand = m // p
                if all(v % cand == 0 for v in pairs):
                    m = cand
                else:
                    break
            p += 1 if p == 2 else 2
    # find a = t_{i+1} * inv(t_i) mod m for the first invertible t_i
    a = None
    for i in range(len(ts) - 1):
        if math.gcd(ts[i], m) != 1:
            continue
        cand = (ts[i + 1] * pow(ts[i], -1, m)) % m
        if all((cand * ts[j]) % m == ts[j + 1] % m
               for j in range(len(ts) - 1)):
            a = cand
            break
    if a is None:
        return None
    c = (outputs[1] - a * outputs[0]) % m
    nxt = (a * outputs[-1] + c) % m
    return {"m": m, "a": a, "c": c, "next": nxt}


# ---------------------------------------------------------------------------
# MT19937 untemper
# ---------------------------------------------------------------------------
MT_N = 624
MT_M = 397
MT_MATRIX_A = 0x9908B0DF
MT_UPPER_MASK = 0x80000000
MT_LOWER_MASK = 0x7FFFFFFF


def _untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    # invert: y ^= (y << 7) & 0x9D2C5680
    t = y
    t = y ^ ((t << 7) & 0x9D2C5680)
    t = y ^ ((t << 7) & 0x9D2C5680)
    t = y ^ ((t << 7) & 0x9D2C5680)
    t = y ^ ((t << 7) & 0x9D2C5680)
    y = t
    # invert: y ^= (y >> 11)
    t = y
    t = y ^ (t >> 11)
    t = y ^ (t >> 11)
    t = y ^ (t >> 11)
    return t


def clone_mt19937(outputs):
    """Clone MT19937 state from 624 consecutive 32-bit outputs."""
    if len(outputs) < MT_N:
        return None
    mt = [_untemper(o & 0xFFFFFFFF) for o in outputs[:MT_N]]
    return MT19937(mt=mt)


class MT19937:
    def __init__(self, seed=None, mt=None):
        self.mt = [0] * MT_N
        self.index = MT_N
        if mt is not None:
            self.mt = mt[:]
            return
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, MT_N):
            self.mt[i] = (1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & 0xFFFFFFFF

    def _twist(self):
        for i in range(MT_N):
            y = ((self.mt[i] & MT_UPPER_MASK) |
                 (self.mt[(i + 1) % MT_N] & MT_LOWER_MASK))
            self.mt[i] = self.mt[(i + MT_M) % MT_N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= MT_MATRIX_A
        self.index = 0

    def next_u32(self):
        if self.index >= MT_N:
            self._twist()
        y = self.mt[self.index]
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        self.index += 1
        return y & 0xFFFFFFFF

    def predict(self, n):
        return [self.next_u32() for _ in range(n)]
