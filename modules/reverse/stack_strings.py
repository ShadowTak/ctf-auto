"""Recover strings a binary builds on the stack, one byte at a time.

Compiled challenges frequently refuse to keep the flag as a literal string.
Instead the program writes it byte by byte::

    mov byte ptr [rbp - 0x30], 0x43   ; C6 45 D0 43
    mov byte ptr [rbp - 0x2f], 0x59   ; C6 45 D1 59
    ...

``strings`` finds nothing, but the immediates *are* the message.  This module
scans for ``mov byte ptr [reg+disp], imm8`` encodings (opcode ``C6 /0``) and
turns the immediate bytes back into text.  No external disassembler required.
"""
import re

_MIN_RUN = 6

# C6 /0 ib — mov byte ptr [reg+disp], imm8.  The ModRM byte's low three bits
# select the register; rm == 100 means a SIB byte follows, which has its own
# layout.  mod == 01 selects a disp8, mod == 10 a disp32.
_NO_SIB_DISP8 = re.compile(rb"\xc6(?P<modrm>[\x40-\x7f])(?P<disp>.)(?P<imm>.)", re.S)
_NO_SIB_DISP32 = re.compile(rb"\xc6(?P<modrm>[\x80-\xbf])(?P<disp>....)(?P<imm>.)", re.S)
_SIB_DISP8 = re.compile(rb"\xc6(?P<modrm>[\x44\x4c\x54\x5c\x64\x6c\x74\x7c])"
                        rb"(?P<sib>.)(?P<disp>.)(?P<imm>.)", re.S)
_SIB_DISP32 = re.compile(rb"\xc6(?P<modrm>[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc])"
                         rb"(?P<sib>.)(?P<disp>....)(?P<imm>.)", re.S)

_PATTERNS = (_SIB_DISP32, _SIB_DISP8, _NO_SIB_DISP32, _NO_SIB_DISP8)


def _collect_immediates(data):
    """Immediate bytes from every frame-store instruction, in file order."""
    hits = []
    for pattern in _PATTERNS:
        for match in pattern.finditer(data):
            if pattern in (_NO_SIB_DISP8, _NO_SIB_DISP32):
                if match.group("modrm")[0] & 7 == 4:
                    continue  # actually a SIB form, handled by its own pattern
            hits.append((match.start(), match.group("imm")[0]))
    hits.sort()
    return [byte for _, byte in hits]


def recover_stack_strings(data, min_run=_MIN_RUN):
    """Return printable strings assembled from stack-store immediates."""
    runs, current = [], bytearray()
    for byte in _collect_immediates(data):
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= min_run:
                runs.append(current.decode("latin-1"))
            current = bytearray()
    if len(current) >= min_run:
        runs.append(current.decode("latin-1"))
    # Longer runs first: the flag-shaped one is usually the real payload.
    return sorted(set(runs), key=len, reverse=True)
