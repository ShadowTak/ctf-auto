"""Flag detection — knows 100+ CTF flag prefixes plus a generic fallback."""
import re

# fmt: off
_KNOWN = (
    r"flag|FLAG|Flag|ctf|CTF|picoCTF|PicoCTF|picoctf|redacted|redacted|redactedCTF|HTB|THM|n00bz|"
    r"DUCTF|ductf|corctf|idek|ractf|crew|TBTL|INTIGRITI|PWNME|BambooFox|TAMUctf|"
    r"gigem|X-MAS|CJ|Hope|CSAW|grey|winterhack|ASIS|UTCTF|sp00ky|N0PS|vsctf|sdctf|"
    r"tjctf|rtcp|FwordCTF|ENO|AraCTF|SIT|downunderctf|buckeyectf|amateursCTF|"
    r"MapleCTF|BCACTF|sun|hackpack|wani|minectf|csictf|shaktictf|hgame|WMCTF|"
    r"DawgCTF|TCTF|CryptoHack|echoCTF|IRONCTF|TFC|Srdnlen|justCTF|PatriotCTF|"
    r"GPNCTF|KashiCTF|T3N4CI0US|NOXCTF|PCTF|RCTF|COMPFEST14|MOCSCTF|TCT|ISITDTU|"
    r"darkCTF|HarekazeCTF|MOCTF|NITCTF|ASCIS|BITSCTF|FlareOn|JISCTF|NKCTF|NUACTF|"
    r"SECCON|UMDCTF|XCTF|nactf|zh3r0|UiTHack|LITCTF|cvctf|hacktoday|SYC|zer0pts|"
    r"CDDC22|WPI|INS|shellmates|squ1rrel|LNC2023|KCTF|UWA|CUCTF|TFCCTF|watevr|"
    r"WolvCTF|SHCTF|KKS|JIS|midnight|cybergrabs|NICC|rarctf|bi0s|openECSC|"
    r"blazctf|Srdnlen|CSAWQual|Insomni|KAPO|KONAN|Metaspolit|b01lers|BYUCTF|"
    r"CyberApocalypse|DanteCTF|DawgCTF|KITCTF|MCTF|m0leCon|RGBCTF|SHELL|"
    r"STHACK|TCP1P|TFCCTF|TJWCTF|TRX|UMassCTF|WannaGame|we45|YBN|ZJUCTF|"
    r"scriptCTF|ScriptCTF|SCRIPTCTF|THCTT|thctt|THCTT24|THCTT2024|TCTT|tctt|"
    r"CYBERHEROCTF|cyberheroctf|CyberHeroCTF|NCSA|WPICTF|"
    r"WTCTT|wtctt|NCSA|ncsa|THAICTF|thaictf|CYBERTHON|cyberthon"
)
# fmt: on

# High confidence: known prefix + braces.
FLAG_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?:{_KNOWN})\{{[^}}\n]{{1,300}}\}}"
)
# Generic candidate: any word-ish prefix + braces (may over-match code).
CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z0-9_\-]{2,30}\{[^}\n]{1,300}\}"
)

# Also flags without braces sometimes (e.g. "picoCTF-xxx" / "FLAG_xxx").
_NAKED_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?:picoCTF|PicoCTF|redacted|redacted|HTB|THM|n00bz|DUCTF|FLAG|flag|CTF)[-_][A-Za-z0-9_\-]{{4,120}}"
)


def _body_ratio(flag):
    """Fraction of the braced body that is [A-Za-z0-9_]. Real flags are
    almost always alnum+underscore; decode garbage ('ctf{noe6:2?|}') isn't."""
    body = flag[flag.find("{") + 1:flag.rfind("}")]
    if not body:
        return 0.0
    good = sum(1 for c in body if c.isalnum() or c in "_-")
    return good / len(body)


def _has_code_artifacts(flag):
    """True if flag body contains JS/code artifacts like [ ], ( ), semicolons, etc."""
    body = flag[flag.find("{") + 1:flag.rfind("}")]
    # Real CTF flags never have these chars in the body
    code_chars = set("[]();:=+<>!&|/\\\"'`")
    return any(c in code_chars for c in body)


def extract_flags(text, include_candidates=True):
    """Return (known_flags, candidate_flags) as sorted unique lists."""
    if not text:
        return [], []
    known = sorted(set(FLAG_RE.findall(text)) | set(_NAKED_RE.findall(text)))
    candidates = sorted(set(CANDIDATE_RE.findall(text)) - set(known)) if include_candidates else []
    # Strict filtering for candidates: high body ratio + no code artifacts + reasonable length
    candidates = [c for c in candidates if
                  _body_ratio(c) >= 0.85 and
                  not _has_code_artifacts(c) and
                  len(c) < 200 and
                  len(c) > 5]
    return known, candidates


# known prefixes sorted longest-first for brace-wrapping below
_KNOWN_PREFIXES = sorted(set(_KNOWN.split("|")) - {""}, key=len, reverse=True)

_PREFIX_WRAP_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9])(?:{_KNOWN})[A-Za-z0-9_]{{4,120}}"
)


def wrap_known_prefix(text):
    """Some challenges hide the flag *without* braces (decoded plaintext like
    'redactedCTFnotwhatitseems' or 'SCRIPTCTFNOTWHATITSEEMS'). If a known flag
    prefix is immediately followed by more identifier chars, report it wrapped:
    redactedCTF{notwhatitseems}. Returns a list of wrapped flag strings.

    Also emits the lowercase-body variant (flag bodies are almost always
    lowercase — e.g. decoded 'SCRIPTCTFNOTWHATITSEEMS' must become
    scriptCTF{notwhatitseems}, not SCRIPTCTF{NOTWHATITSEEMS})."""
    out = []
    for m in _PREFIX_WRAP_RE.finditer(text or ""):
        tok = m.group(0)
        low = tok.lower()
        for prefix in _KNOWN_PREFIXES:
            pl = prefix.lower()
            if low.startswith(pl) and len(tok) > len(prefix):
                body = tok[len(prefix):]
                # try every matching prefix (not just the longest) — the
                # challenge's canonical prefix may be a mixed-case variant
                # like 'scriptCTF' which lowercases to the same stem
                out.append(f"{tok[:len(prefix)]}{{{body}}}")
                if body.isupper() and len(body) >= 4:
                    out.append(f"{tok[:len(prefix)]}{{{body.lower()}}}")
                # also try the prefix spelled exactly as in _KNOWN
                if prefix != tok[:len(prefix)] and prefix.isalnum():
                    out.append(f"{prefix}{{{body.lower() if body.isupper() else body}}}")
    return list(dict.fromkeys(out))


def looks_like_flag(s):
    """True if s is short enough / shaped like a flag (for ranking decodes)."""
    if not s:
        return False
    if FLAG_RE.fullmatch(s.strip()):
        return True
    return bool(CANDIDATE_RE.fullmatch(s.strip())) and len(s) < 400
