"""Flag detection — knows 100+ CTF flag prefixes plus a generic fallback."""
import re

# fmt: off
_KNOWN = (
    r"flag|FLAG|Flag|ctf|CTF|picoCTF|PicoCTF|picoctf|HTB|THM|n00bz|"
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
    rf"(?<![A-Za-z0-9])(?:picoCTF|PicoCTF|HTB|THM|n00bz|DUCTF|FLAG|flag|CTF)[-_][A-Za-z0-9_\-]{{4,120}}"
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


# Challenges plant decoy flags to punish blind grepping: packet captures, images and
# web pages carry marker text such as "<<DECOY - NOT THE REAL FLAG, DO NOT SUBMIT>>"
# right next to the fake value.  Reporting those as findings is worse than useless.
_DECOY_RE = re.compile(
    r"(?i)(?:<<\s*decoy|\bdecoy\w*|not[_ -]the[_ -]real[_ -]flag|not[_ -]the[_ -]flag|"
    r"do[_ -]not[_ -]submit|fake[_ -]?flag|false[_ -]?flag|wrong[_ -]?flag|"
    r"dummy[_ -]?flag|decoy[_ -]?flag|is[_ -]?only[_ -]?the[_ -]?decoy|"
    r"not[_ -]?real|placeholder[_ -]?flag|example[_ -]?flag)"
)


def is_decoy_flag(value, context=""):
    """True when a flag-shaped string (or its surrounding text) is marked as a decoy."""
    return bool(_DECOY_RE.search(str(value or ""))) or bool(_DECOY_RE.search(str(context or "")))


def decoy_flags(text, before=16, after=24):
    """Return flag-shaped strings that the artifact itself marks as decoys.

    Decoys are annotated *in place* (``FLAG{...} <<DECOY - NOT THE REAL FLAG>>``),
    so only the same line around a match is inspected: a marker on another line
    must not invalidate a real flag that happens to follow one.
    """
    if not text:
        return []
    out = []
    for pattern in (FLAG_RE, _NAKED_RE, CANDIDATE_RE):
        for match in pattern.finditer(text):
            value = match.group(0)
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end < 0:
                line_end = len(text)
            lead = text[max(line_start, match.start() - before):match.start()]
            trail = text[match.end():min(line_end, match.end() + after)]
            if is_decoy_flag(value, lead + " " + trail):
                out.append(value)
    return sorted(set(out))


# Characters that signal a wrong decode when they pile up in a flag body.
_STRONG_SYMBOLS = set("~`!@#$%^&*()=+[]|\\;:'\"<>?")


def _garbled_body(body):
    """Decode garbage often forms flag lookalikes (``ctf{htet5##Oe@CwcAESEEEEAEaw}``).

    Real flag bodies rarely repeat the same character four times in a row, and
    those runs are the signature of a wrong decode being wrapped in braces.
    """
    return bool(re.search(r"(.)\1\1\1", body))


def _symbol_storm(body):
    """True when a body carries two or more decodes-only symbol characters."""
    return sum(1 for c in body if c in _STRONG_SYMBOLS) >= 2


_DOMAIN_BODY_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def looks_like_ioc_flag(value):
    """True when a flag-shaped string is really an indicator, not an answer.

    Challenge authors hide values such as
    ``CYBERHEROCTF{drp32k77.todoinfonet.com}`` inside binaries as a decoy: the
    domain is the lead (look it up), the wrapped string is never the answer.
    """
    text = str(value or "")
    if "{" not in text or "}" not in text:
        return False
    body = text[text.find("{") + 1:text.rfind("}")]
    return bool(_DOMAIN_BODY_RE.match(body))


def _repeated_token(body):
    """True when a body is one token repeated three or more times."""
    for size in range(2, len(body) // 2 + 1):
        if len(body) % size == 0 and body == body[:size] * (len(body) // size):
            return True
    return False


def looks_like_noise_flag(value):
    """Brace-shaped text that is almost certainly decode/LSB noise.

    Bit-plane, LSB and XOR hunts over compressed or random data emit thousands
    of brace-shaped ghosts such as ``CJ{oint}`` or
    ``Metaspolit{metaspolitmetaspolit}``.  Callers hunting raw planes should
    drop these instead of showing them as findings; ordinary text sources are
    left alone because short real flags do exist.
    """
    text = str(value or "")
    if "{" not in text or "}" not in text:
        return False
    body = text[text.find("{") + 1:text.rfind("}")]
    if len(body) < 4:
        return True
    if re.search(r"(.)\1\1\1", body):
        return True
    if _repeated_token(body):
        return True
    # A short body with no structure (no underscore, no digits) is the shape of
    # a random brace pair, not a flag: 'oint', 'cOcc', 'jgtcpI'.
    return len(body) < 8 and "_" not in body and not any(c.isdigit() for c in body)


# A decoded payload is not required to use a known flag prefix: competitions
# invent prefixes (``CYBERHEROCTF``, ``AegisCTF``) and chain stages such as a
# pre-ROT13 ``PLOREUREBPGS{...}`` are still worth showing.  Only shapes that
# are provably decode noise are removed here.
_DECODED_MIN_RATIO = 0.6


def extract_decoded(text, limit=60):
    """Brace-shaped strings recovered by a decoder, in *any* flag format.

    The scanner deliberately does not impose a flag format.  Known-prefix
    answers come first, then every other brace-shaped result that is not a
    decoy and not provable noise, so a run can be read as "whatever it
    decoded" instead of "whatever matched the vocabulary".
    """
    if not text:
        return []
    text = str(text)
    known = set(FLAG_RE.findall(text))
    out = []
    for match in CANDIDATE_RE.finditer(text):
        value = match.group(0)
        if len(value) > 320 or len(value) < 6:
            continue
        if _has_code_artifacts(value) or _body_ratio(value) < _DECODED_MIN_RATIO:
            continue
        if looks_like_noise_flag(value) or is_decoy_flag(value):
            continue
        out.append(value)
    # Known prefixes and plausible bodies rank first so a real answer is never
    # buried under incidental brace pairs from the same buffer.
    return sorted(dict.fromkeys(out),
                  key=lambda v: (v not in known, not _plausible_candidate(v), v))[:limit]


_GENERIC_PREFIX_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,29}$")


def _plausible_candidate(value):
    """Generic brace-wrapped candidates must at least look like a flag name.

    Heuristic decoders produce gems such as ``00200{H005}``, ``eeee{ee}`` and
    ``22{U2e2pMEc22c}``; reporting those as flags wastes a competition run.
    """
    start = value.find("{")
    end = value.rfind("}")
    if start < 0 or end <= start:
        return False
    prefix, body = value[:start], value[start + 1:end]
    if not _GENERIC_PREFIX_RE.match(prefix):
        return False
    if len(body) < 3 or len(set(body)) < 2:
        return False
    # A real flag body always carries some letters (leetspeak included).
    return any(ch.isalpha() for ch in body)


def looks_plausible_flag(value):
    """Reject brace-wrapped decode garbage while keeping real flag syntax.

    Both conditions must hold to reject, so leet bodies with repeated digits
    (``ctf{a0000b11}``) and symbolic-but-readable bodies (``ctf{!@#complex}``)
    survive; only strings that are *both* repetitive and symbol-heavy (the
    signature of a heuristic solver guessing the wrong transform) are dropped.
    """
    text = str(value or "")
    if "{" not in text or "}" not in text:
        return True
    body = text[text.find("{") + 1:text.rfind("}")]
    if not body:
        return False
    return not (_garbled_body(body) and _symbol_storm(body))


def extract_flags(text, include_candidates=True):
    """Return (known_flags, candidate_flags) as sorted unique lists.

    Decoys are excluded from both lists; use :func:`decoy_flags` when the
    caller wants to report that it deliberately ignored something.
    """
    if not text:
        return [], []
    known = sorted(set(FLAG_RE.findall(text)) | set(_NAKED_RE.findall(text)))
    candidates = sorted(set(CANDIDATE_RE.findall(text)) - set(known)) if include_candidates else []
    # Strict filtering for candidates: high body ratio + no code artifacts + reasonable length
    candidates = [c for c in candidates if
                  _body_ratio(c) >= 0.85 and
                  not _has_code_artifacts(c) and
                  len(c) < 200 and
                  len(c) > 5 and
                  _plausible_candidate(c) and
                  not _garbled_body(c[c.find("{") + 1:c.rfind("}")])]
    decoys = set(decoy_flags(text))
    known = [value for value in known
             if value not in decoys and looks_plausible_flag(value)]
    candidates = [value for value in candidates if value not in decoys]
    return known, candidates


def extract_flags_with_decoys(text, include_candidates=True):
    """Return ``(known, candidates, decoys)`` for evidence-aware callers."""
    known, candidates = extract_flags(text, include_candidates=include_candidates)
    decoys = decoy_flags(text)
    # known/candidates were filtered against decoys already; recompute the
    # decoy list only from strings that also matched a flag shape.
    return known, candidates, decoys


# known prefixes sorted longest-first for brace-wrapping below
_KNOWN_PREFIXES = sorted(set(_KNOWN.split("|")) - {""}, key=len, reverse=True)


def known_prefixes():
    """Return the built-in prefix vocabulary without braces.

    Solvers can use this for cribs, but must not manufacture a flag with a
    hard-coded competition prefix when the challenge did not provide one.
    """
    return tuple(_KNOWN_PREFIXES)


def normalize_prefix(prefix):
    """Normalize UI/CLI prefix input to the canonical ``name{`` form.

    Users may enter ``ctf``, ``ctf{`` or ``ctf{...}``; only the prefix name
    is retained. Empty input means no prefix hint and never changes default
    flag detection behavior.
    """
    value = str(prefix or "").strip().strip("`'\" ")
    if "{" in value:
        value = value.split("{", 1)[0]
    value = value.rstrip("_") if value.endswith("_{") else value
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,30}", value):
        return ""
    return value + "{"


def infer_prefixes(text):
    """Infer flag prefixes explicitly present in an artifact or plaintext.

    Supports both ``picoCTF{...}``-style examples and hints such as
    ``flag_format: picoCTF{...}`` / ``prefix=HTB``.  Unknown prefixes are
    accepted when the challenge states them explicitly.  An empty result is
    intentional: callers should return a plaintext candidate instead of
    guessing a competition's flag format.
    """
    if not text:
        return []
    found = []
    seen = set()

    def add(prefix):
        prefix = (prefix or "").strip().strip("`'\"{}")
        if not re.fullmatch(r"[A-Za-z0-9_-]{2,30}", prefix):
            return
        key = prefix.lower()
        if key not in seen:
            seen.add(key)
            found.append(prefix + "{")

    # Any concrete braced flag, including an unknown event prefix, is the
    # strongest format signal available in a writeup/artifact.
    for match in re.finditer(r"(?<![A-Za-z0-9])([A-Za-z0-9_-]{2,30})\{", text):
        add(match.group(1))

    # Also understand metadata and prose commonly shipped with challenge
    # files: prefix=..., flag format: ..., expected: PREFIX{...}.
    for match in re.finditer(
            r"(?im)\b(?:flag[_ -]?format|flag[_ -]?prefix|prefix|template|expected)"
            r"\s*[:=]\s*([A-Za-z0-9_-]{2,30})", text):
        add(match.group(1))
    return found

_PREFIX_WRAP_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9])(?:{_KNOWN})[A-Za-z0-9_]{{4,120}}"
)


def wrap_known_prefix(text):
    """Some challenges hide the flag *without* braces (decoded plaintext like
    'SCRIPTCTFNOTWHATITSEEMS'). If a known flag prefix is immediately followed
    by more identifier chars, report it wrapped. Returns a list of wrapped flag strings.

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
