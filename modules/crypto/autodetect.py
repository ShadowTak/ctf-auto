"""Crypto auto-detection: feeds the input to every solver in parallel,
ranks the outputs by English-ness and flag-ness, and prints the best hits."""
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from core import flag as flaglib
from core.output import flag_line, info_line, ok_line, section, warn_line
from . import encodings
from . import classic
from . import hashes as hashes_mod
from . import xor as xor_mod
from .common import score_candidates, text_score

MAX_CANDIDATES = 25


def _rank(candidates):
    """candidates: list of (label, text) or (score, label, text).
    Returns ranked (score, label, text)."""
    scored = []
    for entry in candidates:
        if not entry:
            continue
        if len(entry) == 3:
            pre_score, label, text = entry
        else:
            pre_score, label, text = None, entry[0], entry[1]
        if not text:
            continue
        try:
            s = text_score(text)
        except Exception:
            s = float("inf")
        if s == float("inf"):
            continue
        scored.append((s, label, text))
    scored.sort(key=lambda x: x[0])
    return scored[:MAX_CANDIDATES]


def _flag_hits(text):
    known, cands = flaglib.extract_flags(text)
    wrapped = flaglib.wrap_known_prefix(text)
    return known + cands + wrapped


def _try_rsa_params(text):
    """If the input looks like an RSA parameter dump (n=/e=/c= or space
    separated), run the RSA attacks."""
    from . import rsa as rsa_mod

    vals = {}
    # pattern: n = <digits> (also "n:", "n:" etc.)
    for key in ("n", "e", "c", "d", "p", "q"):
        m = re.search(rf"(?im)^\s*{key}\s*[=:]\s*(\d+)\s*$", text)
        if m:
            vals[key] = int(m.group(1))
    if not vals:
        # maybe plain space-separated ints: n e c
        toks = re.findall(r"\d{30,}", text)
        if len(toks) >= 2 and len(toks) <= 6 and "n" not in vals:
            if len(toks) >= 3:
                vals = {"n": int(toks[0]), "e": int(toks[1]), "c": int(toks[2])}
            elif len(toks) == 2:
                vals = {"n": int(toks[0]), "e": int(toks[1])}
    if "n" not in vals or "e" not in vals:
        return []
    results = []
    for label, pt in rsa_mod.crack_rsa(
        n=vals.get("n"), e=vals.get("e"), c=vals.get("c"),
        d=vals.get("d"), p=vals.get("p"), q=vals.get("q"),
    ):
        try:
            text_out = pt.decode("utf-8", "replace")
        except Exception:
            text_out = repr(pt)
        results.append((f"rsa-{label}", text_out))
    return results


_PAYLOAD_LABEL_RE = re.compile(
    r"(?im)^\s*(?:cipher|ciphertext|enc(?:rypted)?|message|flag|data|hidden|secret|hex|b64|base64)[a-z0-9_]*\s*[:=]\s*(.+?)\s*$"
)


def _labeled_payloads(text):
    """Extract payloads written after common labels ('cipher: XYZ').
    Many crypto challenges ship a comment header + 'cipher: <data>';
    feeding the *label value* to the solvers instead of the whole file
    (whose header pollutes key recovery) is what cracks them."""
    out = []
    for m in _PAYLOAD_LABEL_RE.finditer(text):
        payload = m.group(1).strip().strip("`'\"")
        if payload and payload != text.strip() and len(payload) >= 4:
            out.append(payload)
    return out


def analyze_text(text):
    """Run every solver; return ranked results and flags found."""
    if not text or not text.strip():
        return [], []

    from .common import looks_like_encoding

    flags_from_labels = []
    encoded = looks_like_encoding(text)
    jobs = [
        ("encodings", lambda: encodings.try_all_encodings(text)),
        ("chain-decode", lambda: _chain_decode_job(text)),
        ("hash-crack", lambda: _hash_crack(text)),
        ("rsa-params", lambda: _try_rsa_params(text)),
        ("length-ext", lambda: _length_ext_job(text)),
        ("xor", lambda: xor_mod.crack_xor(text)),
    ]
    # Bacon's cipher is a 5-bit grouping over 0/1 (or A/B) — a binary-
    # looking string is *exactly* its signature, yet looks_like_encoding
    # classifies "100010..." as hex and skips the classic solvers. Run it
    # unconditionally on such inputs (cheap: groups of 5).
    if re.fullmatch(r"[01ABab\s]+", text.strip()) and len(text.strip()) >= 15:
        def _bacon_job():
            try:
                return [("bacon", classic.dec_bacon(text.strip()))]
            except Exception:
                return []

        jobs.append(("bacon", _bacon_job))
    if not encoded:
        # classic ciphers (caesar/vigenere/substitution/…) only make sense
        # on language-like text, not on base64/hex blobs
        jobs.append(("classic", lambda: classic.try_all_classic(text)))
        jobs.append(("vigenere-auto",
                     lambda: [("vigenere", classic.vigenere_decrypt(text)[1])]))
    else:
        # XOR ciphertext is frequently base64-wrapped — also run XOR on the
        # decoded layers, but LIGHT (single-byte + crib only; the full
        # repeating-key anneal on every decode is what made this explode)
        def _xor_on_decoded():
            out = []
            try:
                decoded = encodings.try_all_encodings(text)
                for label, dec in decoded[:3]:
                    for xlabel, xplain in xor_mod.single_byte_xor(dec, top=2):
                        out.append((f"xor-single-on-{label}", xplain))
                    for xlabel, xplain in xor_mod.crib_attack(dec)[:2]:
                        out.append((f"xor-crib-on-{label}", xplain))
            except Exception:
                pass
            return out

        jobs.append(("xor-decoded", _xor_on_decoded))
    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(fn): name for name, fn in jobs}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                items = fut.result()
            except Exception as exc:  # noqa: BLE001
                items = [(f"{name}-error", str(exc))]
            # exploit findings (e.g. forged length-extension MAC) are printed
            # directly — their binary-ish payloads never survive text ranking
            for it in items or []:
                if isinstance(it, (tuple, list)) and len(it) == 2 and \
                        it[0] == "hash-length-extension":
                    ok_line(f"  [i] {it[1]}")
            results.extend(items or [])

    # also run the whole pipeline on labeled payloads ('cipher: <data>') and
    # merge — the header around a payload wrecks classic-cipher key recovery
    for payload in _labeled_payloads(text):
        try:
            sub_ranked, sub_flags = analyze_text(payload)
            results.extend(sub_ranked)
            flags_from_labels.extend(sub_flags)
        except Exception:
            pass

    ranked = _rank(results)
    all_flags = []
    seen = set()
    # collect flags from EVERY solver output, not just the top-ranked 25 —
    # a cracked-hash flag like 'redactedCTF{chocolate}' scores poorly as text
    # but is the answer, and must never be dropped by the ranking cutoff
    for entry in results:
        if isinstance(entry, (tuple, list)) and entry:
            cand_text = entry[-1] if len(entry) >= 2 else str(entry)
            for f in _flag_hits(cand_text):
                if f not in seen:
                    seen.add(f)
                    all_flags.append(f)
    for f in flags_from_labels:
        if f not in seen:
            seen.add(f)
            all_flags.append(f)
    return ranked, all_flags


def _length_ext_job(text):
    """SHA-256 length extension: forge a MAC from a known (msg, mac) pair."""
    try:
        from . import length_ext
        return length_ext.detect_and_forge(text)
    except Exception:
        return []


def _chain_decode_job(text):
    """Layered-encoding chains, EXPLORING ALL DECODE PATHS (beam search).
    Multi-layer inputs (base64>hex>rot13>binary...) that greedy decoding
    misses are recovered here; flags at ANY layer are returned."""
    out = []
    try:
        for i, (name, cur) in enumerate(encodings.chain_decode(text), 1):
            out.append((f"chain[{i}]={name}", cur))
    except Exception:
        pass
    try:
        for path, cur in encodings.chain_decode_best(text)[:40]:
            out.append((f"chain-best({path})", cur))
    except Exception:
        pass
    return out


def _hash_crack(text):
    """Crack any hex hash found in the text. If the file carries a flag
    template like 'redactedCTF{<password>}', substitute the cracked value."""
    for h in re.findall(r"[0-9a-fA-F]{8,128}", text):
        names = hashes_mod.identify_hash(h)
        cracked = hashes_mod.crack_hash(h)
        if not cracked:
            continue
        out = [(f"hash({','.join(names[:3])})=cracked", cracked)]
        for m in re.finditer(r"([A-Za-z0-9_\-]{2,30})\{<password>\}", text):
            out.append((f"flag-template-{m.group(1)}",
                        f"{m.group(1)}{{{cracked}}}"))
        return out
    return []


def analyze_file(path, as_binary=None):
    """Analyze a file: text decoders, binary sniffing, strings scanning."""
    with open(path, "rb") as f:
        data = f.read()
    results = []
    flags = []

    # strings + embedded flags
    try:
        strings_out = _extract_strings(data)
    except Exception:
        strings_out = []
    for s in strings_out:
        for f in _flag_hits(s):
            if f not in flags:
                flags.append(f)

    # binary magic
    magic = encodings.sniff_bytes(data)
    if magic:
        results.append(("file-type", f"{path} -> {magic}"))

    # whole-file decoders
    text = data.decode("latin-1")
    if not as_binary:
        results.extend(encodings.try_all_encodings(text))
        results.extend(classic.try_all_classic(text))
        results.extend(xor_mod.crack_xor(text))

    # base64 blobs inside binary (common: flag hidden in base64 in png/zip)
    for m in re.finditer(rb"[A-Za-z0-9+/=]{40,}", data):
        blob = m.group(0)
        try:
            import base64
            raw = base64.b64decode(blob, validate=True)
            if encodings.sniff_bytes(raw) or b"flag" in raw.lower() or b"ctf" in raw.lower():
                for f in _flag_hits(raw.decode("latin-1", "replace")):
                    if f not in flags:
                        flags.append(f)
        except Exception:
            pass

    # zip members
    if data[:2] == b"PK":
        try:
            import io
            import zipfile
            zf = zipfile.ZipFile(io.BytesIO(data))
            for name in zf.namelist():
                inner = zf.read(name)
                for s in _extract_strings(inner):
                    for f in _flag_hits(s):
                        if f not in flags:
                            flags.append(f)
        except Exception:
            pass

    ranked = _rank(results)
    return ranked, flags


def _extract_strings(data, min_len=4):
    """Extract printable ASCII runs (like the `strings` command)."""
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127 or b in (9, 10, 13):
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


def run_crypto(target, interactive=False):
    """Public entry for the crypto category. target = file path or raw string."""
    section("🔐 CRYPTO AUTO-DETECT")
    info_line(f"target: {target}")

    if os.path.isfile(target):
        with open(target, "rb") as f:
            data = f.read()
        # try text decoders if the file looks textual, else binary analysis
        try:
            as_text = data.decode("utf-8")
            if sum(1 for c in as_text if c.isprintable()) / max(len(as_text), 1) > 0.8:
                ranked, flags = analyze_text(as_text)
                ranked2, flags2 = analyze_file(target, as_binary=True)
                ranked = ranked + [r for r in ranked2 if r not in ranked]
                flags = list(dict.fromkeys(flags + flags2))
            else:
                ranked, flags = analyze_file(target, as_binary=True)
        except Exception:
            ranked, flags = analyze_file(target, as_binary=True)
    else:
        ranked, flags = analyze_text(target)

    print()
    if flags:
        for f in flags:
            flag_line(f"FLAG: {f}")
    else:
        warn_line("ยังไม่เจอ flag โดยตรง — ดูผล decode ข้างล่าง")

    if ranked:
        print()
        ok_line(f"ผล decode ที่น่าสนใจ ({len(ranked)} อันดับแรก):")
        for i, (score, label, text) in enumerate(ranked[:12], 1):
            shown = text.strip().replace("\n", " ")[:120]
            print(f"  {i:2}. [{score:8.1f}] {label}: {shown}")
            if len(text) > 120:
                print(f"      ... (total {len(text)} chars)")
    else:
        warn_line("ไม่พบผล decode ที่เป็นไปได้ — ลองป้อนรูปแบบอื่น หรือใช้โหมดเฉพาะ")
    return flags
