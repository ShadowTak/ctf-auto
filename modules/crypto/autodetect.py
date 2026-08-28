"""Crypto auto-detection: feeds the input to every solver in parallel,
ranks the outputs by English-ness and flag-ness, and prints the best hits."""
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

from core import flag as flaglib
from core.evidence import EvidenceLedger, decode_trace
from core.output import flag_line, info_line, ok_line, section, warn_line
from . import encodings
from . import classic
from . import hashes as hashes_mod
from . import xor as xor_mod
from . import structured as structured_mod
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
        # gated crib decodes are high-precision — surface them first
        if label.startswith(("xor-crib", "crib")):
            s -= 1000.0
        elif label.startswith(("hash(", "kdf(")):
            # A verified dictionary/KDF match is stronger evidence than a
            # high-English-score heuristic decode.
            s -= 800.0
        scored.append((s, label, text))
    scored.sort(key=lambda x: x[0])
    return scored[:MAX_CANDIDATES]


def _filter_flag_families(flags):
    """Drop fabricated flag families: the SAME body appearing under >=3
    different prefixes is the fingerprint of blind crib sweeps on data
    that was never really XOR-with-that-prefix."""
    from collections import defaultdict
    fam_prefixes = defaultdict(set)
    parsed = []
    for f in flags:
        i, j = f.find("{"), f.rfind("}")
        body = f[i + 1:j] if 0 <= i < j else f
        key = "".join(c for c in body[:14] if c.isalnum()).lower()
        prefix = f[:i].lower() if i > 0 else ""
        parsed.append((f, key, prefix))
        fam_prefixes[key].add(prefix)
    out = []
    seen = set()
    for f, key, prefix in parsed:
        if key and len(fam_prefixes[key]) >= 3:
            continue
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _flag_hits(text):
    if isinstance(text, bytes):
        text = text.decode("latin-1", "replace")
    # Keep the decoded bytes literal.  The wrapped value below is only an
    # additional candidate for an explicit, known prefix already in the text.
    known, cands = flaglib.extract_flags(text)
    # Some challenges intentionally omit braces in the decoded plaintext
    # (for example SCRIPTCTFNOTWHATITSEEMS).  The prefix itself is explicit
    # evidence, so expose the canonical wrapped form alongside the literal
    # decode instead of losing the answer during flag collection.
    wrapped = flaglib.wrap_known_prefix(text)
    return list(dict.fromkeys(known + cands + wrapped))


def _verified_fast_hits(entries, prefix_hint=None):
    """Collect only high-signal hits for deterministic fast-path exits.

    Generic ``word{...}`` candidates are deliberately not enough to skip the
    rest of the pipeline: classic/XOR decoys frequently have that shape.  An
    explicit challenge prefix is accepted as strong evidence even when it is
    not part of the built-in competition vocabulary.
    """
    explicit = {p[:-1].lower() for p in flaglib.infer_prefixes(prefix_hint or "")
                if p.endswith("{")}
    hits = []
    for entry in entries or ():
        if not isinstance(entry, (tuple, list)) or len(entry) < 2:
            continue
        value = entry[-1]
        known, _ = flaglib.extract_flags(value, include_candidates=False)
        for item in known:
            if item not in hits:
                hits.append(item)
        if explicit:
            for item in _flag_hits(value):
                prefix = item.split("{", 1)[0].lower() if "{" in item else ""
                if prefix in explicit and item not in hits:
                    hits.append(item)
    return hits


def _try_rsa_params(text):
    """If the input looks like an RSA parameter dump (n=/e=/c= or space
    separated), run the RSA attacks."""
    from . import rsa as rsa_mod

    vals = {}
    # pattern: n = <digits> (also "n:", "n:" etc.)
    for key in ("n", "e", "c", "c1", "c2", "d", "p", "q", "delta"):
        m = re.search(rf"(?im)^\s*{key}\s*[=:]\s*(0x[0-9a-f]+|\d+)\s*$", text)
        if m:
            vals[key] = int(m.group(1), 0)
    # Also look for n1/n2 pattern (shared-prime RSA)
    n1_val = re.search(r"(?im)^\s*n1\s*[=:]\s*(\d+)\s*$", text)
    n2_val = re.search(r"(?im)^\s*n2\s*[=:]\s*(\d+)\s*$", text)
    if n1_val and n2_val:
        vals["n"] = int(n1_val.group(1))
        vals["n2"] = int(n2_val.group(1))
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
    if all(key in vals for key in ("c1", "c2", "delta")):
        recovered = rsa_mod.franklin_reiter(
            vals["c1"], vals["c2"], vals["n"], vals["e"], vals["delta"])
        if recovered is not None:
            results.append(("rsa-franklin-reiter",
                            rsa_mod.long_to_bytes(recovered).decode("utf-8", "replace")))
    for label, pt in rsa_mod.crack_rsa(
        n=vals.get("n"), e=vals.get("e"), c=vals.get("c"),
        d=vals.get("d"), p=vals.get("p"), q=vals.get("q"),
        n2=vals.get("n2"),
    ):
        try:
            text_out = pt.decode("utf-8", "replace")
        except Exception:
            text_out = repr(pt)
        results.append((f"rsa-{label}", text_out))
    return results


def _prefix_cribs(prefix_hint):
    """Turn explicit challenge metadata into a precise XOR crib."""
    if not prefix_hint:
        return None
    match = re.search(r"(?i)([A-Za-z0-9_-]{2,30})\s*\{", str(prefix_hint))
    return [match.group(1) + "{"] if match else None


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


_KEY_HINT_RE = re.compile(
    r"(?im)\b(?:key|keyword)\s*(?:hint\s*)?(?:is|=|:)\s*[`\"']?"
    r"([A-Za-z][A-Za-z0-9_-]{1,31})"
)


def _hinted_classic_results(text):
    """Use explicit key metadata from a challenge bundle.

    Auto key-recovery is necessarily heuristic and often loses on short
    Vigenere/Beaufort flags.  Challenge descriptions commonly disclose a key
    hint (``The key is ORANGE``), so consume that evidence when present and
    apply it to labeled payloads such as ``cipher: ...``.  This never guesses a
    key from ordinary ciphertext; it only acts on explicit metadata.
    """
    keys = [m.group(1) for m in _KEY_HINT_RE.finditer(text or "")]
    if not keys:
        return []
    payloads = _labeled_payloads(text) or [text.strip()]
    out = []
    for key in dict.fromkeys(keys):
        for payload in payloads:
            if not payload or len(payload) < 4:
                continue
            try:
                _, plain = classic.vigenere_decrypt(payload, key=key)
            except Exception:
                continue
            if plain and plain != payload:
                out.append((f"vigenere-explicit-key={key}", plain))
            # Some CTF authors advance the key over every ciphertext byte,
            # including punctuation, instead of only alphabetic characters.
            # Keep both interpretations; a flag-shaped result provides the
            # evidence needed to rank the intended convention.
            try:
                per_char = classic._decrypt_per_char(payload, key)
            except Exception:
                per_char = None
            if per_char and per_char != plain and per_char != payload:
                out.append((f"vigenere-explicit-key-per-char={key}", per_char))
    return out


_NESTED_KEY_RE = re.compile(
    r"(?i)(?:cipher|crypt|enc(?:rypted)?|payload|token|secret|hidden|blob|"
    r"message|data|value|content|private|public|key|nonce|iv|mac|hash)")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _nested_payloads(text, max_items=24):
    """Find encoded-looking leaf strings inside JSON/config artifacts.

    Structured attacks still receive the whole object.  This companion pass
    sends likely payload leaves through the complete decoder pipeline, which
    is important for records such as {"data": {"token": "b64(b64(flag))"}}.
    It is deliberately bounded and skips ordinary prose to keep the fast
    path fast and avoid classic-cipher noise.
    """
    import json
    from .common import looks_like_encoding

    try:
        root = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if not isinstance(root, (dict, list)):
        return []
    output, seen = [], set()

    def visit(value, path, depth=0, key_hint=""):
        if len(output) >= max_items or depth > 8:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, f"{path}.{key}", depth + 1, str(key))
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]", depth + 1, key_hint)
            return
        if not isinstance(value, str):
            return
        candidate = value.strip().strip("`'\"")
        if len(candidate) < 6 or len(candidate) > 20_000 or candidate in seen:
            return
        known, candidates = flaglib.extract_flags(candidate)
        encoded = looks_like_encoding(candidate)
        jwt_like = bool(_JWT_RE.fullmatch(candidate))
        key_like = bool(_NESTED_KEY_RE.search(key_hint))
        explicit = bool(known or candidates or jwt_like)
        if not (explicit or encoded or (key_like and len(candidate) >= 12)):
            return
        seen.add(candidate)
        output.append((path, candidate))

    visit(root, "$", 0)
    return output


def _nested_payload_job(text):
    results = []
    for path, payload in _nested_payloads(text):
        try:
            sub_ranked, sub_flags = analyze_text(payload)
        except Exception:
            continue
        for score, label, output in sub_ranked:
            results.append((score, f"json[{path}] -> {label}", output))
        # Direct flags are normally present in sub_ranked, but retain them as
        # a fallback when a solver exposes a flag only through its side list.
        for value in sub_flags:
            results.append((0.0, f"json[{path}] -> nested-flag", value))
    return results


def _fernet_job(text):
    """Fernet token detection + wordlist key brute."""
    try:
        from . import blockciphers
        from .common import looks_like_encoding as _enc
    except ImportError:
        return []
    out = []
    for tok in re.findall(r"gAAAA[A-Za-z0-9_\-]{40,}", text):
        hit = blockciphers.crack_fernet(tok, _wordlist_candidates())
        if hit:
            plain, key = hit
            out.append((f"fernet-cracked key={key!r}",
                        plain.decode("utf-8", "replace")))
    return out


@lru_cache(maxsize=8)
def _load_wordlist(path, mtime_ns):
    words = ["password", "secret", "secret_key", "changeme", "supersecret",
             "letmein", "welcome", "admin", "ctf", "flag"]
    if path:
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for i, line in enumerate(fh):
                    if i >= 200_000:
                        break
                    words.append(line.rstrip("\r\n"))
        except Exception:
            pass
    return tuple(words)


def _wordlist_candidates():
    """Shared wordlist for brute jobs (env ROCKYOU or bundled defaults)."""
    path = os.environ.get("ROCKYOU", "")
    try:
        mtime_ns = os.stat(path).st_mtime_ns if path else 0
    except OSError:
        mtime_ns = 0
    return _load_wordlist(path, mtime_ns)


def _prng_job(text):
    """Predict-the-next challenges from explicit generator metadata.

    Java/glibc were the original autodetect paths.  Wire the already-tested
    xorshift128+ implementation here as well; keeping the generator name
    mandatory prevents arbitrary integer lists from triggering an expensive
    SMT search.
    """
    from . import prng as prng_mod

    out = []

    def _int_list(m):
        return [int(x) for x in re.findall(r"-?\d+", m.group(1))]

    # V8/browser xorshift128+ outputs.  Full 64-bit outputs are preferred;
    # Math.random() floating-point recovery still needs a dedicated solver.
    xs_match = re.search(
        r"(?is)(?:xorshift128\+|xs128p|next_u64)[^\[]*[\[=]\s*"
        r"([\d\s,\n]{20,900})", text)
    if xs_match:
        vals = _int_list(xs_match)
        if len(vals) >= 6:
            try:
                gen = prng_mod.xs128p_recover(vals)
                if gen is not None:
                    out.append(("xorshift128+-recovered",
                                f"next={[gen.next_u64() for _ in range(3)]}"))
            except Exception:
                pass

    # java: consecutive nextInt() outputs
    m = re.search(
        r"(?is)(?:java|nextInt|next_int)[^\[]{0,80}[\[=]\s*([\d\s,\n]{6,400})",
        text)
    if m:
        vals = _int_list(m)
        for i in range(len(vals) - 2):
            seed = prng_mod.java_recover(vals[i], vals[i + 1])
            if seed is None:
                continue
            jr = prng_mod.JavaRandom(seed)
            replay = [jr.next_int() for _ in range(i, len(vals))]
            if replay != [v & 0xFFFFFFFF for v in vals[i:]]:
                break
            nxt = [jr.next_int() for _ in range(3)]
            out.append(("java-random-recovered",
                        f"seed={seed} next={nxt}"))
            break

    # glibc: srand seed + outputs
    m = re.search(r"(?is)srand\s*[=(]\s*(\d+)", text)
    mo = re.search(
        r"(?is)(?:outputs?|random(?:_numbers)?)[^\[]{0,60}[\[=:]\s*"
        r"([\d\s,\n]{6,400})", text)
    if mo:
        vals = _int_list(mo)
        seed = int(m.group(1)) if m else None
        if seed is not None:
            stream = prng_mod.glibc_rand_stream(seed, min(len(vals), 8))
            if stream == [v & 0x7FFFFFFF for v in vals[:len(stream)]]:
                pred = prng_mod.glibc_rand_stream(seed, len(vals) + 3)
                out.append(("glibc-rand",
                            f"srand({seed}) verified; next="
                            f"{pred[len(vals):len(vals)+3]}"))
        else:
            got_seed, predict = prng_mod.glibc_seed_brute(vals)
            if got_seed is not None:
                out.append(("glibc-rand-brute",
                            f"srand({got_seed}) matches; "
                            f"next={predict(3)}"))
    return out


def _analyze_text_uncached(text, prefix_hint=None):
    """Run every solver; return ranked results and flags found."""
    if not text or not text.strip():
        return [], []
    stripped = text.strip()
    direct_flags, _ = flaglib.extract_flags(stripped, include_candidates=False)
    if direct_flags and stripped == direct_flags[0]:
        return [(0.0, "direct", stripped)], direct_flags

    from .common import looks_like_encoding

    flags_from_labels = []
    encoded = looks_like_encoding(text)
    structured_input = bool(re.match(r"\s*[\[{]", text))
    kdf_input = bool(re.search(
        r"(?i)(?:pbkdf2_sha256|pbkdf2-sha(?:256|512)|\$argon2|\$scrypt\$)",
        text,
    ))
    parameter_input = bool(re.search(
        r"(?im)^\s*(?:n|p|g|e|c|cipher|ciphertext)\s*[=:]", text
    ))

    # Structured artifacts and RSA parameter dumps have deterministic,
    # verified solvers. Run those first and stop before generic factoring,
    # substitution, or chain jobs can consume minutes on the same input.
    if structured_input:
        fast_entries = structured_mod.analyze(text, prefix_hint=prefix_hint)
        fast_flags = _verified_fast_hits(fast_entries, prefix_hint)
        if fast_flags:
            return _rank(fast_entries), _filter_flag_families(
                list(dict.fromkeys(fast_flags))
            )
    elif parameter_input:
        fast_entries = _try_rsa_params(text)
        fast_flags = _verified_fast_hits(fast_entries, prefix_hint)
        if fast_flags:
            return _rank(fast_entries), _filter_flag_families(
                list(dict.fromkeys(fast_flags))
            )
    # Two-time pad detection: c1_hex = ... / c2_hex = ... pattern
    m1 = re.search(r'c1_hex\s*=\s*([0-9a-fA-F]+)', text)
    m2 = re.search(r'c2_hex\s*=\s*([0-9a-fA-F]+)', text)
    if m1 and m2:
        try:
            c1 = bytes.fromhex(m1.group(1))
            c2 = bytes.fromhex(m2.group(1))
            tt_results = xor_mod.two_time_pad_crib_drag(c1, c2)
            jobs_extra = [("two-time-pad", lambda: tt_results)]
        except Exception:
            jobs_extra = []
    else:
        jobs_extra = []

    jobs = [
        ("encodings", lambda: encodings.try_all_encodings(text)),
        ("explicit-key", lambda: _hinted_classic_results(text)),
        ("structured", lambda: structured_mod.analyze(text,
                                                       prefix_hint=prefix_hint)),
        ("nested-json", lambda: _nested_payload_job(text)),
        ("hash-crack", lambda: _hash_crack(text)),
        ("rsa-params", lambda: _try_rsa_params(text)),
        ("length-ext", lambda: _length_ext_job(text)),
        ("fernet", lambda: _fernet_job(text)),
        ("prng", lambda: _prng_job(text)),
        ("xor", lambda: xor_mod.crack_xor(
            text, prefixes=_prefix_cribs(prefix_hint))),
    ] + jobs_extra
    if structured_input or kdf_input or parameter_input:
        # The generic repeating-key XOR search is expensive and has a high
        # false-positive rate on deterministic parameter/KDF artifacts.
        jobs = [item for item in jobs if item[0] != "xor"]
    # Chain/classic/annealing solvers are valuable on free-form ciphertext,
    # but waste most of the time on JSON/KDF/parameter artifacts whose
    # structured path is deterministic and independently verifiable.
    if encoded or (not structured_input and not kdf_input and not parameter_input):
        jobs.append(("chain-decode", lambda: _chain_decode_job(text)))
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
    if not encoded and not structured_input and not kdf_input and not parameter_input:
        # classic ciphers (caesar/vigenere/substitution/…) only make sense
        # on language-like text, not on base64/hex blobs
        jobs.append(("classic", lambda: classic.try_all_classic(text)))
        jobs.append(("vigenere-auto",
                     lambda: [("vigenere", classic.vigenere_decrypt(text)[1])]))
    elif not structured_input and not kdf_input:
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
            except Exception:
                pass
            return out

        jobs.append(("xor-decoded", _xor_on_decoded))
    results = []
    with ThreadPoolExecutor(max_workers=6) as pool:
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
            sub_ranked, sub_flags = analyze_text(payload,
                                                  prefix_hint=prefix_hint)
            results.extend(sub_ranked)
            flags_from_labels.extend(sub_flags)
        except Exception:
            pass

    ranked = _rank(results)
    all_flags = []
    seen = set()
    # If a non-chain solver already produced a known-prefix flag, discard
    # generic brace-shaped ghosts from later ROT13/leet chain stages.  When
    # there is no such anchor, keep chain stages because the final plaintext
    # may genuinely be discovered at an intermediate-looking step (for
    # example hex -> rot13).
    known_nonchain = set()
    for entry in results:
        if not isinstance(entry, (tuple, list)) or len(entry) < 2:
            continue
        label = str(entry[0])
        if label.startswith(("chain[", "xor-", "classic", "vigenere")):
            continue
        for value in flaglib.extract_flags(entry[-1], include_candidates=False)[0]:
            known_nonchain.add(value)
    # collect flags from EVERY solver output, not just the top-ranked 25 —
    # a cracked-hash flag like 'picoCTF{chocolate}' scores poorly as text
    # but is the answer, and must never be dropped by the ranking cutoff
    for entry in results:
        if isinstance(entry, (tuple, list)) and entry:
            label = str(entry[0]) if len(entry) >= 2 else ""
            cand_text = entry[-1] if len(entry) >= 2 else str(entry)
            # Intermediate chain stages are useful in the ranked decode list,
            # but are not final answers and often create ROT13/leet ghosts of
            # a real flag.  Let chain-best/final solver results report them.
            if label.startswith("chain["):
                chain_hits = _flag_hits(cand_text)
                if known_nonchain:
                    chain_hits = [value for value in chain_hits
                                  if value in known_nonchain]
                for value in chain_hits:
                    if value not in seen:
                        seen.add(value)
                        all_flags.append(value)
                continue
            if label.startswith("xor-crib"):
                # A heuristic crib is useful decode output, but the guessed
                # prefix is not proof that this is a flag. Only a complete
                # prefix/key-period match may enter the flag list.
                if "xor-crib crib-verified" not in label:
                    continue
                for f in _flag_hits(cand_text):
                    if f not in seen:
                        seen.add(f)
                        all_flags.append(f)
                continue
            for f in _flag_hits(cand_text):
                if f not in seen:
                    seen.add(f)
                    all_flags.append(f)
    for f in flags_from_labels:
        if f not in seen:
            seen.add(f)
            all_flags.append(f)
    return ranked, _filter_flag_families(all_flags)


@lru_cache(maxsize=64)
def _analyze_text_cached(text):
    ranked, flags = _analyze_text_uncached(text)
    return tuple(ranked), tuple(flags)


def analyze_text(text, prefix_hint=None):
    """Cached public wrapper; return fresh lists for compatibility.

    Prefix hints are explicit challenge metadata and intentionally bypass the
    text-only cache so they never contaminate a standalone decode.
    """
    if not isinstance(text, str) or len(text) > 100_000:
        return _analyze_text_uncached(text, prefix_hint=prefix_hint)
    if prefix_hint:
        return _analyze_text_uncached(text, prefix_hint=prefix_hint)
    ranked, flags = _analyze_text_cached(text)
    return list(ranked), list(flags)


def analyze_text_evidence(text):
    """Analyze text and return rich findings without changing the legacy API.

    ``analyze_text`` remains the compatibility entry point returning
    ``(ranked, list[str])``.  This companion API labels deterministic flag
    extractions as verified, heuristic XOR cribs as candidates, and all other
    interesting plaintext as raw decode output.
    """
    ranked, legacy_flags = analyze_text(text)
    ledger = EvidenceLedger()
    observed = set()

    def deterministic_label(label):
        """Only a direct, validated decoder can promote a flag to verified."""
        low = str(label).lower().strip()
        if "->" in low:
            low = low.rsplit("->", 1)[1].strip()
        if low.startswith("chain["):
            return False  # intermediate chain stages are candidates
        if low.startswith("chain-best("):
            return "xor" not in low
        return low.split(" ", 1)[0] in {
            "base16", "base32", "base32hex", "base45", "base58", "base64",
            "base62", "base85", "ascii85", "hex", "url", "unicode",
            "html", "gzip", "zlib", "morse", "brainfuck", "ook",
            "malbolge", "bacon", "emoji", "jwt", "binary", "octal",
            "decimal", "quoted-printable", "a1z26", "nato", "tapcode",
            "custom-base",
        }

    for score, label, output in ranked:
        hits = _flag_hits(output)
        if hits:
            heuristic = "xor-crib crib-heuristic" in str(label)
            verified = not heuristic and deterministic_label(label)
            for value in hits:
                observed.add(value)
                ledger.add_flag(
                    value,
                    source=f"crypto:{label}",
                    verified=verified,
                    confidence=0.92 if verified else
                    (0.58 if heuristic else 0.68),
                    evidence=("flag-shaped plaintext", f"score={score:.2f}"),
                    trace=decode_trace(label),
                )
        elif str(label).startswith("xor-crib"):
            ledger.add(
                output,
                kind="candidate",
                source=f"crypto:{label}",
                confidence=0.58,
                evidence=("known-prefix crib", "raw plaintext preserved"),
                trace=decode_trace(label),
            )
    for value in legacy_flags:
        if value not in observed:
            ledger.add_flag(
                value,
                source="crypto:flag-detector",
                verified=False,
                confidence=0.62,
                evidence=("flag-shaped output from solver",),
            )
    return ranked, ledger.all()


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
        if any(flaglib.extract_flags(item[-1], include_candidates=False)[0]
               for item in out if len(item) >= 2):
            return out
    except Exception:
        pass
    try:
        for path, cur in encodings.chain_decode_best(text)[:40]:
            out.append((f"chain-best({path})", cur))
    except Exception:
        pass
    return out


def _preview_decode_value(value, limit=240):
    """Make an intermediate value safe and readable in CLI/UI explanations."""
    if isinstance(value, bytes):
        value = value.decode("latin-1", "replace")
    value = str(value if value is not None else "")
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    return value if len(value) <= limit else value[:limit] + f"… ({len(value)} chars)"


def _json_value_at_path(text, path):
    """Resolve the simple ``$.key[0].value`` paths emitted by nested decode."""
    if not text or not path or not path.startswith("$"):
        return None
    try:
        import json
        current = json.loads(text)
    except (TypeError, ValueError):
        return None
    for match in re.finditer(r"\.([^.\[]+)|\[(\d+)\]", path[1:]):
        key, index = match.groups()
        try:
            current = current[int(index)] if index is not None else current[key]
        except (KeyError, IndexError, TypeError, ValueError):
            return None
    return current if isinstance(current, (str, bytes)) else None


def _decoder_for_explanation(name):
    """Find a primitive decoder for replaying a displayed chain step."""
    normalized = str(name or "").strip().lower()
    aliases = {"base16": "hex", "gzip/zlib": "gzip", "zlib": "gzip"}
    normalized = aliases.get(normalized, normalized)
    if normalized == "gzip":
        return lambda value: encodings.dec_gzip(
            value.encode("latin-1") if isinstance(value, str) else value)
    for decoder_name, decoder in (encodings._ALL_LAYER_DECODERS +
                                  encodings._CHAIN_TRANSFORMS):
        if decoder_name.lower() == normalized:
            return decoder
    for decoder_name, decoder in encodings._LAYER_DECODERS:
        if decoder_name.lower() == normalized:
            return decoder
    return None


def _explanation_operations(label):
    """Extract a human-readable operation list from a solver label."""
    raw = str(label or "").strip()
    nested_path = None
    nested = re.match(r"^json\[(.*?)\]\s*->\s*(.*)$", raw)
    if nested:
        nested_path, raw = nested.groups()
        raw = raw.strip()

    stage = re.match(r"^chain\[(\d+)\]=(.+)$", raw)
    if stage:
        number, operation = stage.groups()
        return nested_path, [(f"chain stage {number}: {operation}", operation)]

    best = re.match(r"^chain-best\((.*)\)$", raw)
    if best:
        names = [part.strip() for part in best.group(1).split(">") if part.strip()]
        return nested_path, [(name, name) for name in names]

    names = [part.strip() for part in raw.split("->") if part.strip()]
    return nested_path, [(name, name) for name in (names or [raw])]


def explain_decode(label, output, source_text=None):
    """Return replayable, UI-friendly details for a ranked decode result.

    The solver result remains the exact decoded text.  This companion object
    only explains the path that produced it; if a primitive cannot be safely
    replayed, the final solver output is shown as the verified last step.
    """
    nested_path, operations = _explanation_operations(label)
    initial = source_text
    if nested_path:
        nested_value = _json_value_at_path(source_text, nested_path)
        if nested_value is not None:
            initial = nested_value
    if initial is None:
        initial = ""
    # ``chain[2]=rot13`` stores only the current stage in the legacy ranked
    # label. Rebuild the earlier greedy stages when they reproduce the same
    # solver output, so the explanation does not pretend stage two started
    # from the original ciphertext.
    if operations and operations[0][0].startswith("chain stage "):
        stage_match = re.match(r"chain stage (\d+): (.+)$", operations[0][0])
        if stage_match and isinstance(initial, str):
            stage_number = int(stage_match.group(1))
            try:
                stages = encodings.chain_decode(initial, max_depth=stage_number)
                if (len(stages) >= stage_number and
                        str(stages[stage_number - 1][1]) == str(output)):
                    operations = [
                        (f"chain stage {index}: {name}", name)
                        for index, (name, _value) in enumerate(
                            stages[:stage_number], 1)]
            except Exception:
                pass
    current = initial
    steps = []
    for index, (display_name, lookup_name) in enumerate(operations, 1):
        before = current
        decoder = _decoder_for_explanation(lookup_name)
        replayed = None
        if decoder is not None:
            try:
                replayed = decoder(current)
            except Exception:
                replayed = None
            if replayed == current:
                replayed = None
        # A solver-specific method (RSA/XOR/hash/etc.) cannot be replayed by
        # a text primitive. Its actual ranked output is still the authoritative
        # final value and is attached to the last displayed step.
        if replayed is None and index == len(operations):
            replayed = output
        if replayed is None:
            replayed = before
        steps.append({
            "index": index,
            "operation": display_name,
            "input": _preview_decode_value(before),
            "output": _preview_decode_value(replayed),
        })
        current = replayed

    if not steps:
        steps = [{"index": 1, "operation": str(label),
                  "input": _preview_decode_value(initial),
                  "output": _preview_decode_value(output)}]
    trace = [step["operation"] for step in steps]
    scope = f"JSON path {nested_path}" if nested_path else "input"
    return {
        "method": str(label),
        "scope": scope,
        "trace": trace,
        "summary": "decode with " + " -> ".join(trace),
        "steps": steps,
        "input": _preview_decode_value(initial),
        "output": _preview_decode_value(output),
    }


def explain_flag(flag, ranked, source_text=None):
    """Attach the best available decode explanation to a discovered flag."""
    for entry in ranked or []:
        if isinstance(entry, (tuple, list)) and len(entry) >= 3:
            output = entry[2]
            if flag and flag in str(output):
                return explain_decode(entry[1], output, source_text)
    return {
        "method": "flag detector",
        "scope": "scanner output",
        "trace": ["flag detector"],
        "summary": "flag-shaped value detected; no reversible decode trace available",
        "steps": [{"index": 1, "operation": "flag detector",
                    "input": "scanner output", "output": _preview_decode_value(flag)}],
        "input": "scanner output",
        "output": _preview_decode_value(flag),
    }


def _hash_crack(text):
    """Crack any hex hash found in the text. If the file carries a flag
    template like 'picoCTF{<password>}', substitute the cracked value."""
    from . import kdf
    words = _wordlist_candidates()
    for token in re.findall(r"(?:pbkdf2_sha256\$[^\s]+|pbkdf2-sha(?:256|512)\$[^\s]+)", text):
        cracked = kdf.crack_kdf(token, words)
        if cracked:
            return [(f"kdf({kdf.identify_kdf(token)})=cracked", cracked)]
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


def _binary_xor_analysis(data):
    """Simple single-byte XOR brute force on binary data — only returns hits
    when the result is >90% printable AND has decent English text score."""
    flags = []
    if len(data) < 16:
        return flags
    for k in range(256):
        xored = bytes(b ^ k for b in data)
        printable = sum(32 <= b < 127 for b in xored)
        if printable > len(data) * 0.9:
            text = xored.decode("latin-1", "replace")
            # Require some English quality (not just printable garbage)
            letters = sum(c.isalpha() for c in text)
            if letters < len(text) * 0.3:
                continue  # too few letters — likely garbage XOR
            for f in _flag_hits(text):
                if f not in flags:
                    flags.append(f)
    return flags


def _solve_klg3(data):
    """Solve KLG3 ledger format: position-bound SHA-256 proof + Base85 + XOR.
    Format: KLG3(4) + seed(18) + anchor(16) + n(2) + records...
    Each record: ln(2) + proof(12) + enc(ln) bytes.
    For each record, find original index (0..5) via SHA-256 proof,
    Base85-decode enc, XOR with SHA-256 stream to get plaintext,
    verify with anchor. Only the verified record is the real flag."""
    import base64, hashlib, struct
    flags = []
    try:
        b = data
        assert b[:4] == b"KLG3"
        seed = b[4:22]         # 18 bytes ("ledger-quorum-2026")
        anchor = b[22:38]      # 16 bytes (verification hash)
        n = struct.unpack(">H", b[38:40])[0]  # number of records
        p = 40
        candidates = []
        for _ in range(n):
            if p + 14 > len(b):
                break
            ln = struct.unpack(">H", b[p:p+2])[0]
            proof = b[p+2:p+14]   # 12 bytes
            enc = b[p+14:p+14+ln] # Base85-encoded encrypted data
            p += 14 + ln
            # Find original key index (0..5) by checking SHA-256 proof
            orig = None
            for i in range(6):
                h = hashlib.sha256(seed + enc + i.to_bytes(2, "big")).digest()
                if h[:12] == proof:
                    orig = i
                    break
            if orig is None:
                continue
            # Base85 decode
            raw = base64.b85decode(enc)
            # Derive XOR key from SHA-256
            key = hashlib.sha256(seed + bytes([orig]) + b"/quorum").digest()
            # Generate key stream
            ks = b""
            j = 0
            while len(ks) < len(raw):
                ks += hashlib.sha256(key + j.to_bytes(4, "big")).digest()
                j += 1
            # XOR to get plaintext
            plain = bytes(x ^ y for x, y in zip(raw, ks))
            # Verify with anchor
            if hashlib.sha256(seed + enc).digest()[:16] == anchor:
                candidates.append(plain)
        # Extract flags from verified records
        for plain in candidates:
            for f in _flag_hits(plain.decode("latin-1", "replace")):
                if f not in flags:
                    flags.append(f)
    except Exception:
        pass
    return flags


def analyze_file(path, as_binary=None):
    """Analyze a file: every independent pipeline section runs CONCURRENTLY
    (structured JSON, strings scan, text decoders, RSA params, embedded
    blobs, zip members) — wall time is the slowest section, not the sum."""
    from core.parallel import run_concurrent
    with open(path, "rb") as f:
        data = f.read()
    try:
        from .artifacts import extract as extract_artifacts
        nested_artifacts = extract_artifacts(data)
    except Exception:
        nested_artifacts = [("root", data)]
    results = []
    flags = []
    as_text = data.decode("utf-8", errors="ignore")
    printable_ratio = sum(1 for c in as_text if c.isprintable()) / max(len(as_text), 1)

    # ---- job definitions (pure functions over `data`) -------------------
    def job_structured():
        out = []
        try:
            sr = structured_mod.analyze(as_text)
            for entry in sr:
                for f in _flag_hits(entry[-1] if len(entry) >= 2 else entry):
                    out.append(("flag", None, f))
                out.append(("result", entry, None))
            return out
        except Exception:
            return []

    def job_strings():
        out = []
        try:
            strings_out = _extract_strings(data)
        except Exception:
            return out
        for s in strings_out:
            for f in _flag_hits(s):
                out.append(("flag", None, f))
        return out

    def job_magic():
        magic = encodings.sniff_bytes(data)
        if magic:
            return [("result", ("file-type", f"{path} -> {magic}"), None)]
        return []

    def job_encodings():
        if as_binary:
            return []
        out = []
        for label, dec in encodings.try_all_encodings(
                data.decode("latin-1")):
            out.append(("result", (label, dec), None))
        return out

    def job_classic():
        if as_binary:
            return []
        out = []
        for item in classic.try_all_classic(data.decode("latin-1")):
            out.append(("result", item, None))
        return out

    def job_xor():
        if as_binary:
            return []
        out = []
        for item in xor_mod.crack_xor(data.decode("latin-1")):
            out.append(("result", item, None))
        return out

    def job_analyze_text():
        if as_binary:
            return []
        out = []
        try:
            tr, tf = analyze_text(as_text)
            for r in tr:
                out.append(("result", r, None))
            for f in tf:
                out.append(("flag", None, f))
        except Exception:
            pass
        return out

    def job_rsa_params():
        out = []
        if printable_ratio <= 0.8:
            return out
        try:
            rsa_results = _try_rsa_params(as_text)
            for label, text_out in rsa_results:
                out.append(("result", (label, text_out), None))
                for f in _flag_hits(text_out):
                    out.append(("flag", None, f))
            m1 = re.search(r'c1_hex\s*=\s*([0-9a-fA-F]+)', as_text)
            m2 = re.search(r'c2_hex\s*=\s*([0-9a-fA-F]+)', as_text)
            if m1 and m2:
                c1 = bytes.fromhex(m1.group(1))
                c2 = bytes.fromhex(m2.group(1))
                for label, text_out in xor_mod.two_time_pad_crib_drag(c1, c2):
                    out.append(("result", (label, text_out), None))
                    for f in _flag_hits(text_out):
                        out.append(("flag", None, f))
        except Exception:
            pass
        return out

    def job_blobs():
        """Encoded blobs and recursively extracted container members."""
        out = []
        for member_label, member_data in nested_artifacts:
            member_text = member_data.decode("latin-1", "replace")
            for f in _flag_hits(member_text):
                out.append(("flag", None, f))
            for m in re.finditer(rb"[A-Za-z0-9+/=]{40,}", member_data):
                blob = m.group(0)
                try:
                    import base64
                    rawb = base64.b64decode(blob, validate=True)
                    if encodings.sniff_bytes(rawb) or b"flag" in rawb.lower() \
                            or b"ctf" in rawb.lower():
                        for f in _flag_hits(rawb.decode("latin-1", "replace")):
                            out.append(("flag", None, f))
                except Exception:
                    pass
        for m in re.finditer(rb"[A-Za-z0-9+/=]{40,}", data):
            blob = m.group(0)
            try:
                import base64
                rawb = base64.b64decode(blob, validate=True)
                if encodings.sniff_bytes(rawb) or b"flag" in rawb.lower() \
                        or b"ctf" in rawb.lower():
                    for f in _flag_hits(rawb.decode("latin-1", "replace")):
                        out.append(("flag", None, f))
            except Exception:
                pass
        return out

    def job_binary_extras():
        out = []
        if data[:4] == b"KLG3":
            for f in _solve_klg3(data):
                out.append(("flag", None, f))
        for f in _binary_xor_analysis(data):
            out.append(("flag", None, f))
        for f, r in _companion_lcg(path, data, results_ref=None):
            out.append(("result", (f, r), None))
            for fl in _flag_hits(r):
                out.append(("flag", None, fl))
        return out

    jobs = [job_structured, job_strings, job_magic, job_encodings,
            job_classic, job_xor, job_analyze_text, job_rsa_params,
            job_blobs, job_binary_extras]
    sections = run_concurrent(jobs, workers=len(jobs),
                              desc="file analysis")
    for res in sections:
        if isinstance(res, Exception):
            continue
        for kind, payload, flag in res or []:
            if kind == "flag" and flag and flag not in flags:
                flags.append(flag)
            elif kind == "result" and payload not in results:
                results.append(payload)

    ranked = _rank(results)
    return ranked, _filter_flag_families(flags)


def _companion_lcg(path, data, results_ref=None):
    """Custom cipher: detect LCG/PRNG keystream in companion .py files.
    Returns [(label, plaintext)] candidates."""
    parent = os.path.dirname(path)
    basename = os.path.basename(path)
    out = []
    if not (basename.endswith((".enc", ".bin")) or "cipher" in basename.lower()):
        return out
    for py in os.listdir(parent):
        if not py.endswith(".py") or py == basename:
            continue
        py_path = os.path.join(parent, py)
        try:
            py_text = open(py_path).read()
            lcg_m = re.search(
                r'(?i)seed\s*=\s*(?:0x([0-9a-fA-F]+)|(\d+))', py_text)
            mult_m = re.search(
                r's\s*\*\s*(?:0x([0-9a-fA-F]+)|(\d+))', py_text)
            inc_m = re.search(
                r'\+\s*(?:0x([0-9a-fA-F]+)|(\d+))', py_text)
            mask_m = re.search(
                r'&\s*(?:0x([0-9a-fA-F]+)|(\d+))', py_text)
            byte_m = re.search(r's\s*&\s*(?:0x([0-9a-fA-F]+)|(\d+))',
                               py_text)
            if not (lcg_m and mult_m):
                continue

            def _parse_int(mm, default):
                if mm is None:
                    return int(default, 0)
                hex_part, dec_part = mm.group(1), mm.group(2)
                return int('0x' + hex_part, 16) if hex_part else int(dec_part)

            seed = _parse_int(lcg_m, '0')
            mult = _parse_int(mult_m, '0')
            inc = _parse_int(inc_m, '0x12345')
            mask = _parse_int(mask_m, '0x7FFFFFFF')
            byte_mask = _parse_int(byte_m, '0xFF')
            with open(path, 'rb') as ef:
                raw = ef.read()
            enc_text = raw.decode('ascii', errors='ignore').strip()
            if re.fullmatch(r'[0-9a-fA-F]+', enc_text) and len(enc_text) >= 8:
                enc_bytes = bytes.fromhex(enc_text)
            else:
                enc_bytes = raw.rstrip(b'\n\r')
            s = seed
            ks = bytearray()
            for _ in range(len(enc_bytes)):
                s = (s * mult + inc) & mask
                ks.append(s & byte_mask)
            plain = bytes(a ^ b for a, b in zip(enc_bytes, ks))
            pt = plain.decode('utf-8', errors='ignore')
            out.append((f"custom-lcg({py})", pt.strip()[:200]))
        except Exception:
            continue
    return out


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


def run_crypto(target, interactive=False, prefix_hint=None, context_text=None):
    """Public entry for the crypto category.

    ``prefix_hint`` is optional challenge metadata such as ``picoCTF{...}``.
    """
    section("🔐 CRYPTO AUTO-DETECT")
    info_line(f"target: {target}")

    source_text = None
    if os.path.isfile(target):
        with open(target, "rb") as f:
            data = f.read()
        # try text decoders if the file looks textual, else binary analysis
        try:
            as_text = data.decode("utf-8")
            if sum(1 for c in as_text if c.isprintable()) / max(len(as_text), 1) > 0.8:
                source_text = as_text
                ranked, flags = analyze_text(as_text,
                                             prefix_hint=prefix_hint)
                if context_text:
                    contextual = _hinted_classic_results(
                        str(context_text) + "\n\n" + as_text)
                    ranked.extend(_rank(contextual))
                    for entry in contextual:
                        if isinstance(entry, (tuple, list)) and len(entry) >= 2:
                            for item in _flag_hits(entry[-1]):
                                if item not in flags:
                                    flags.append(item)
                # A verified textual solve is complete; the second generic
                # file pass only adds noise and can re-enter expensive
                # factoring/classic jobs. Keep the deep pass for misses.
                # Generic brace-shaped candidates are not enough to skip the
                # binary/deep pass.  For example a hex ciphertext often
                # yields a coincidental ``CJ{...}`` under ROT47 before a
                # companion LCG solver reveals the real plaintext.
                if _verified_fast_hits(ranked, prefix_hint):
                    ranked2, flags2 = [], []
                else:
                    ranked2, flags2 = analyze_file(target, as_binary=True)
                ranked = ranked + [r for r in ranked2 if r not in ranked]
                flags = list(dict.fromkeys(flags + flags2))
            else:
                ranked, flags = analyze_file(target, as_binary=True)
        except Exception:
            ranked, flags = analyze_file(target, as_binary=True)
    else:
        source_text = target
        ranked, flags = analyze_text(str(target), prefix_hint=prefix_hint)
        if context_text:
            contextual = _hinted_classic_results(
                str(context_text) + "\n\n" + str(target))
            ranked.extend(_rank(contextual))
            for entry in contextual:
                if isinstance(entry, (tuple, list)) and len(entry) >= 2:
                    for item in _flag_hits(entry[-1]):
                        if item not in flags:
                            flags.append(item)

    # The legacy API also returns generic brace-shaped candidates.  Keep
    # those visible in the decode ranking, but reserve the prominent FLAG
    # section for a known/explicit flag prefix so heuristic ROT13/XOR ghosts
    # cannot be mistaken for accepted answers.
    display_flags = []
    explicit_prefixes = [p[:-1].lower() for p in
                         flaglib.infer_prefixes(prefix_hint or "")
                         if p.endswith("{")]
    for value in flags:
        known, _ = flaglib.extract_flags(value, include_candidates=False)
        if explicit_prefixes and not any(
                str(value).lower().startswith(prefix + "{")
                for prefix in explicit_prefixes):
            continue
        if known and value not in display_flags:
            display_flags.append(value)

    print()
    if display_flags:
        print()
        for f in display_flags:
            flag_line(f"FLAG: {f}")
            explanation = explain_flag(f, ranked, source_text)
            ok_line(f"วิธีแกะ: {explanation['summary']}")
            info_line(f"ขอบเขต: {explanation['scope']}")
            for step in explanation["steps"]:
                print(f"      {step['index']}. {step['operation']}: "
                      f"{step['input']} -> {step['output']}")
    else:
        warn_line("ยังไม่เจอ flag โดยตรง — ดูผล decode ข้างล่าง")

    if ranked:
        print()
        ok_line(f"ผล decode ที่น่าสนใจ ({len(ranked)} อันดับแรก):")
        for shown_count, (score, label, text) in enumerate(ranked[:12], 1):
            shown = text.strip().replace("\n", " ")[:120]
            trace = " -> ".join(decode_trace(label))
            trace_suffix = f" [trace: {trace}]" if trace else ""
            print(f"  {shown_count:2}. [{score:8.1f}] {label}{trace_suffix}: {shown}")
            explanation = explain_decode(label, text, source_text)
            print(f"      HOW: {explanation['summary']} ({explanation['scope']})")
            if len(text) > 120:
                print(f"      ... (total {len(text)} chars)")
    else:
        warn_line("ไม่พบผล decode ที่เป็นไปได้ — ลองป้อนรูปแบบอื่น หรือใช้โหมดเฉพาะ")
    return flags
