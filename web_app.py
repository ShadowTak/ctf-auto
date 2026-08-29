#!/usr/bin/env python3
"""CTF Auto Recon — Web UI.

    python3 web_app.py                # start on http://localhost:8088
    python3 web_app.py --port 9000    # custom port
"""
import os
import sys
import json
import time
import tempfile
import threading
import argparse
import traceback
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 128 * 1024 * 1024

# ── in-memory job store ───────────────────────────────────────────────────────
_jobs = {}   # job_id → {status, results, started, finished, error, cancel}
_lock = threading.Lock()
_web_scan_lock = threading.Lock()


def _detect_uploaded_kind(path, original=""):
    """Classify an upload by magic bytes first, extension second.

    CTF artifacts are frequently misnamed (``flag.jpg`` containing a ZIP or
    a text dump with no extension), so this is deliberately not MIME-only.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(64)
            sample = head + handle.read(64 * 1024)
    except OSError:
        return "binary"
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                    b"\x0a\x0d\x0d\x0a"):
        return "pcap"
    image_signatures = (
        b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a",
        b"BM", b"RIFF",
    )
    if any(head.startswith(signature) for signature in image_signatures):
        return "image"
    try:
        text = sample.decode("utf-8")
        printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
        if text and printable / len(text) >= 0.82:
            return "text"
    except UnicodeDecodeError:
        pass
    extension = os.path.splitext(original or path)[1].lower()
    if extension in {".pcap", ".pcapng", ".cap"}:
        return "pcap"
    if extension in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
                     ".tif", ".tiff", ".ico", ".pnm"}:
        return "image"
    return "binary"

# ── helpers ───────────────────────────────────────────────────────────────────

def _is_clean_flag(f):
    """Check if a flag string looks like a real CTF flag (not garbage)."""
    if not f or len(f) < 6 or len(f) > 80:
        return False
    if '{' not in f or '}' not in f:
        return False
    body = f.split('{', 1)[1].rstrip('}')
    if not body:
        return False
    # Strict whitelist: only letters, digits, underscores, hyphens, spaces
    # Reject anything with =, ], [, $, ~, @, |, ), (, ^, &, comma, backslash, etc.
    allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ -')
    for c in body:
        if c not in allowed:
            return False
    # No control chars or high-bit chars
    if any(ord(c) < 32 or ord(c) > 126 for c in body):
        return False
    return True


def _new_job():
    import uuid
    jid = uuid.uuid4().hex[:12]
    with _lock:
        _jobs[jid] = {"status": "running", "results": [], "started": time.time(),
                       "finished": None, "error": None,
                       "cancel": threading.Event(), "stop_requested": False}
    return jid


def _job_cancelled(jid):
    with _lock:
        job = _jobs.get(jid)
        return bool(job and job["cancel"].is_set())


def _finish_job(jid, results, error=None, cancelled=False):
    cleanup = []
    with _lock:
        if jid in _jobs:
            stopped = cancelled or _jobs[jid]["cancel"].is_set()
            _jobs[jid]["status"] = "cancelled" if stopped else ("error" if error else "done")
            _jobs[jid]["results"] = results
            _jobs[jid]["finished"] = time.time()
            _jobs[jid]["error"] = error
            cleanup = list(_jobs[jid].get("cleanup_paths", ()))
    for path in cleanup:
        try:
            if path and os.path.isfile(path):
                os.unlink(path)
        except OSError:
            pass


# ── Crypto ───────────────────────────────────────────────────────────────────

def _run_crypto(jid, text=None, filepath=None, prefix_hint=None):
    try:
        from modules.crypto.autodetect import (
            analyze_file, analyze_text, analyze_text_evidence,
            explain_decode, explain_flag)
        results = []
        if text:
            text_ranked, findings = analyze_text_evidence(text, prefix_hint=prefix_hint)
            results.append({"type": "text-input", "input": text[:200]})
            for r in (text_ranked or []):
                if isinstance(r, (list, tuple)):
                    score = r[0] if len(r) > 0 else 0
                    label = r[1] if len(r) > 1 else ""
                    out = r[2] if len(r) > 2 else ""
                    explanation = explain_decode(label, out, text)
                    results.append({"type": "decode", "method": str(label),
                                    "score": round(float(score), 2),
                                    "output": str(out)[:5000],
                                    "explanation": explanation})
            for finding in (findings or []):
                value = finding.value
                solution = explain_flag(value, text_ranked, text)
                if finding.kind == "verified":
                    # Keep the old shape for consumers while exposing the
                    # richer status/evidence fields to the UI.
                    if _is_clean_flag(value):
                        results.append({"type": "flag", "flag": value,
                                        "status": "verified",
                                        "confidence": finding.confidence,
                                        "source": finding.source,
                                        "evidence": list(finding.evidence),
                                        "solution": solution})
                elif finding.kind == "candidate":
                    results.append({"type": "candidate", "value": value,
                                    "confidence": finding.confidence,
                                    "source": finding.source,
                                    "evidence": list(finding.evidence),
                                    "solution": solution})
        if filepath:
            file_source_text = None
            with open(filepath, "rb") as handle:
                file_data = handle.read()
            try:
                file_source_text = file_data.decode("utf-8")
            except UnicodeDecodeError:
                file_source_text = None
            is_text = bool(file_source_text) and (
                sum(1 for char in file_source_text if char.isprintable()) /
                max(len(file_source_text), 1) > 0.8)
            if is_text:
                file_ranked, flags = analyze_text(file_source_text, prefix_hint=prefix_hint)
                # analyze_text already runs the verified structured/RSA fast
                # path. Avoid re-entering generic factorers when it solved the
                # file; this keeps the UI responsive on hard RSA artifacts.
                if flags:
                    file_ranked2, flags2 = [], []
                else:
                    file_ranked2, flags2 = analyze_file(filepath, as_binary=True)
                file_ranked += [item for item in file_ranked2 if item not in file_ranked]
                flags = list(dict.fromkeys(flags + flags2))
            else:
                file_ranked, flags = analyze_file(filepath, as_binary=True)
            for r in (file_ranked or []):
                if isinstance(r, (list, tuple)) and len(r) >= 3:
                    score, label, out = r[0], r[1], r[2]
                    results.append({"type": "decode", "method": str(label),
                                    "score": round(float(score), 2),
                                    "output": str(out)[:5000],
                                    "explanation": explain_decode(label, out,
                                                                    file_source_text)})
            for f in (flags or []):
                results.append({"type": "flag", "flag": f,
                                "status": "candidate",
                                "source": "crypto:file scanner",
                                "solution": explain_flag(f, file_ranked,
                                                           file_source_text)})
            results.append({"type": "file", "path": os.path.basename(filepath)})
        _finish_job(jid, results)
    except Exception as e:
        _finish_job(jid, [], error=None if _job_cancelled(jid) else f"{e}\n{traceback.format_exc()}")


def _run_image(jid, filepath):
    try:
        from modules.image.forensics import analyze_image
        report = analyze_image(filepath)
        results = [{"type": "file", "path": report["file"]["name"]},
                   {"type": "image", "section": "format", "data": json.dumps(
                       {"format": report["format"], "summary": report["summary"],
                        "file": report["file"]}, ensure_ascii=False)}]
        for section_name in ("metadata", "chunks", "embedded", "anomalies", "text", "strings",
                             "stego", "signatures", "decodes", "tools"):
            values = report.get(section_name)
            if values:
                results.append({"type": "image", "section": section_name,
                                "data": json.dumps(values, ensure_ascii=False,
                                                     default=str)})
        for finding in report.get("findings", []):
            solution = next((item.get("explanation") for item in report.get("decodes", [])
                             if item.get("output") and
                             finding.get("value", "") in item.get("output", "")), None)
            if solution is None:
                solution = {"method": "image forensics",
                            "scope": finding.get("source", "image evidence"),
                            "summary": "value extracted directly from image evidence",
                            "steps": [{"index": 1, "operation": finding.get("source", "image evidence"),
                                       "input": "image bytes", "output": finding.get("value", "")}]}
            if finding.get("kind") == "verified":
                results.append({"type": "flag", "flag": finding["value"],
                                "status": "verified", "confidence": finding.get("confidence"),
                                "source": finding.get("source"),
                                "evidence": finding.get("evidence", []),
                                "solution": solution})
            elif finding.get("kind") == "candidate":
                results.append({"type": "candidate", "value": finding["value"],
                                "confidence": finding.get("confidence"),
                                "source": finding.get("source"),
                                "evidence": finding.get("evidence", []),
                                "solution": solution})
        _finish_job(jid, results)
    except Exception as e:
        _finish_job(jid, [], error=None if _job_cancelled(jid) else f"{e}\n{traceback.format_exc()}")


# ── Web ───────────────────────────────────────────────────────────────────────

def _run_web_once(jid, url, use_browser=False, prefix_hint=None):
    try:
        from core.evidence import findings_from_flags
        from modules.web.scanner import run_web
        results = []
        results.append({"type": "target", "url": url})
        output = run_web(url, interactive=False, use_browser=use_browser)
        if isinstance(output, dict):
            for k, v in output.items():
                results.append({"type": "scan", "section": k,
                                "data": str(v)[:1000] if not isinstance(v, list) else
                                json.dumps(v[:50])[:1000]})
        elif isinstance(output, list):
            from core.flag import normalize_prefix
            normalized = normalize_prefix(prefix_hint)
            evidence = ("flag-shaped value returned by scanner",)
            if normalized:
                evidence += (f"operator prefix hint: {normalized}",)
            for finding in findings_from_flags(
                output, source="web:scanner", verified=False,
                confidence=0.78,
                evidence=evidence):

                results.append({"type": "candidate",
                                "value": finding.value,
                                "confidence": finding.confidence,
                                "source": finding.source,
                                "evidence": list(finding.evidence)})
        else:
            results.append({"type": "scan", "data": str(output)[:2000]})
        _finish_job(jid, results)
    except Exception as e:
        _finish_job(jid, [], error=None if _job_cancelled(jid) else f"{e}\n{traceback.format_exc()}")


def _run_web(jid, url, use_browser=False, deep=True,
             max_seconds=0, max_requests=0, prefix_hint=None):
    """Run one web job with an isolated process-local HTTP session.

    The solver modules intentionally share cookies and learned auth headers
    across their concurrent phases. The lock prevents two UI jobs from
    leaking those credentials into each other while preserving that behavior
    within one scan.
    """
    from core import httpx
    from core import budget
    from core.cancel import clear_event, set_event
    with _web_scan_lock:
        httpx.reset_session()
        budget.configure(requests=max_requests, seconds=max_seconds)
        set_event(_jobs[jid]["cancel"])
        try:
            _run_web_once(jid, url, use_browser=use_browser,
                          prefix_hint=prefix_hint)
        finally:
            clear_event()
            budget.clear()
            httpx.reset_session()
            httpx.close_pool()


# ── Network ───────────────────────────────────────────────────────────────────

def _run_network(jid, filepath):
    try:
        # The project exposes the pure-Python parser as modules.network.pcap;
        # keep the UI path on that same implementation so uploaded pcaps do
        # not fail with a stale import name.
        from modules.network import pcap as pcap_analyzer
        results = []
        results.append({"type": "file", "path": os.path.basename(filepath)})
        parsed = pcap_analyzer.analyze(filepath)
        if isinstance(parsed, dict):
            for k, v in parsed.items():
                results.append({"type": "network", "section": k,
                                "data": str(v)[:1000] if not isinstance(v, list) else
                                json.dumps(v[:50])[:1000]})
        elif isinstance(parsed, list):
            for item in parsed:
                results.append({"type": "network", "data": str(item)[:500]})
        else:
            results.append({"type": "network", "data": str(parsed)[:2000]})
        _finish_job(jid, results)
    except Exception as e:
        _finish_job(jid, [], error=None if _job_cancelled(jid) else f"{e}\n{traceback.format_exc()}")


def _run_child_for_auto(parent_jid, fn, args=(), kwargs=None):
    """Run an existing category runner and return its result list.

    Category runners already contain their own error handling and evidence
    formatting.  A short-lived child job lets the upload orchestrator reuse
    them concurrently without duplicating that logic or allowing one runner
    to overwrite the parent job's state.
    """
    child = _new_job()
    with _lock:
        parent = _jobs.get(parent_jid)
        if parent and child in _jobs:
            _jobs[child]["cancel"] = parent["cancel"]
    try:
        fn(child, *args, **(kwargs or {}))
        with _lock:
            item = _jobs.get(child, {})
            return list(item.get("results", ())), item.get("error")
    finally:
        with _lock:
            _jobs.pop(child, None)


def _publish_job_results(jid, results):
    """Publish bounded partial evidence without marking the job complete."""
    with _lock:
        job = _jobs.get(jid)
        if job and job["status"] == "running":
            job["results"] = list(results)


def _fast_upload_crypto(filepath):
    """Cheap first pass for upload UX; the full solver follows in parallel.

    It intentionally limits itself to direct strings, structured artifacts,
    RSA parameter parsing and one-pass encodings.  Expensive classic/XOR/
    annealing work stays in the background runner, so a dropped file produces
    visible evidence quickly without sacrificing final coverage.
    """
    from core.flag import extract_flags
    from modules.crypto import encodings, structured
    from modules.crypto.autodetect import _try_rsa_params

    try:
        with open(filepath, "rb") as handle:
            data = handle.read(8 * 1024 * 1024)
    except OSError:
        return []
    text = data.decode("utf-8", errors="ignore")
    results = [{"type": "file", "path": os.path.basename(filepath)}]
    if text:
        for flag in extract_flags(text)[0]:
            results.append({"type": "flag", "flag": flag,
                            "status": "verified", "source": "upload:direct"})
        fast_entries = []
        try:
            fast_entries.extend(structured.analyze(text))
        except Exception:
            pass
        try:
            fast_entries.extend(_try_rsa_params(text))
        except Exception:
            pass
        # ``try_all_encodings`` also launches the deep chain beam-search.  A
        # dropped-file fast pass must not wait on that 12-second guard; the
        # full child runner below still performs it after this evidence is
        # published.
        direct_decoders = (
            ("base64", encodings.dec_base64),
            ("base32", encodings.dec_base32),
            ("base16", encodings.dec_base16),
            ("hex", encodings.dec_hex),
            ("base85", encodings.dec_base85),
            ("ascii85", encodings.dec_ascii85),
            ("url", encodings.dec_url),
            ("rot13", encodings.dec_rot13),
            ("rot47", encodings.dec_rot47),
            ("binary", encodings.dec_binary),
            ("morse", encodings.dec_morse),
            ("quoted-printable", encodings.dec_quoted_printable),
        )
        def decode_one(item):
            label, decoder = item
            try:
                value = decoder(text)
                return (label, value) if value and value != text else None
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            for entry in pool.map(decode_one, direct_decoders):
                if entry:
                    fast_entries.append(entry)
        for entry in fast_entries:
            if not isinstance(entry, (tuple, list)) or len(entry) < 2:
                continue
            label, output = str(entry[0]), entry[-1]
            for flag in extract_flags(str(output))[0]:
                results.append({"type": "flag", "flag": flag,
                                "status": "candidate", "source": "upload:fast:" + label})
            results.append({"type": "decode", "method": label,
                            "score": 0, "output": str(output)[:5000]})
    else:
        # Binary first pass: magic/embedded flag extraction is cheap and keeps
        # image/pcap uploads responsive while the deep runners continue.
        for flag in extract_flags(data.decode("latin-1", "replace"))[0]:
            results.append({"type": "flag", "flag": flag,
                            "status": "candidate", "source": "upload:binary-strings"})
    return results


def _run_auto_file(jid, filepath, original=""):
    """Upload pipeline: classify once, then run all relevant solvers in parallel."""
    try:
        kind = _detect_uploaded_kind(filepath, original)
        results = _fast_upload_crypto(filepath)
        results.insert(0, {"type": "auto", "kind": kind,
                            "path": os.path.basename(filepath),
                            "pipelines": ["crypto"] + ([kind] if kind in ("image", "pcap") else [])})
        _publish_job_results(jid, results)
        runners = [(_run_crypto, (), {"filepath": filepath})]
        if kind == "image":
            # Image forensics already feeds extracted text through the crypto
            # chain; running both catches polyglot/embedded binary payloads.
            runners.append((_run_image, (filepath,), {}))
        elif kind == "pcap":
            # Network extraction and raw crypto/blob analysis are independent.
            runners.append((_run_network, (filepath,), {}))

        errors = []
        with ThreadPoolExecutor(max_workers=len(runners)) as pool:
            futures = [pool.submit(_run_child_for_auto, jid, fn, args, kwargs)
                       for fn, args, kwargs in runners]
            for future in futures:
                child_results, child_error = future.result()
                results.extend(child_results)
                if child_error:
                    errors.append(child_error)
        _finish_job(jid, results, error="\n".join(errors) if errors else None)
    except Exception as e:
        _finish_job(jid, [], error=None if _job_cancelled(jid) else f"{e}\n{traceback.format_exc()}")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json or {}
    category = data.get("category", "")
    jid = _new_job()

    if category == "crypto":
        text = data.get("text", "").strip()
        prefix_hint = data.get("prefix", "").strip()
        if prefix_hint:
            from core.flag import normalize_prefix
            prefix_hint = normalize_prefix(prefix_hint)
            if not prefix_hint:
                _finish_job(jid, [], error="Prefix must look like ctf, ctf{, or ctf{...}")
                return jsonify({"job_id": jid})
        filepath = None
        # If a file was uploaded previously, it's in /tmp
        file_path = data.get("file_path")
        if file_path and os.path.exists(file_path):
            filepath = file_path
        if not text and not filepath:
            _finish_job(jid, [], error="No text or file provided")
            return jsonify({"job_id": jid})
        t = threading.Thread(target=_run_crypto, args=(jid,), kwargs={"text": text or None, "filepath": filepath, "prefix_hint": prefix_hint or None}, daemon=True)
        t.start()

    elif category == "web":
        url = data.get("url", "").strip()
        prefix_hint = data.get("prefix", "").strip()
        if prefix_hint:
            from core.flag import normalize_prefix
            prefix_hint = normalize_prefix(prefix_hint)
            if not prefix_hint:
                _finish_job(jid, [], error="Prefix must look like ctf, ctf{, or ctf{...}")
                return jsonify({"job_id": jid})
        if not url:
            _finish_job(jid, [], error="No URL provided")
            return jsonify({"job_id": jid})
        if not url.startswith("http"):
            url = "https://" + url
        try:
            max_seconds = max(0, int(data.get("max_seconds", 0) or 0))
            max_requests = max(0, int(data.get("max_requests", 0) or 0))
        except (TypeError, ValueError):
            max_seconds, max_requests = 0, 0
        t = threading.Thread(target=_run_web, args=(jid, url),
                             kwargs={"use_browser": bool(data.get("browser")),
                                     "deep": bool(data.get("deep", True)),
                                     "max_seconds": max_seconds,
                                     "max_requests": max_requests,
                                     "prefix_hint": prefix_hint or None}, daemon=True)
        t.start()

    elif category == "network":
        file_path = data.get("file_path")
        if not file_path or not os.path.exists(file_path):
            _finish_job(jid, [], error="No file uploaded")
            return jsonify({"job_id": jid})
        t = threading.Thread(target=_run_network, args=(jid, file_path), daemon=True)
        t.start()

    elif category in ("image", "picture", "pic"):
        file_path = data.get("file_path")
        if not file_path or not os.path.isfile(file_path):
            _finish_job(jid, [], error="No image uploaded")
            return jsonify({"job_id": jid})
        t = threading.Thread(target=_run_image, args=(jid, file_path), daemon=True)
        t.start()

    else:
        _finish_job(jid, [], error=f"Unknown category: {category}")
        return jsonify({"job_id": jid})

    return jsonify({"job_id": jid})


@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    original = os.path.basename(f.filename or "upload.bin")
    suffix = os.path.splitext(original)[1][:16]
    fd, tmp = tempfile.mkstemp(prefix="ctfweb_", suffix=suffix)
    os.close(fd)
    f.save(tmp)
    payload = {"file_path": tmp, "filename": original,
               "kind": _detect_uploaded_kind(tmp, original)}
    # Upload-first is the fast path in the UI: start the complete relevant
    # pipeline immediately, while still allowing API callers to opt out with
    # ?auto=0 and submit /api/scan themselves.
    auto = request.args.get("auto", "1").lower() not in {"0", "false", "no"}
    if auto:
        jid = _new_job()
        with _lock:
            _jobs[jid]["cleanup_paths"] = [tmp]
        threading.Thread(target=_run_auto_file, args=(jid, tmp, original),
                         daemon=True).start()
        payload["job_id"] = jid
        payload["auto"] = True
    else:
        payload["auto"] = False
    return jsonify(payload)


@app.route("/api/status/<jid>")
def api_status(jid):
    with _lock:
        job = _jobs.get(jid)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    elapsed = (job["finished"] or time.time()) - job["started"]
    return jsonify({
        "status": job["status"],
        "results": job["results"],
        "error": job["error"],
        "elapsed": round(elapsed, 1),
        "stop_requested": job["stop_requested"],
    })


@app.route("/api/stop/<jid>", methods=["POST"])
def api_stop(jid):
    """Request cooperative cancellation for a running scan."""
    from core.cancel import stop_event
    with _lock:
        job = _jobs.get(jid)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        if job["status"] in ("done", "error", "cancelled"):
            return jsonify({"status": job["status"], "accepted": False})
        job["stop_requested"] = True
        job["status"] = "stopping"
        stop_event(job["cancel"])
        return jsonify({"status": "stopping", "accepted": True})


# ── Lattice / ECDSA Solver API ──────────────────────────────────────────────

@app.route("/api/solver/lattice", methods=["POST"])
def api_solver_lattice():
    """Run lattice-based crypto solvers (Coppersmith, HNP, Boneh-Durfee)."""
    data = request.json or {}
    jid = _new_job()

    def _run_lattice(jid):
        try:
            from modules.crypto.lattice import (
                boneh_durfee, coppersmith_small_roots, hnp_solve,
                available_backends)
            results = [{"type": "backends", "data": available_backends()}]

            # RSA small d (Boneh-Durfee)
            n = data.get("n")
            e = data.get("e")
            if n and e:
                result = boneh_durfee(int(n), int(e))
                if result:
                    d, p, q = result
                    from modules.crypto.common import long_to_bytes, strip_zeros
                    c = data.get("c")
                    if c:
                        pt = strip_zeros(long_to_bytes(pow(int(c), d, int(n))))
                        results.append({"type": "flag", "flag": pt.decode("latin-1", "replace"),
                                        "status": "verified", "method": "boneh-durfee",
                                        "source": "lattice:solver"})
                    results.append({"type": "result", "method": "boneh-durfee",
                                    "data": {"d": str(d), "p": str(p), "q": str(q)}})

            # HNP for partial nonce
            remainders = data.get("remainders", [])
            moduli = data.get("moduli", [])
            bound = data.get("bound", 2)
            if remainders and moduli:
                candidates = hnp_solve(moduli, remainders, bound)
                results.append({"type": "result", "method": "hnp",
                                "data": {"candidates": [str(c) for c in candidates[:5]]}})

            _finish_job(jid, results)
        except Exception as e:
            _finish_job(jid, [], error=f"{e}\n{traceback.format_exc()}")

    t = threading.Thread(target=_run_lattice, args=(jid,), daemon=True)
    t.start()
    return jsonify({"job_id": jid})


@app.route("/api/solver/ecdsa", methods=["POST"])
def api_solver_ecdsa():
    """Analyze ECDSA signatures: nonce reuse, partial nonce, malleability."""
    data = request.json or {}
    jid = _new_job()

    def _run_ecdsa(jid):
        try:
            from modules.crypto.ecdsa_solver import (
                detect_nonce_reuse, malleable_variants,
                extract_signatures_from_text, CURVES)
            from core.flag import extract_flags
            results = []

            # Parse signatures from text input
            text = data.get("text", "")
            sigs = extract_signatures_from_text(text)
            if sigs:
                results.append({"type": "signatures-found", "count": len(sigs)})

                # Detect nonce reuse
                sig_dicts = [{"r": s["r"], "s": s["s"],
                              "z": data.get("z", 0)} for s in sigs]
                reuse = detect_nonce_reuse(sig_dicts)
                for r in reuse:
                    results.append({"type": "flag",
                                    "flag": f"private_key={hex(r['private_key'])}",
                                    "status": "verified",
                                    "method": "ecdsa-nonce-reuse",
                                    "source": "ecdsa:solver"})

                # Check malleability
                for s in sigs:
                    variants = malleable_variants(s["r"], s["s"])
                    if variants:
                        results.append({"type": "result",
                                        "method": "malleability",
                                        "data": {"original": {"r": s["r"], "s": s["s"]},
                                                   "variants": [{"r": v["r"], "s": v["s"]}
                                                                for v in variants[:3]]}})

            # Check for flags in input
            known, candidates = extract_flags(text)
            for flag in known:
                results.append({"type": "flag", "flag": flag,
                                "status": "verified", "source": "ecdsa:direct"})

            _finish_job(jid, results)
        except Exception as e:
            _finish_job(jid, [], error=f"{e}\n{traceback.format_exc()}")

    t = threading.Thread(target=_run_ecdsa, args=(jid,), daemon=True)
    t.start()
    return jsonify({"job_id": jid})


# ── Authenticated Workflow API ───────────────────────────────────────────────

@app.route("/api/workflow/record", methods=["POST"])
def api_workflow_record():
    """Record a browser-based login flow."""
    data = request.json or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not url.startswith("http"):
        url = "https://" + url

    jid = _new_job()

    def _run_record(jid):
        try:
            from modules.web.workflow import record_login_flow
            result = record_login_flow(
                url,
                username=data.get("username"),
                password=data.get("password"),
                login_path=data.get("login_path"),
                timeout=data.get("timeout", 20),
            )
            if result is None:
                _finish_job(jid, [{"type": "error",
                                  "data": "Playwright not available. Install: pip install playwright && playwright install chromium"}])
            else:
                results = [{"type": "auth-state", "data": result}]
                # Check for flags in captured data
                from core.flag import extract_flags
                for token in result.get("tokens", []):
                    known, _ = extract_flags(token)
                    for flag in known:
                        results.append({"type": "flag", "flag": flag,
                                        "status": "verified", "source": "workflow:token"})
                _finish_job(jid, results)
        except Exception as e:
            _finish_job(jid, [], error=f"{e}\n{traceback.format_exc()}")

    t = threading.Thread(target=_run_record, args=(jid,), daemon=True)
    t.start()
    return jsonify({"job_id": jid})


@app.route("/api/workflow/replay", methods=["POST"])
def api_workflow_replay():
    """Replay captured auth state against target endpoints."""
    data = request.json or {}
    url = data.get("url", "")
    auth_state = data.get("auth_state", {})
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    jid = _new_job()

    def _run_replay(jid):
        try:
            from modules.web.workflow import replay_workflow
            findings = replay_workflow(url, auth_state)
            results = []
            for finding in findings:
                if finding.get("type") == "flag":
                    results.append({"type": "flag", "flag": finding["flag"],
                                    "status": "verified", "source": "workflow:replay"})
                else:
                    results.append({"type": "scan", "section": finding.get("type"),
                                    "data": json.dumps(finding, default=str)[:1000]})
            _finish_job(jid, results)
        except Exception as e:
            _finish_job(jid, [], error=f"{e}\n{traceback.format_exc()}")

    t = threading.Thread(target=_run_replay, args=(jid,), daemon=True)
    t.start()
    return jsonify({"job_id": jid})


# ── Benchmark API ────────────────────────────────────────────────────────────

@app.route("/api/benchmark", methods=["GET"])
def api_benchmark():
    """Run challenge corpus benchmark."""
    jid = _new_job()

    def _run_bench(jid):
        try:
            from tests.corpus.benchmark import benchmark_crypto
            result = benchmark_crypto()
            _finish_job(jid, [{"type": "benchmark", "data": result}])
        except Exception as e:
            _finish_job(jid, [], error=f"{e}\n{traceback.format_exc()}")

    t = threading.Thread(target=_run_bench, args=(jid,), daemon=True)
    t.start()
    return jsonify({"job_id": jid})


# ── Evidence Dashboard API ───────────────────────────────────────────────────

@app.route("/api/evidence/<jid>")
def api_evidence(jid):
    """Get structured evidence data for the live dashboard."""
    with _lock:
        job = _jobs.get(jid)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    elapsed = (job["finished"] or time.time()) - job["started"]
    results = job["results"]

    # Classify results into dashboard sections
    flags = [r for r in results if r.get("type") == "flag"]
    candidates = [r for r in results if r.get("type") == "candidate"]
    decodes = [r for r in results if r.get("type") == "decode"]
    scans = [r for r in results if r.get("type") in ("scan", "network", "image")]
    errors = [r for r in results if r.get("type") == "error"]

    return jsonify({
        "status": job["status"],
        "elapsed": round(elapsed, 1),
        "summary": {
            "total_findings": len(flags) + len(candidates),
            "verified_flags": len(flags),
            "candidates": len(candidates),
            "decodes": len(decodes),
            "scan_sections": len(scans),
            "errors": len(errors),
        },
        "flags": flags,
        "candidates": candidates[:20],
        "decodes": decodes[:30],
        "scans": scans[:20],
        "error": job["error"],
    })


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF Auto Web UI")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    print(f"\n  🚩 CTF Auto — Web UI")
    print(f"  http://localhost:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=False)
