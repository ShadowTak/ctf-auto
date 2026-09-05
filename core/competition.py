"""Competition queue with process isolation, hard deadlines and resumable JSON.

Each immediate file/subdirectory of --batch is one challenge. A directory
submitted as a single target is a multi-file challenge, enabling RSA correlation.
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
MAX_FILES = 64
MAX_BYTES = 16 * 1024 * 1024


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _inventory(target):
    from modules.crypto.correlation import collect
    return collect(str(target), max_files=MAX_FILES, max_bytes=MAX_BYTES)


def engine_digest():
    digest = hashlib.sha256()
    for base in (ROOT / 'core', ROOT / 'modules'):
        for path in sorted(base.rglob('*.py')):
            digest.update(str(path.relative_to(ROOT)).encode())
            digest.update(path.read_bytes())
    # A dependency/backend change can alter results even without a code change.
    from importlib.metadata import distributions
    versions = sorted((d.metadata.get('Name', ''), d.version) for d in distributions())
    digest.update(json.dumps([sys.version, versions]).encode())
    return digest.hexdigest()


def fingerprint(target, options, engine):
    files = _inventory(target)
    digest = hashlib.sha256(json.dumps([engine, options], sort_keys=True).encode())
    for item in files:
        digest.update(item['path'].encode())
        digest.update(item['sha256'].encode())
    return digest.hexdigest(), files


def solve_target(target, *, prefix=None, deep=False, passwords=(), category='auto', progress=None):
    """Run only inside an isolated worker when a hard deadline is required."""
    import re
    from core.evidence import EvidenceLedger
    from core.flag import extract_flags, normalize_prefix
    from core.artifact_triage import inspect_artifact, json_evidence
    from core.planner import artifact_kind
    from modules.crypto.artifacts import extract
    from modules.crypto.rsa_bundle import solve_inventory

    ledger = EvidenceLedger()
    files = _inventory(target)
    if category not in {'auto', 'crypto', 'image', 'network'}:
        raise ValueError('Unknown artifact category')
    if not files:
        raise ValueError('No readable regular artifacts within the file/byte limits')
    result = {'status': 'running', 'findings': [], 'artifacts': [], 'notes': [],
              'files': [{k: v for k, v in f.items() if k != 'data'} for f in files]}

    def publish():
        result['findings'] = ledger.as_dicts()[:1000]
        if progress:
            progress(result)

    def scan_text(text, source, verified=True, evidence=()):
        known, candidates = extract_flags(text)
        expected = normalize_prefix(prefix)
        if expected:
            known += re.findall(re.escape(expected) + r'[^}\r\n]{1,300}\}', text)
        for value in dict.fromkeys(known + candidates):
            confirmed = verified and value in known
            ledger.add_flag(value, source=source, verified=confirmed,
                            confidence=0.99 if confirmed else 0.65,
                            evidence=tuple(evidence) + ('exact recovered text; scoreboard acceptance untested',))
        return bool(known or candidates)

    solved_sources = set()
    for solved in solve_inventory(files):
        solved_sources.update(solved['sources'])
        source = solved['method'] + ':' + ','.join(solved['sources'])
        scan_text(solved['plaintext'], source, evidence=solved['evidence'])
        ledger.add(solved['plaintext'], source=source, confidence=1.0,
                   evidence=solved['evidence'] + ['plaintext hex: ' + solved['plaintext_hex']])
    publish()
    expanded = 0
    for item in files:
        path, data = item['path'], item['data']
        kind = artifact_kind(path)
        if category == 'image' and kind != 'image':
            raise ValueError('Image mode requires a recognized image. Use Auto CTF for disguised artifacts.')
        if category == 'network' and kind not in {'pcap', 'pcapng'}:
            raise ValueError('Network mode requires PCAP/PCAPNG. Use Auto CTF for other artifacts.')
        notes = []
        members = extract(data, passwords=passwords, diagnostics=notes)
        result['artifacts'].append({'path': path, 'kind': kind, 'members': len(members)})
        result['notes'].extend({'source': path, **note} for note in notes)
        if len(members) > 1 and category in {'auto', 'crypto'}:
            bundle = [{'path': path + ':' + label, 'data': value} for label, value in members[1:]]
            for solved in solve_inventory(bundle):
                solved_sources.update(solved['sources'])
                source = solved['method'] + ':' + ','.join(solved['sources'])
                scan_text(solved['plaintext'], source, evidence=solved['evidence'])
                ledger.add(solved['plaintext'], source=source, confidence=1.0,
                           evidence=solved['evidence'] + ['plaintext hex: ' + solved['plaintext_hex']])
        for label, member in members:
            expanded += len(member)
            if expanded > 128 * 1024 * 1024:
                result['notes'].append({'source': path, 'reason': 'challenge expanded-byte limit'})
                break
            source = path + ':' + label
            text = member.decode('utf-8', 'replace')
            found = scan_text(text, source)
            for encoding in ('utf-16-le', 'utf-16-be'):
                if b'\x00' in member[:65536]:
                    found |= scan_text(member.decode(encoding, 'replace'), source + ':' + encoding)
            triage = inspect_artifact(member)
            if triage['kind'] != 'binary':
                result['artifacts'].append({'path': source, **{k: v for k, v in triage.items() if k != 'texts'}})
                for where, content in triage['texts']:
                    found |= scan_text(content, source + ':' + where)
            publish()  # Keep early evidence even if a deeper solver times out.
            printable = sum(c.isprintable() or c in '\r\n\t' for c in text) / max(1, len(text))
            if not member or len(member) > 256 * 1024 or printable < 0.90:
                continue
            if found and not deep:
                continue
            from modules.crypto.fastlane import decode_fast, TRANSPORTS
            for method, output in decode_fast(member, prefix=prefix):
                if scan_text(output, source + ':' + method,
                             verified=all(part in TRANSPORTS for part in method.split('>')),
                             evidence=['byte-preserving fast path', 'layers: ' + str(len(method.split('>')))]):
                    found = True
            publish()
            if found and not deep:
                continue
            # Deterministic chains first; long source files should not enter
            # expensive substitution/XOR guessing unless --deep was requested.
            from modules.crypto.encodings import chain_decode_best
            for method, output in chain_decode_best(text, max_depth=12, max_branches=12,
                                                    max_nodes=1200, timeout=3):
                is_exact = all(part in TRANSPORTS for part in method.split('>'))
                if scan_text(str(output), source + ':' + method, verified=is_exact):
                    found = True
            publish()
            if (deep or not found) and len(member) <= 32768:
                # RSA bundle results already validate matching parameter files.
                record_source = path if label == 'root' else source
                if not deep and any(s == record_source or s.startswith(record_source + ':') for s in solved_sources):
                    continue
                from modules.crypto.autodetect import analyze_text_evidence
                ranked, findings = analyze_text_evidence(text, prefix_hint=prefix)
                for finding in findings:
                    ledger.add(finding.value, kind=finding.kind,
                               source=source + ':' + finding.source,
                               confidence=finding.confidence, evidence=finding.evidence)
                for score, method, output in ranked[:12]:
                    ledger.add(str(output)[:5000], source=source + ':' + method,
                               confidence=0.0, evidence=['raw solver output; score=' + str(score)])
                publish()
        if kind in ('pcap', 'pcapng') and category in {'auto', 'network'}:
            from modules.network.pcap import analyze_pcap
            report = analyze_pcap(path)
            result['artifacts'].append({'path': path, 'kind': 'pcap', 'details': json_evidence(report)})
            for value in report.get('flags', []):
                scan_text(value, path + ':pcap', verified=False)
        if kind == 'image' and category in {'auto', 'image'}:
            from modules.image.forensics import analyze_image
            report = analyze_image(path)
            details = {k: report[k] for k in ('format', 'summary', 'metadata', 'anomalies', 'stego', 'tools') if k in report}
            result['artifacts'].append({'path': path, 'kind': 'image', 'details': details})
            for finding in report.get('findings', []):
                ledger.add(finding['value'], kind=finding['kind'], source=path + ':' + finding.get('source', 'image'),
                           confidence=finding.get('confidence', .65), evidence=finding.get('evidence', []))
        publish()
    if len(files) == MAX_FILES:
        result['notes'].append({'reason': 'file-count limit may have truncated this challenge'})
    result['status'] = 'completed'
    publish()
    return result


def _stop(process):
    if os.name == 'posix':
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        process.kill()
    process.wait()


def run_isolated(target, options, seconds, *, stop_event=None, on_progress=None):
    """A real process deadline, including stuck solvers and their subprocesses."""
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='ctf-auto-job-') as directory:
        spec, output = Path(directory) / 'input.json', Path(directory) / 'result.json'
        atomic_json(spec, {'target': str(target), **options})
        env = dict(os.environ, CTF_AUTO_WORKERS='2', PYTHONUNBUFFERED='1')
        process = subprocess.Popen([sys.executable, '-m', 'core.competition',
                                    '--worker', str(spec), str(output)],
                                   cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=os.name == 'posix')
        timed_out = cancelled = False
        last_progress = 0
        try:
            while process.poll() is None:
                cancelled = bool(stop_event and stop_event.is_set())
                timed_out = time.monotonic() - started >= seconds
                if cancelled or timed_out:
                    _stop(process)
                    break
                if on_progress and time.monotonic() - last_progress >= 0.25:
                    last_progress = time.monotonic()
                    try:
                        on_progress(json.loads(output.read_text()))
                    except (OSError, ValueError):
                        pass
                time.sleep(0.05)
        except BaseException:
            _stop(process)
            raise
        try:
            result = json.loads(output.read_text())
        except (OSError, ValueError):
            result = {'findings': [], 'artifacts': [], 'notes': []}
        if cancelled:
            result['status'] = 'cancelled'
        elif timed_out:
            result['status'] = 'timeout'
        elif process.returncode or result.get('status') != 'completed':
            result['status'] = 'error'
            result.setdefault('error', 'Worker exited with code ' + str(process.returncode))
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        return result


def run_batch(target, *, output='competition-results', jobs=2, seconds=60,
              resume=False, prefix=None, deep=False, single=False):
    import threading
    target, output = Path(target).absolute(), Path(output).absolute()
    if not target.exists() or target.is_symlink():
        raise ValueError('Target must be an existing regular file or directory')
    if not 1 <= jobs <= 8 or not 0.1 <= seconds <= 86400:
        raise ValueError('jobs must be 1..8 and seconds must be 0.1..86400')
    if output == target or (target.is_dir() and target in output.parents):
        raise ValueError('Output directory must be outside the challenge input directory')
    targets = [target] if single or target.is_file() else sorted(
        p for p in target.iterdir() if not p.name.startswith('.') and
        not p.is_symlink() and (p.is_file() or p.is_dir()))
    if not targets or len(targets) > 256:
        raise ValueError('Provide between 1 and 256 challenges')
    options = {'prefix': prefix, 'deep': deep}
    engine = engine_digest()
    manifest = output / 'results.json'
    old = {}
    if resume and manifest.is_file():
        previous = json.loads(manifest.read_text())
        if previous.get('schema_version') == SCHEMA_VERSION:
            old = {j['target']: j for j in previous.get('jobs', [])}
    report = {'schema_version': SCHEMA_VERSION, 'engine_sha256': engine,
              'target': str(target), 'options': options, 'jobs': [],
              'verification': 'local evidence only; no scoreboard submissions'}
    pending = []
    for path in targets:
        key, files = fingerprint(path, options, engine)
        prior = old.get(str(path))
        if prior and prior.get('fingerprint') == key and prior.get('status') == 'completed':
            report['jobs'].append(dict(prior, resumed=True))
        else:
            item = {'target': str(path), 'name': path.name, 'fingerprint': key,
                    'status': 'queued', 'findings': [], 'resumed': False}
            report['jobs'].append(item)
            pending.append(item)

    def checkpoint():
        atomic_json(manifest, report)
        lines = ['# CTF Auto competition results', '', report['verification'], '']
        for job in report['jobs']:
            lines += ['## ' + job['name'].replace('\n', ' '), '',
                      'Status: ' + job['status'] + (' (resumed)' if job.get('resumed') else ''), '']
            for finding in job.get('findings', []):
                if finding.get('kind') in ('verified', 'candidate'):
                    # JSON quoting keeps arbitrary flag syntax literal in a text report.
                    lines.append('- ' + finding['kind'].upper() + ': ' + json.dumps(finding['value'], ensure_ascii=False))
            lines.append('')
        (output / 'results.md').write_text('\n'.join(lines), encoding='utf-8')

    checkpoint()
    stop = threading.Event()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=jobs)
    try:
        futures = {pool.submit(run_isolated, item['target'], options, seconds,
                               stop_event=stop): item for item in pending}
        for future in concurrent.futures.as_completed(futures):
            item = futures[future]
            try:
                item.update(future.result())
                current, _ = fingerprint(item['target'], options, engine)
                if current != item['fingerprint']:
                    item['status'] = 'input_changed'
            except Exception as exc:
                item.update(status='error', error=str(exc))
            checkpoint()
            print(f"[{item['status']}] {item['name']} ({item.get('elapsed_seconds', 0):.2f}s)", flush=True)
    except KeyboardInterrupt:
        stop.set()
        for future, item in futures.items():
            if not future.cancel():
                try:
                    item.update(future.result())
                except Exception:
                    item['status'] = 'cancelled'
            else:
                item['status'] = 'cancelled'
        checkpoint()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    return report


def _worker(spec, output):
    try:
        options = json.loads(Path(spec).read_text())
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink):
            result = solve_target(**options, progress=lambda value: atomic_json(output, value))
        atomic_json(output, result)
    except Exception as exc:
        try:
            result = json.loads(Path(output).read_text())
        except (OSError, ValueError):
            result = {'findings': []}
        result.update(status='error', error=type(exc).__name__ + ': ' + str(exc))
        atomic_json(output, result)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--worker':
        _worker(sys.argv[2], sys.argv[3])
