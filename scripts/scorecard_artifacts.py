#!/usr/bin/env python3
"""Replay the engine over a folder of real competition artifacts.

This is the honest scorecard: it runs the same isolated worker the CLI uses on
each file of a challenge set and reports, per challenge, whether the expected
flag was recovered and whether any self-labelled decoy leaked into the
findings.  It is meant to be run on a folder of files you already have on
disk, so nothing is downloaded and no scoreboard is contacted.

Usage:
    python3 scripts/scorecard_artifacts.py --dir "/path/to/artifacts"
    python3 scripts/scorecard_artifacts.py --dir ... --seconds 90 --json out.json

The built-in answer key targets the Cyber Hero Chiang Rai CTF set.  Pass
``--answers path.json`` to score a different set with your own key.
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.competition import run_isolated

# artifact -> (category, expected flag or None, note, external tool needed)
DEFAULT_KEY = {
    'X3_step': ('crypto', 'CYBERHEROCTF{MkaeX345fsimple}', 'hex -> reverse -> rot13', None),
    'gpio_capture.csv': ('logic', 'CYBERHEROCTF{L0G1C_4N4LYZ3R_C4PTUR3}',
                         'even-parity parallel bus', None),
    'find_me': ('reverse', 'CYBERHEROCTF{pl3ase_Find_me_r3verSe}',
                'bytes written to the stack in main', None),
    'cyber_hero.jpeg': ('image', 'CYBERHEROCTF{423945235349405354242495485040}',
                        'steghide payload (empty passphrase)', 'stegseek'),
    'factory_incident.pcap': ('network', None,
                              'decoy maze + ip.id covert channel (all decoys)', None),
    'blynk-2-27-34.apk': ('auto', None,
                          'APK: embedded domain decoy demoted to IOC', None),
    'Capture The Hill.md': ('auto', 'CYBERHEROCTF{2642.281}',
                            'manual OSINT; not auto-solvable', None),
    'Capture The Flower.md': ('auto', 'CYBERHEROCTF{3.8895238914,115.4350038104}',
                              'manual image geolocation', None),
}

# Challenges whose answer requires human OSINT; they are reported, not scored.
MANUAL = {'Capture The Hill.md', 'Capture The Flower.md'}


def _norm(value):
    return ''.join(ch for ch in str(value or '') if not ch.isspace())


def score_one(path, category, expected, seconds):
    result = run_isolated(path, {'category': category, 'deep': False}, seconds)
    findings = result.get('findings', [])
    # Only verified/candidate items are flag *claims*; "decode" entries are raw
    # evidence (including IOC notes) and must not count as reported flags.
    claims = [_norm(f.get('value')) for f in findings
              if f.get('kind') in ('verified', 'candidate')]
    values = [_norm(f.get('value')) for f in findings]
    notes = [str(n.get('reason', '')) for n in result.get('notes', [])]
    decoys = [d.get('value') if isinstance(d, dict) else d
              for d in result.get('decoys', [])]
    leaked = [v for v in claims if v and any(_norm(v) == _norm(d) for d in decoys)]
    ioc = [reason for reason in notes if 'IOC only' in reason]
    # Decoded output with an unverified format is surfaced, not scored.
    decoded = [_norm(f.get('value')) for f in findings if f.get('kind') == 'decode']
    if expected is None:
        ok = not any(v.startswith('CYBERHEROCTF{') for v in claims) and not leaked
    else:
        ok = any(v == _norm(expected) for v in claims)
    return {
        'status': result.get('status'),
        'seconds': result.get('elapsed_seconds'),
        'expected': expected,
        'ok': bool(ok),
        'leaked_decoys': leaked,
        'decoy_count': len(decoys),
        'ioc_only': ioc,
        'covert_channels': [reason for reason in notes
                            if 'covert header channel' in reason],
        'decoded_count': len(decoded),
        'decoded': decoded[:4],
        'top_findings': values[:6],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', required=True, help='folder holding the artifact files')
    parser.add_argument('--answers', help='JSON file with your own answer key')
    parser.add_argument('--seconds', type=float, default=75.0, help='deadline per artifact')
    parser.add_argument('--json', default='', help='also write machine-readable results here')
    args = parser.parse_args()

    root = Path(args.dir).expanduser().resolve()
    if not root.is_dir():
        parser.error('--dir must be an existing directory')
    key = json.loads(Path(args.answers).read_text()) if args.answers else DEFAULT_KEY
    known_names = set(key)

    rows = []
    for name, spec in sorted(key.items(), key=lambda kv: kv[0].lower()):
        path = root / name
        if not path.exists():
            rows.append({'name': name, 'skipped': 'missing in --dir'})
            continue
        if isinstance(spec, list):
            category, expected, note = (spec + [None, ''])[:3]
            requires = None
        else:
            category, expected, note, requires = (list(spec) + [None, None])[:4]
        if requires and not shutil.which(requires):
            rows.append({'name': name, 'category': category, 'expected': expected,
                         'requires': requires, 'note': note,
                         'needs_tool': True})
            continue
        if name in MANUAL:
            rows.append({'name': name, 'category': category, 'note': note,
                         'expected': expected, 'manual': True})
            continue
        scored = score_one(path, category, expected, args.seconds)
        scored.update({'name': name, 'category': category, 'note': note})
        rows.append(scored)

    extras = sorted(p.name for p in root.iterdir()
                    if p.is_file() and p.name not in known_names
                    and not p.name.startswith('.'))
    passed = sum(1 for r in rows if r.get('ok'))
    total = sum(1 for r in rows if 'ok' in r)
    width = max((len(r['name']) for r in rows), default=10)
    print('CTF Auto artifact scorecard')
    print('=' * (width + 60))
    for row in rows:
        if 'skipped' in row:
            print(f"  {row['name']:<{width}}  SKIP  ({row['skipped']})")
            continue
        if row.get('needs_tool'):
            print(f"  {row['name']:<{width}}  NEEDS-TOOL  {row['expected']}  "
                  f"(install '{row['requires']}' to extract)  ({row['note']})")
            continue
        if row.get('manual'):
            print(f"  {row['name']:<{width}}  MANUAL {row['category']:<8} "
                  f"{row['expected']}  ({row['note']})")
            continue
        verdict = 'PASS' if row['ok'] else 'FAIL'
        expected = row['expected'] or '(no single flag)'
        print(f"  {row['name']:<{width}}  {verdict}  {row['category']:<8} {expected}")
        if not row['ok']:
            print(f"    top findings : {row['top_findings']}")
        print(f"    decoys ignored: {row['decoy_count']}"
              f"{'  leaked=' + str(row['leaked_decoys']) if row['leaked_decoys'] else ''}"
              f"  status={row['status']} {row['seconds']}s")
        if row.get('decoded_count'):
            print(f"    decoded (any format): {row['decoded_count']} shown, "
                  f"e.g. {row['decoded'][:2]}")
        for channel in row['covert_channels']:
            print(f"    covert       : {channel[:140]}")
        for reason in row.get('ioc_only', []):
            print(f"    ioc only     : {reason[:140]}")
    print('=' * (width + 60))
    manual = sum(1 for r in rows if r.get('manual'))
    needs = sum(1 for r in rows if r.get('needs_tool'))
    summary = f"score: {passed}/{total} automated challenges solved"
    extra = []
    if manual:
        extra.append(f"{manual} manual/OSINT")
    if needs:
        extra.append(f"{needs} need an external tool")
    if extra:
        summary += '  (+' + ', '.join(extra) + ')'
    print(summary)
    if extras:
        print('unscored files present: ' + ', '.join(extras))
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2) + '\n')
        print('wrote ' + args.json)
    return 0 if passed == total else 1


if __name__ == '__main__':
    raise SystemExit(main())
