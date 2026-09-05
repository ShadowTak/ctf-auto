#!/usr/bin/env python3
"""Reproducible exact-answer speed checks; no downloaded challenge code."""
import argparse
import base64
import gzip
import json
from pathlib import Path
import statistics
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.competition import run_isolated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--output', default='output/performance/current.json')
    args = parser.parse_args()
    if not 1 <= args.repeat <= 20:
        parser.error('--repeat must be 1..20')
    cases = []
    for depth in (8, 16, 24):
        expected = b'CTF{layered_speed_evidence}'
        value = expected
        for _ in range(depth):
            value = base64.b64encode(value)
        cases.append((f'base64-{depth}', value, expected.decode()))
    expected = b'CTF{mixed_binary_layers}'
    value = expected
    for _ in range(3):
        value = base64.b64encode(gzip.compress(value, mtime=0)).hex().encode()
    cases.append(('mixed-9', value, expected.decode()))
    results = []
    with tempfile.TemporaryDirectory() as directory:
        for name, data, expected in cases:
            path = Path(directory, name + '.txt'); path.write_bytes(data)
            trials = []
            for _ in range(args.repeat):
                result = run_isolated(path, {}, 6)
                verified = {f['value'] for f in result['findings'] if f['kind'] == 'verified'}
                trials.append({'seconds': result['elapsed_seconds'], 'status': result['status'],
                               'correct': verified == {expected}})
            results.append({'case': name, 'bytes': len(data), 'trials': trials,
                            'median_seconds': statistics.median(t['seconds'] for t in trials),
                            'correct': all(t['correct'] for t in trials)})
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))
    return 0 if all(r['correct'] for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
