#!/usr/bin/env python3
"""Small repeatable speed check for the hot crypto/image paths.

Examples:
    python3 benchmarks/benchmark_speed.py
    python3 benchmarks/benchmark_speed.py --image suspicious.png --repeat 5
"""
import argparse
import base64
import io
import os
import statistics
import sys
import time
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


SAMPLE = base64.b64encode(
    b"ductf{benchmark_decode_path}"
).decode()


def timed(label, fn, repeat):
    values = []
    for _ in range(repeat):
        sink = io.StringIO()
        started = time.perf_counter()
        with redirect_stdout(sink), redirect_stderr(sink):
            fn()
        values.append((time.perf_counter() - started) * 1000)
    print(f"{label:28} median={statistics.median(values):8.2f} ms  runs={repeat}")
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", help="optional image artifact to benchmark")
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    repeat = max(1, args.repeat)

    from modules.crypto import encodings
    from modules.crypto.autodetect import analyze_text_evidence

    print("CTF-AUTO speed benchmark")
    timed("encodings cold", lambda: encodings._try_all_encodings_uncached(SAMPLE), 1)
    timed("encodings cached", lambda: encodings.try_all_encodings(SAMPLE), repeat)
    timed("crypto evidence cold", lambda: analyze_text_evidence(SAMPLE), 1)
    timed("crypto evidence cached", lambda: analyze_text_evidence(SAMPLE), repeat)

    if args.image:
        from modules.image.forensics import analyze_image
        timed("image forensics", lambda: analyze_image(args.image), 1)


if __name__ == "__main__":
    main()
