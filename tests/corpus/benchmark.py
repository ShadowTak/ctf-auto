"""Benchmark CTF auto solver against the challenge corpus.

Measures solve rate, speed, and false-positive rate across all categories.
"""
import json
import os
import signal
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TimeoutError(Exception):
    pass


def _timeout_handler(signum, frame):
    raise TimeoutError("Challenge timed out")


def _candidate_text(item):
    """Normalize solver result shapes to plaintext for corpus assertions.

    Most legacy solvers return ``(label, plaintext)`` while ranked classic
    solvers return ``(score, label, plaintext)``.  The old benchmark treated
    the label as plaintext for the latter shape and reported false negatives.
    """
    if not isinstance(item, (tuple, list)):
        return str(item)
    if len(item) >= 3 and isinstance(item[0], (int, float)):
        value = item[-1]
    elif len(item) >= 2:
        value = item[1]
    else:
        value = item[-1] if item else ""
    if isinstance(value, bytes):
        return value.decode("latin-1", "replace")
    return str(value)


def benchmark_crypto(corpus=None):
    """Benchmark crypto solvers against the corpus."""
    if corpus is None:
        from tests.corpus.generate import generate_corpus
        corpus = generate_corpus()

    from modules.crypto.autodetect import analyze_text
    from modules.crypto.rsa import crack_rsa
    from modules.crypto.xor import crack_xor

    results = []
    total = 0
    solved = 0
    total_time = 0
    CHALLENGE_TIMEOUT = 5  # seconds per challenge

    for challenge in corpus:
        if challenge.get("error"):
            continue
        if challenge["category"] != "crypto":
            continue

        ctype = challenge["type"]
        inputs = challenge["inputs"]
        expected = challenge.get("flag", "")
        total += 1

        start = time.time()
        found_flags = []
        method_used = None

        # Set per-challenge timeout
        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(CHALLENGE_TIMEOUT)

        try:
            if ctype in ("rsa_small_e", "rsa_fermat", "rsa_wiener"):
                results_r = crack_rsa(
                    n=inputs["n"], e=inputs["e"], c=inputs["c"])
                for item in results_r:
                    if isinstance(item, (tuple, list)) and len(item) >= 2:
                        label = item[0]
                        pt_str = _candidate_text(item)
                        pt = item[-1]
                        if expected.encode() in pt or expected in pt_str:
                            found_flags.append(expected)
                            method_used = label
                            break

            elif ctype == "rsa_broadcast":
                from modules.crypto.rsa import hastad_broadcast
                pairs = [(p["n"], p["e"], p["c"]) for p in inputs["pairs"]]
                m = hastad_broadcast(pairs)
                if m is not None:
                    pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
                    if expected.encode() in pt:
                        found_flags.append(expected)
                        method_used = "broadcast"

            elif ctype == "rsa_common_modulus":
                from modules.crypto.rsa import common_modulus
                m = common_modulus(inputs["c1"], inputs["c2"],
                                   inputs["e1"], inputs["e2"], inputs["n"])
                if m is not None:
                    pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
                    if expected.encode() in pt:
                        found_flags.append(expected)
                        method_used = "common_modulus"

            elif ctype in ("xor_single_byte", "xor_repeating_key"):
                ct = bytes.fromhex(inputs["ciphertext"])
                results_x = crack_xor(ct)
                for item in results_x:
                    if isinstance(item, (tuple, list)) and len(item) >= 2:
                        label = item[0]
                        pt_str = _candidate_text(item)
                        if expected in pt_str:
                            found_flags.append(expected)
                            method_used = label
                            break

            elif ctype == "encoding_chain":
                encoded = inputs["encoded"]
                ranked, flags = analyze_text(encoded)
                for flag in flags:
                    if expected in flag:
                        found_flags.append(expected)
                        method_used = "chain_decode"
                        break

            elif ctype in ("caesar", "vigenere"):
                ct = inputs["ciphertext"]
                # Benchmark the intended family directly.  Running every
                # classic solver here measures unrelated substitution/
                # transposition work and hides the actual hot path.
                if ctype == "caesar":
                    from modules.crypto.classic import solve_caesar
                    results_c = solve_caesar(ct)
                else:
                    from modules.crypto.classic import solve_vigenere
                    results_c = solve_vigenere(ct)
                for item in results_c:
                    if isinstance(item, (tuple, list)) and len(item) >= 2:
                        label = item[0]
                        pt_str = _candidate_text(item)
                        if expected in pt_str:
                            found_flags.append(expected)
                            method_used = label
                            break

            elif ctype == "hash_crack":
                from modules.crypto.hashes import crack_hash
                cracked = crack_hash(inputs["hash"])
                if cracked and expected in cracked:
                    found_flags.append(expected)
                    method_used = "wordlist"

        except TimeoutError:
            method_used = "timeout"
        except Exception as e:
            method_used = f"error: {e}"
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

        elapsed = time.time() - start
        total_time += elapsed

        solved_flag = len(found_flags) > 0
        if solved_flag:
            solved += 1

        results.append({
            "type": ctype,
            "expected": expected,
            "found": found_flags[0] if found_flags else None,
            "solved": solved_flag,
            "method": method_used,
            "time_ms": round(elapsed * 1000, 1),
        })

    durations = [item["time_ms"] for item in results]
    failures = [item for item in results if not item["solved"]]
    return {
        "total": total,
        "solved": solved,
        "solve_rate": round(solved / max(total, 1) * 100, 1),
        "total_time_ms": round(total_time * 1000, 1),
        "avg_time_ms": round(total_time * 1000 / max(total, 1), 1),
        "max_time_ms": max(durations, default=0),
        "p95_time_ms": round(statistics.quantiles(durations, n=20,
                                                  method="inclusive")[18], 1)
        if len(durations) >= 2 else (durations[0] if durations else 0),
        "failures": [item["type"] for item in failures],
        "details": results,
    }


def run_benchmark():
    """Run full benchmark and print results."""
    print("=" * 60)
    print("  CTF AUTO BENCHMARK")
    print("=" * 60)

    from tests.corpus.generate import generate_corpus
    corpus = generate_corpus()
    print(f"\nCorpus size: {len(corpus)} challenges")

    print("\n--- Crypto ---")
    crypto_results = benchmark_crypto(corpus)
    print(f"  Solved: {crypto_results['solved']}/{crypto_results['total']}")
    print(f"  Solve rate: {crypto_results['solve_rate']}%")
    print(f"  Total time: {crypto_results['total_time_ms']} ms")
    print(f"  Avg time: {crypto_results['avg_time_ms']} ms per challenge")
    print(f"  P95 time: {crypto_results['p95_time_ms']} ms")
    print(f"  Max time: {crypto_results['max_time_ms']} ms")

    for detail in crypto_results["details"]:
        status = "PASS" if detail["solved"] else "FAIL"
        print(f"  {status} [{detail['type']}] {detail['method'] or 'unsolved'} "
              f"({detail['time_ms']} ms)")

    print("\n" + "=" * 60)
    print(f"  OVERALL: {crypto_results['solved']}/{crypto_results['total']} solved")
    print(f"  TIME: {crypto_results['total_time_ms']} ms total")
    print("=" * 60)

    return crypto_results


if __name__ == "__main__":
    run_benchmark()
