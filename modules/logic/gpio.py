"""Logic-analyzer / GPIO capture decoding.

Hardware and "misc" CTF challenges hand out a raw capture of microcontroller
pins — a CSV of ``timestamp,GPIO0..GPIO7``, a Logic/Saleae text export or a
simple VCD — and expect the solver to work out *which* pin is the clock, which
four pins form the parallel data bus, which pin carries parity, where each
frame starts and how the two nibbles map onto a byte.

Nothing in the capture says any of that, so this module recovers it from the
samples themselves:

1. statistics (transition counts, pulse widths) separate strobe from data
2. exhaustive clock x data-group x parity search, scored by even-parity match
3. frames formed from strobe pulse pairs, sampled at several offsets
4. nibble bit-order + inversion search, scored by printable/flag-shaped output
5. bounded repair of frames whose high nibble was lost

Output is a report plus any flag-shaped text the decoded stream contains.
"""

from __future__ import annotations

import itertools
import os
import re

MAX_SAMPLES = 4_000_000
MAX_COLUMNS = 40
MIN_FRAMES = 6
PARITY_MIN_RATE = 0.98
NARROW_PULSE = 2


# Sample parsing ------------------------------------------------------------


def _numeric(text):
    text = text.strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        pass
    try:
        return int(float(text))
    except ValueError:
        return None


def parse_samples(source):
    """Parse a capture file/text into (labels, columns).

    ``columns[j][i]`` is the level of pin ``j`` at sample ``i``.  Lines that do
    not parse as numeric data become the header; comment lines are skipped.
    """
    if os.path.isfile(str(source)):
        with open(source, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(MAX_SAMPLES * 16)
    else:
        text = str(source)
    labels, rows = [], []
    for raw_line in text.splitlines()[:MAX_SAMPLES]:
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        parts = [part for part in re.split(r"[,\t;|]+|\s{1,}", line) if part != ""]
        if len(parts) < 3 or len(parts) > MAX_COLUMNS:
            continue
        values = [_numeric(part) for part in parts]
        if any(value is None for value in values):
            if not rows:
                labels = [part.strip() for part in parts]
            continue
        rows.append(values)
    if not rows:
        return [], []
    width = min(len(row) for row in rows)
    rows = [row[:width] for row in rows]
    columns = [[row[index] for row in rows] for index in range(width)]
    if len(labels) != width:
        labels = ["col%d" % index for index in range(width)]
    # Time-like columns (many distinct values) cannot carry digital state.
    digital = [index for index, column in enumerate(columns)
               if len(set(column)) <= 8]
    if len(digital) < 3:
        return [], []
    return ([labels[index] for index in digital],
            [columns[index] for index in digital])


def looks_like_logic_capture(path):
    """Cheap pre-check so auto/batch mode can route sample captures correctly."""
    try:
        labels, columns = parse_samples(path)
    except (OSError, ValueError):
        return False
    if len(columns) < 3 or len(columns[0]) < 24:
        return False
    return sum(1 for column in columns if len(set(column)) <= 2) >= 3


# Signal statistics ---------------------------------------------------------


def _transitions(column):
    return sum(1 for i in range(1, len(column)) if column[i] != column[i - 1])


def _edges(column, rising=True):
    if rising:
        return [i for i in range(1, len(column))
                if column[i - 1] == 0 and column[i] == 1]
    return [i for i in range(1, len(column))
            if column[i - 1] == 1 and column[i] == 0]


def _pulse_widths(column, indices):
    widths = []
    for index in indices:
        width = 1
        cursor = index
        while cursor + 1 < len(column) and column[cursor + 1] == column[index]:
            width += 1
            cursor += 1
        widths.append(width)
    return widths


def _median(values):
    return sorted(values)[len(values) // 2] if values else 0


def _pin_stats(labels, columns):
    stats = []
    for label, column in zip(labels, columns):
        edges = _edges(column)
        widths = _pulse_widths(column, edges)
        stats.append({
            "pin": label,
            "high_ratio": round(sum(column) / max(len(column), 1), 4),
            "transitions": _transitions(column),
            "edges": len(edges),
            "median_pulse": _median(widths),
        })
    return stats


# Bus discovery -------------------------------------------------------------


def discover_bus(labels, columns, min_edges=8):
    """Find (clock pin, edge, data group of 4 pins, parity pin) via even parity.

    Parity is the only invariant the capture gives away for free: when the
    clock edge fires, the parity pin must equal the XOR of the data pins.  A
    mapping that scores 100% over every edge is the real bus.
    """
    best = None
    order = range(len(columns))
    for clock in order:
        for rising in (True, False):
            edges = _edges(columns[clock], rising)
            if len(edges) < min_edges:
                continue
            for group in itertools.combinations([p for p in order if p != clock], 4):
                for parity in order:
                    if parity == clock or parity in group:
                        continue
                    matches = 0
                    for index in edges:
                        xor = (columns[group[0]][index] ^ columns[group[1]][index] ^
                               columns[group[2]][index] ^ columns[group[3]][index])
                        if columns[parity][index] == xor:
                            matches += 1
                    rate = matches / len(edges)
                    if rate < PARITY_MIN_RATE:
                        continue
                    adjacent = all(group[i + 1] - group[i] == 1
                                   for i in range(len(group) - 1))
                    rank = (round(rate, 4), 1 if adjacent else 0, len(edges))
                    if best is None or rank > best[0]:
                        best = (rank, clock, rising, group, parity, len(edges),
                                matches)
    if best is None:
        return None
    rank, clock, rising, group, parity, edge_count, matches = best
    return {
        "clock": labels[clock],
        "clock_index": clock,
        "edge": "rising" if rising else "falling",
        "data_pins": [labels[p] for p in group],
        "data_indices": list(group),
        "parity": labels[parity],
        "parity_index": parity,
        "parity_rate": rank[0],
        "parity_mismatches": int(edge_count - matches),
        "edges": edge_count,
        "adjacent_group": bool(rank[1]),
    }


# Framing -------------------------------------------------------------------


def _strobes(labels, columns, bus):
    """Narrow-pulse pins, most active first — the nibble strobe leads."""
    excluded = set(bus["data_indices"]) | {bus["parity_index"]}
    found = []
    for index, column in enumerate(columns):
        if index in excluded:
            continue
        edges = _edges(column)
        if len(edges) < 2 * MIN_FRAMES:
            continue
        widths = _pulse_widths(column, edges)
        found.append({"index": index, "label": labels[index],
                      "edges": len(edges), "median_pulse": _median(widths)})
    found.sort(key=lambda item: (item["median_pulse"] > NARROW_PULSE,
                                 -item["edges"]))
    # A nibble strobe is a spike (one or two samples wide); wide pulses belong
    # to the frame/enable lines and pairing them mixes nibbles from two frames.
    narrow = [item for item in found if item["median_pulse"] <= NARROW_PULSE]
    return narrow or found


def _constant_runs(column, value):
    runs, start = [], None
    for index, item in enumerate(column):
        if item == value and start is None:
            start = index
        elif item != value and start is not None:
            runs.append((start, index - 1))
            start = None
    if start is not None:
        runs.append((start, len(column) - 1))
    return runs


def _control_pin(columns, bus, strobe_index, expected_frames):
    """Find the active-low frame line that gates the strobe."""
    excluded = set(bus["data_indices"]) | {bus["parity_index"], strobe_index}
    best = None
    for index, column in enumerate(columns):
        if index in excluded:
            continue
        runs = _constant_runs(column, 0)
        if not runs:
            continue
        delta = abs(len(runs) - expected_frames)
        if best is None or delta < best[0]:
            best = (delta, index, len(runs))
    if best is None or best[0] > max(2, expected_frames // 5):
        return None
    return best[1]


def _pulse_pairs(labels, columns, bus, strobe_index):
    """Pair strobe pulses into frames (one byte = two nibbles).

    A gating control line defines frames exactly; without one, consecutive
    strobe pulses are paired, which matches regular captures.
    """
    strobe = columns[strobe_index]
    edges = _edges(strobe)
    frames = [(edges[i], edges[i + 1]) for i in range(0, len(edges) - 1, 2)]
    control = _control_pin(columns, bus, strobe_index, len(edges) // 2)
    if control is None:
        return frames, None
    framed = []
    for start, end in _constant_runs(columns[control], 0):
        pulses = []
        for index in range(start, end + 1):
            if strobe[index] == 1 and (not pulses or index > pulses[-1] + 1):
                pulses.append(index)
        if len(pulses) >= 2:
            framed.append((pulses[0], pulses[1]))
        elif len(pulses) == 1:
            framed.append((pulses[0], pulses[0]))
    if len(framed) >= MIN_FRAMES:
        return framed, labels[control]
    return frames, None


def sample_sets(labels, columns, bus):
    """Candidate nibble positions: strobe pulse pairs at a few offsets.

    The data lines settle just before each strobe pulse, so the sample index
    may need to be the pulse itself or the sample in front of it; both are
    tried and scored rather than guessed.
    """
    limit = len(columns[0])
    sets = []
    for strobe in _strobes(labels, columns, bus)[:2]:
        frames, control = _pulse_pairs(labels, columns, bus, strobe["index"])
        if len(frames) < MIN_FRAMES:
            continue
        for offset in (0, -1, 1):
            first, second = [], []
            for left, right in frames:
                left, right = left + offset, right + offset
                if 0 <= left < limit and 0 <= right < limit:
                    first.append(left)
                    second.append(right)
            if len(first) < MIN_FRAMES:
                continue
            label = "%s pulses, offset %+d" % (strobe["label"], offset)
            if control:
                label += ", framed by " + control
            sets.append({
                "label": label,
                "strobe": strobe["label"],
                "control": control,
                "offset": offset,
                "first": first,
                "second": second,
            })
    return sets


# Nibble mapping ------------------------------------------------------------

# Bit-order permutations x inversions of none/all/single lines: a straight or
# reversed bus, optionally with an active-low data line, is covered.
_MASKS = (0b0000, 0b1111, 0b0001, 0b0010, 0b0100, 0b1000)
_STRAIGHT_PERMS = ((0, 1, 2, 3), (3, 2, 1, 0))


def _mappings(fast=True):
    perms = _STRAIGHT_PERMS if fast else list(itertools.permutations(range(4)))
    return [(perm, mask) for perm in perms for mask in _MASKS]


def _all_mappings():
    """Every bit-order/inversion candidate: 24 permutations x 6 inversions.

    The pruning inside :func:`_search_mappings` makes the full sweep cheap, and
    transposed data lines (``GPIO0,GPIO2,GPIO1,GPIO3``) only appear here.
    """
    return _mappings(fast=False)


def _nibble_lut(mapping):
    perm, mask = mapping
    return bytes(sum((((value >> perm[bit]) & 1) ^ ((mask >> bit) & 1)) << bit
                     for bit in range(4)) for value in range(16))


def _raw_nibbles(columns, group, indices):
    return bytes(sum(columns[group[bit]][index] << bit for bit in range(4))
                 for index in indices)


def _translate(low_raw, high_raw, low_lut, high_lut):
    table = bytes(((high_lut[high] << 4) | low_lut[low]) & 0xFF
                  for high in range(16) for low in range(16))
    combined = bytes(((high_raw[i] << 4) | low_raw[i]) & 0xFF
                     for i in range(len(high_raw)))
    return combined.translate(table)


def _printable(ch):
    return 32 <= ord(ch) < 127 or ch in "\r\n\t"


def _project_text(text):
    """Render a decoded stream with unprintable bytes shown as '?'."""
    return "".join(ch if _printable(ch) else "?" for ch in text)


def _score_text(text):
    if not text:
        return -1e9
    from core.flag import extract_flags, known_prefixes
    printable = sum(1 for ch in text if _printable(ch))
    score = (printable / len(text)) * 100.0
    upper = text.upper()
    for token in ("CTF{", "FLAG", "ACCESS", "LOG:", "PASSWORD", "SECRET",
                  "KEY", "END OF"):
        if token in upper:
            score += 60.0
    # The flag prefix alone is a very strong signal the bus mapping is right,
    # even when the braces themselves were dropped by a dead data line.
    for prefix in known_prefixes():
        if prefix.isalnum() and len(prefix) >= 4 and prefix in text:
            score += 300.0
            break
    try:
        known, _ = extract_flags(text)
        score += 500.0 * len(known)
    except Exception:
        pass
    return score


def _repair_dropped_braces(text, limit=6):
    """Recover ``{``/``}`` whose high nibble was lost to a dead data line.

    The low nibble survives, so a dropped ``{`` still shows as a byte ending in
    0xB.  Substituting those bytes back is enough to close the flag.
    """
    from core.flag import extract_flags
    opens = [index for index, ch in enumerate(text)
             if not _printable(ch) and (ord(ch) & 0x0F) == 0x0B][:limit]
    closes = [index for index, ch in enumerate(text)
              if not _printable(ch) and (ord(ch) & 0x0F) == 0x0D][:limit]
    found, repairs = [], []
    for left in opens:
        for right in closes:
            if right <= left:
                continue
            fixed = text[:left] + "{" + text[left + 1:right] + "}" + text[right + 1:]
            known, _ = extract_flags(fixed)
            for value in known:
                if value not in found:
                    found.append(value)
                    repairs.append({"braces_repaired": value,
                                    "offsets": [left, right]})
    return found, repairs


def _result_from(low_raw, high_raw, low_index, high_index, mappings, luts,
                 label, order):
    produced = _translate(low_raw, high_raw, luts[low_index], luts[high_index])
    text = produced.decode("latin-1")
    return {
        "score": round(_score_text(text), 2),
        "sampling": label,
        "order": "first-nibble-low" if order else "second-nibble-low",
        "low_mapping": {"permutation": list(mappings[low_index][0]),
                        "invert": "0x%X" % mappings[low_index][1]},
        "high_mapping": {"permutation": list(mappings[high_index][0]),
                         "invert": "0x%X" % mappings[high_index][1]},
        "text": text,
        "repaired": [],
    }


def _search_mappings(first_raw, second_raw, label, probe=32, keep=48):
    """Score every (low, high) nibble mapping for one sampling strategy.

    Printable ASCII needs the decoded *high* nibble to land in 0x2..0x7, which
    depends only on the high mapping, so a short window of frames prunes 144
    candidates to a handful before the (low, high) pair sweep.  Bus noise and
    boot chatter usually sit at one end of a capture, so the window is taken
    from both ends and the best mapping is then re-scored on the whole stream.
    """
    mappings = _all_mappings()
    luts = [_nibble_lut(mapping) for mapping in mappings]
    length = len(first_raw)
    probe = max(8, min(probe, length))
    tolerance = max(2, probe // 5)
    results = []
    for order in (True, False):
        low_raw = first_raw if order else second_raw
        high_raw = second_raw if order else first_raw
        for window in (slice(length - probe, length), slice(0, probe)):
            probe_low = low_raw[window]
            probe_high = high_raw[window]
            combined = bytes(((probe_high[i] << 4) | probe_low[i]) & 0xFF
                             for i in range(len(probe_low)))
            scored = []
            for high_index, high_lut in enumerate(luts):
                values = [high_lut[value] for value in probe_high]
                bad = sum(1 for value in values
                          if value != 0 and not 2 <= value <= 7)
                if bad > tolerance:
                    continue
                for low_index, low_lut in enumerate(luts):
                    text = bytes(((values[i] << 4) | low_lut[combined[i] & 0x0F])
                                 & 0xFF for i in range(len(combined))).decode("latin-1")
                    scored.append((_score_text(text), low_index, high_index))
            scored.sort(reverse=True)
            for _, low_index, high_index in scored[:keep]:
                results.append(_result_from(low_raw, high_raw, low_index,
                                            high_index, mappings, luts,
                                            label, order))
    results.sort(key=lambda item: -item["score"])
    return results[:6]


def decode_frames(labels, columns, bus):
    """Search sampling offsets, nibble order and bit mapping for readable text."""
    candidates = sample_sets(labels, columns, bus)
    if not candidates:
        return None
    group = bus["data_indices"]
    results = []
    for entry in candidates:
        first_raw = _raw_nibbles(columns, group, entry["first"])
        second_raw = _raw_nibbles(columns, group, entry["second"])
        results.extend(_search_mappings(first_raw, second_raw, entry["label"]))
    if not results:
        return None
    results.sort(key=lambda item: -item["score"])
    for item in results[1:]:
        item["text"] = _project_text(item["text"])[:400]
    best = dict(results[0])
    from core.flag import extract_flags
    if not extract_flags(best["text"])[0]:
        found, repairs = _repair_dropped_braces(best["text"])
        if found:
            best["repairs"] = repairs
            best["text"] = _project_text(best["text"])
            best["flags"] = found
            best["score"] = round(best["score"] + 500.0 * len(found), 2)
    else:
        best["text"] = _project_text(best["text"])
    return {"best": best, "alternatives": results[1:6]}


# Public API ----------------------------------------------------------------


def analyze_logic_capture(source):
    """Decode a GPIO/logic capture and report any flag found in the stream."""
    labels, columns = parse_samples(source)
    if not labels or not columns:
        return {"status": "unparsed",
                "notes": ["no numeric sample columns found"]}
    report = {
        "status": "ok",
        "samples": len(columns[0]),
        "pins": labels,
        "statistics": _pin_stats(labels, columns),
        "flags": [],
        "decodes": [],
        "notes": [],
    }
    bus = discover_bus(labels, columns)
    if bus is None:
        report.update(status="no-bus", notes=[
            "no clock/data/parity combination matched even parity"])
        return report
    report["bus"] = bus
    decoded = decode_frames(labels, columns, bus)
    if not decoded:
        report.update(status="no-frames", notes=["no strobe pulse pairs found"])
        return report
    best = decoded["best"]
    report["decode"] = decoded
    report["text"] = best["text"]
    report["frames"] = len(_pulse_pairs(labels, columns, bus,
                                        _strobes(labels, columns, bus)[0]["index"])[0])
    from core.flag import extract_flags

    for value in best.get("flags", []):
        if value not in report["flags"]:
            report["flags"].append(value)
        report["notes"].append(
            "recovered flag after repairing dropped nibbles: " + value)
    text = best["text"]
    known, candidates = extract_flags(text)
    for value in known:
        if value not in report["flags"]:
            report["flags"].append(value)
    if candidates:
        report["candidate_flags"] = candidates
    # A decoded stream is often still encoded (rot13, base64, reversed), so the
    # crypto chain gets one bounded pass over the recovered text.
    try:
        from modules.crypto.encodings import chain_decode_best
        for method, output in chain_decode_best(text, max_depth=6,
                                                max_branches=6, max_nodes=300,
                                                timeout=5):
            output = str(output)
            more, _ = extract_flags(output)
            report["decodes"].append({"method": method, "output": output[:400]})
            for value in more:
                if value not in report["flags"]:
                    report["flags"].append(value)
    except Exception as exc:  # solver output is best-effort by design
        report["notes"].append("chain decode skipped: " + str(exc)[:120])
    if bus["parity_mismatches"]:
        report["notes"].append(
            "%d clock edge(s) failed even parity (noisy capture)"
            % bus["parity_mismatches"])
    return report


def format_logic_report(report):
    """Human-readable lines for the CLI."""
    lines = []
    if report.get("status") != "ok":
        lines.append("logic capture: " + str(report.get("status")))
        lines.extend("  " + note for note in report.get("notes", []))
        return lines
    bus = report["bus"]
    lines.append("pins: " + ", ".join(report["pins"]))
    lines.append("samples: %d" % report["samples"])
    lines.append("clock: %s (%s)  data: %s  parity: %s (%.0f%% match, %d mismatch)" % (
        bus["clock"], bus["edge"], ",".join(bus["data_pins"]), bus["parity"],
        bus["parity_rate"] * 100, bus["parity_mismatches"]))
    best = report.get("decode", {}).get("best")
    if best:
        lines.append("sampling: %s  nibble order: %s  score: %s" % (
            best["sampling"], best["order"], best["score"]))
        for entry in best.get("repairs", []):
            lines.append("repaired dropped brace: %(braces_repaired)s at %(offsets)s"
                         % entry)
        lines.append("decoded stream:")
        for line in str(best["text"]).splitlines() or [""]:
            lines.append("  " + line)
    for note in report.get("notes", []):
        lines.append("note: " + note)
    for entry in report.get("decodes", [])[:4]:
        lines.append("chain %s: %s" % (entry["method"], entry["output"][:120]))
    return lines
