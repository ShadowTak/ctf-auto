import base64
import bz2
import gzip
import io
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

from core.competition import run_batch, run_isolated, solve_target
from modules.crypto import artifacts
from modules.crypto.correlation import correlate
from modules.crypto.rsa_bundle import records_from_bytes, solve_records

PRIMES = [4294967291, 4294967279, 4294967231, 4294967197, 4294967189, 4294967161]


def rsa_record(message, p, q, e=65537, source='fixture'):
    n = p * q
    return dict(n=n, e=e, c=pow(int.from_bytes(message, 'big'), e, n), sources=[source])


class BundleTests(unittest.TestCase):
    def test_common_modulus_across_archive_members(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'bundle.zip')
            with zipfile.ZipFile(path, 'w') as z:
                for e in (17, 65537):
                    z.writestr(str(e) + '.json', json.dumps(rsa_record(b'CTF{c}', *PRIMES[:2], e=e)))
            report = solve_target(path)
            self.assertIn('CTF{c}', [f['value'] for f in report['findings']])
    def test_shared_prime_recovers_exact_message(self):
        left = rsa_record(b'CTF{a}', *PRIMES[:2], source='first')
        right = rsa_record(b'CTF{b}', PRIMES[0], PRIMES[2], source='second')
        out = solve_records([left, right])
        self.assertEqual({x['plaintext'] for x in out}, {'CTF{a}', 'CTF{b}'})
        self.assertTrue(all(x['sources'] == ['first', 'second'] for x in out))

    def test_common_modulus_and_tampered_ciphertext(self):
        left = rsa_record(b'CTF{c}', *PRIMES[:2], e=17)
        right = rsa_record(b'CTF{c}', *PRIMES[:2], e=65537)
        out = solve_records([left, right])
        self.assertIn('CTF{c}', [x['plaintext'] for x in out])
        self.assertFalse(solve_records([left, dict(right, c=right['c'] + 1)]))

    def test_broadcast_modular_wrap_and_decoy(self):
        records = [rsa_record(b'CTF{d}', *PRIMES[i:i+2], e=3, source=str(i))
                   for i in (0, 2, 4)]
        self.assertGreater(int.from_bytes(b'CTF{d}', 'big')**3, records[0]['n'])
        decoy = dict(records[-1], c=records[-1]['c'] + 1, sources=['decoy'])
        out = solve_records([decoy] + records)
        good = [x for x in out if x['method'] == 'rsa-hastad-broadcast']
        self.assertTrue(good)
        self.assertEqual(good[0]['plaintext'], 'CTF{d}')
        self.assertNotIn('decoy', good[0]['sources'])

    def test_directory_entrypoint_and_leading_zero_decimal(self):
        with tempfile.TemporaryDirectory() as directory:
            left = rsa_record(b'CTF{e}', *PRIMES[:2], e=17)
            right = rsa_record(b'CTF{e}', *PRIMES[:2], e=65537)
            for i, value in enumerate([left, right]):
                Path(directory, str(i) + '.json').write_text(json.dumps(value))
            out = correlate(directory)
            self.assertIn('CTF{e}', [x['plaintext'] for x in out['solutions']])
        record = records_from_bytes(b'n = 00323\ne = 3\nc = 0042', 'text')[0]
        self.assertEqual((record['n'], record['e'], record['c']), (323, 3, 42))

    def test_structured_bundle_precedes_generic_factoring(self):
        from modules.crypto.structured import analyze
        records = [rsa_record(b'CTF{d}', *PRIMES[i:i+2], e=3) for i in (0, 2, 4)]
        with patch('modules.crypto.rsa.crack_rsa', side_effect=AssertionError('slow ladder')):
            out = analyze(json.dumps({'recipients': records}))
        self.assertTrue(any(b'CTF{d}' == item[1] for item in out))


class ContainerTests(unittest.TestCase):
    def test_concatenated_streams_share_output_budget(self):
        for compressor in (gzip.compress, bz2.compress, lzma.compress):
            data = compressor(b'CTF{') + compressor(b'joined}')
            self.assertEqual(artifacts._decompress(data), b'CTF{joined}')
            self.assertIsNone(artifacts._decompress(data, limit=8))

    def test_reversed_words_recover_binary_header(self):
        data = b'\xff\xd8\xff\xe0' + b'CTF{endianness}'
        swapped = b''.join(data[i:i+4][::-1] for i in range(0, len(data), 4))
        self.assertIn(('byte-swap-32', data), artifacts.byte_order_repairs(swapped))
        self.assertFalse(artifacts.byte_order_repairs(b'just ordinary text'))

    def test_all_compressions_stop_before_expanded_allocation(self):
        for compressor in (gzip.compress, bz2.compress, lzma.compress):
            data = compressor(b'x' * 100000)
            with patch.object(artifacts, 'MAX_MEMBER_BYTES', 2048):
                self.assertIsNone(artifacts._decompress(data))

    def test_budget_is_shared_across_grandchildren(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            for i in range(4):
                archive.writestr(str(i), gzip.compress(b'x' * 1000))
        data = buffer.getvalue()
        with patch.object(artifacts, 'MAX_TOTAL_BYTES', len(data) + 2100):
            out = artifacts.extract(data)
        self.assertLessEqual(sum(len(v) for _, v in out), len(data) + 2100)
        self.assertEqual(sum(v == b'x' * 1000 for _, v in out), 2)

    def test_bad_member_does_not_discard_good_sibling(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('bad.txt', b'broken')
            archive.writestr('../good.txt', b'CTF{f}')
        data = bytearray(buffer.getvalue())
        data[30 + len('bad.txt')] ^= 1
        notes = []
        out = artifacts.extract(data, diagnostics=notes)
        self.assertIn(b'CTF{f}', [v for _, v in out])
        self.assertTrue(notes)

    def test_archive_password_and_unencrypted_siblings(self):
        # ZIP Crypto fixture from a locally generated archive, not downloaded code.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'hidden.txt').write_text('CTF{zip}')
            import shutil
            if not shutil.which('zip'):
                self.skipTest('zip unavailable to generate encrypted fixture')
            subprocess.run(['zip', '-q', '-P', 'contest', str(path / 'x.zip'), 'hidden.txt'],
                           cwd=path, check=True)
            data = (path / 'x.zip').read_bytes()
            self.assertEqual(len(artifacts.extract(data)), 1)
            out = artifacts.extract(data, passwords=['wrong', 'contest'])
            self.assertIn(b'CTF{zip}', [v for _, v in out])


class CompetitionTests(unittest.TestCase):
    def test_tcp_capture_keeps_json_serializable_protocol_evidence(self):
        payload = b'GET / HTTP/1.0\r\nX-Data: ' + base64.b64encode(b'CTF{tcp_capture}') + b'\r\n\r\n'
        tcp = struct.pack('!HHIIBBHHH', 50000, 80, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, b'\x7f\0\0\1', b'\x7f\0\0\2') + tcp
        pcap = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
        pcap += struct.pack('<IIII', 1, 0, len(ip), len(ip)) + ip
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'network.pcap'); path.write_bytes(pcap)
            result = run_isolated(path, {'category': 'network'}, 10)
            self.assertEqual(result['status'], 'completed', result)
            self.assertIn('CTF{tcp_capture}', [f['value'] for f in result['findings']])
            self.assertIn('decoded_blobs', json.dumps(result))

    def test_category_rejects_mismatched_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'not-a-capture.txt')
            path.write_text('CTF{wrong_category}')
            with self.assertRaisesRegex(ValueError, 'Network mode'):
                solve_target(path, category='network')

    def test_pdf_metadata_is_recovered_without_executing_content(self):
        from pypdf import PdfWriter
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'document.pdf')
            writer = PdfWriter()
            writer.add_blank_page(width=72, height=72)
            writer.add_metadata({'/Title': 'CTF{pdf_metadata}'})
            with path.open('wb') as handle:
                writer.write(handle)
            result = solve_target(path)
            self.assertIn('CTF{pdf_metadata}', [f['value'] for f in result['findings']])
            self.assertTrue(any(a['kind'] == 'pdf' for a in result['artifacts']))

    def test_elf_header_triage_on_inert_minimal_fixture(self):
        from core.artifact_triage import inspect_artifact
        data = b'\x7fELF\x02\x01\x01' + b'\0' * 9
        data += struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x401000, 0, 0, 0, 64, 0, 0, 0, 0, 0)
        report = inspect_artifact(data)
        self.assertEqual(report['details']['bits'], 64)
        self.assertEqual(report['details']['entry'], '0x401000')
        self.assertIsNone(report['details']['nx_stack'])

    def test_nested_archive_runs_decode_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory, 'misnamed.jpg')
            with zipfile.ZipFile(p, 'w') as z:
                z.writestr('payload.txt', base64.b64encode(b'MyCTF{nested}'))
            result = solve_target(p, prefix='MyCTF')
            self.assertIn('MyCTF{nested}', [f['value'] for f in result['findings']])
            self.assertEqual(result['artifacts'][0]['kind'], 'zip/office')

    def test_unknown_prefix_is_candidate_unless_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'flag.txt')
            path.write_text('NovelEvent{exact_bytes}')
            result = solve_target(path)
            self.assertFalse(any(f['kind'] == 'verified' for f in result['findings']))
            self.assertTrue(any(f['kind'] == 'candidate' for f in result['findings']))
            result = solve_target(path, prefix='NovelEvent')
            self.assertTrue(any(f['kind'] == 'verified' for f in result['findings']))

    def test_archive_header_concatenation_cannot_inflate_verified_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'archive.zip')
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('clue.txt', 'CTF{archive}')
            result = solve_target(path)
            verified = [f['value'] for f in result['findings'] if f['kind'] == 'verified']
            self.assertEqual(verified, ['CTF{archive}'])

    def test_batch_resume_and_content_invalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs, output = root / 'input', root / 'output'
            inputs.mkdir()
            (inputs / 'one.txt').write_text('CTF{one}')
            (inputs / 'two.txt').write_text('CTF{two}')
            one = run_batch(inputs, output=output, seconds=10)
            self.assertTrue(all(j['status'] == 'completed' for j in one['jobs']))
            two = run_batch(inputs, output=output, resume=True, seconds=10)
            self.assertTrue(all(j['resumed'] for j in two['jobs']))
            (inputs / 'two.txt').write_text('CTF{new}')
            three = run_batch(inputs, output=output, resume=True, seconds=10)
            self.assertEqual([j['resumed'] for j in three['jobs']], [True, False])
            self.assertIn('CTF{new}', [f['value'] for f in three['jobs'][1]['findings']])
            self.assertTrue((output / 'results.md').is_file())

    def test_deadline_kills_process_group(self):
        real_popen = subprocess.Popen
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'must-not-exist'
            child = f"import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).touch()"
            code = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(5)"

            def spawn(*args, **kwargs):
                return real_popen([sys.executable, '-c', code], **kwargs)

            start = time.monotonic()
            with patch('core.competition.subprocess.Popen', side_effect=spawn):
                result = run_isolated('unused', {}, 0.4)
            self.assertEqual(result['status'], 'timeout')
            self.assertLess(time.monotonic() - start, 2)
            time.sleep(1.1)
            self.assertFalse(marker.exists())

    def test_output_cannot_contaminate_input(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                run_batch(directory, output=Path(directory) / 'results')


class FastLaneTests(unittest.TestCase):
    def test_24_base64_layers_recover_only_the_exact_flag(self):
        from modules.crypto.fastlane import decode_fast
        value = b'CTF{layers}'
        for _ in range(24):
            value = base64.b64encode(value)
        result = decode_fast(value)
        self.assertEqual(result[0][1], 'CTF{layers}')
        self.assertEqual(len(result[0][0].split('>')), 24)

    def test_nine_layers_preserve_binary_compression(self):
        from modules.crypto.fastlane import decode_fast
        value = b'CTF{mixed}'
        for _ in range(3):
            value = base64.b64encode(gzip.compress(value)).hex().encode()
        result = decode_fast(value)
        self.assertEqual(result[0][1], 'CTF{mixed}')
        self.assertEqual(len(result[0][0].split('>')), 9)

    def test_fastlane_obeys_depth_and_expansion_limits(self):
        from modules.crypto.fastlane import decode_fast
        self.assertFalse(decode_fast(base64.b64encode(base64.b64encode(b'CTF{x}')), max_depth=1))
        self.assertFalse(decode_fast(gzip.compress(b'A' * 1000000), max_bytes=4096))

    def test_heuristic_transform_does_not_promote_verified(self):
        import codecs
        from modules.crypto.autodetect import analyze_text_evidence
        _, findings = analyze_text_evidence(codecs.encode(base64.b64encode(b'CTF{rotated}').decode(), 'rot13'))
        self.assertTrue(any(f.value == 'CTF{rotated}' for f in findings))
        self.assertFalse(any(f.kind == 'verified' for f in findings))


class WebCompetitionTests(unittest.TestCase):
    def test_live_flag_stops_before_expensive_recon(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from modules.web.scanner import run_web
        from core import httpx
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                value = b'CTF{local_web_fixture}'
                self.send_response(200); self.send_header('Content-Length', str(len(value))); self.end_headers(); self.wfile.write(value)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        updates = []
        try:
            with patch('modules.web.recon.run_recon', side_effect=AssertionError('unnecessary recon')):
                flags = run_web('http://127.0.0.1:' + str(server.server_port), stop_on_flag=True, on_progress=updates.append)
            self.assertEqual(flags, ['CTF{local_web_fixture}'])
            self.assertEqual(updates[0], flags)
        finally:
            httpx.close_pool(); server.shutdown(); server.server_close()

    def test_web_budget_options_reach_scanner(self):
        import web_app
        jid = web_app._new_job()
        with patch('modules.web.scanner.run_web', return_value=[]) as scan:
            web_app._run_web(jid, 'http://localhost:1', deep=False, stop_on_flag=True)
        self.assertFalse(scan.call_args.kwargs['deep'])
        self.assertTrue(scan.call_args.kwargs['stop_on_flag'])
        self.assertEqual(web_app._jobs[jid]['status'], 'done')


if __name__ == '__main__':
    unittest.main()
