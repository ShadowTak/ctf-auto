"""Regression tests for image metadata, carving indicators, and findings."""
import os
import struct
import tempfile
import unittest
import zlib
import zipfile

from modules.image.forensics import analyze_image
from modules.image.pixel_stego import extract_pixel_planes


def _png_chunk(kind, payload):
    raw_kind = kind.encode("ascii")
    body = raw_kind + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)


def _make_png():
    # 1x1 RGBA PNG with a directly embedded flag and an appended ZIP marker.
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    raw = zlib.compress(b"\x00\x01\x02\x03\x04")
    data = (b"\x89PNG\r\n\x1a\n" + _png_chunk("IHDR", ihdr) +
            _png_chunk("tEXt", b"Comment\x00DUCTF{png_meta_ok}") +
            _png_chunk("IDAT", raw) + _png_chunk("IEND", b""))
    return data + b"PK\x03\x04embedded"


class ImageForensicsTests(unittest.TestCase):
    def test_png_metadata_strings_flags_and_polyglot_signature(self):
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as handle:
            handle.write(_make_png())
            path = handle.name
        try:
            report = analyze_image(path, run_tools=False)
        finally:
            os.unlink(path)
        self.assertEqual(report["format"], "PNG")
        self.assertEqual(report["metadata"][0]["key"], "width")
        self.assertIn("Comment=DUCTF{png_meta_ok}", report["text"])
        self.assertIn("DUCTF{png_meta_ok}", report["verified_flags"])
        self.assertTrue(any(item["type"] == "ZIP" and item["offset"] > 0
                            for item in report["signatures"]))
        self.assertGreater(report["trailing_bytes"], 0)
        self.assertTrue(any("trailing" in item for item in report["anomalies"]))

    def test_image_report_is_json_serializable(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as handle:
            handle.write(b"not-an-image FLAG{raw_candidate} PK\x03\x04")
            path = handle.name
        try:
            report = analyze_image(path, run_tools=False)
        finally:
            os.unlink(path)
        import json
        json.dumps(report, ensure_ascii=False)
        self.assertEqual(report["format"], "unknown")
        self.assertTrue(report["strings"]["ascii"])

    def test_embedded_zip_is_inspected_in_memory(self):
        payload = b"DUCTF{embedded_zip_ok}\n"
        archive = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        archive.close()
        try:
            with zipfile.ZipFile(archive.name, "w") as zf:
                zf.writestr("secret.txt", payload)
            with open(archive.name, "rb") as handle:
                embedded = handle.read()
            image_handle = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
            image_handle.close()
            path = image_handle.name
            with open(path, "wb") as handle:
                handle.write(_make_png() + embedded)
            report = analyze_image(path, run_tools=False)
            self.assertTrue(report["embedded"])
            self.assertIn("DUCTF{embedded_zip_ok}", report["verified_flags"])
        finally:
            for target in (archive.name, locals().get("path")):
                if target and os.path.exists(target):
                    os.unlink(target)

    def test_pixel_lsb_flag_is_recovered(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow not installed")
        text = b"DUCTF{pixel_lsb_ok}"
        bits = [(byte >> shift) & 1 for byte in text for shift in range(7, -1, -1)]
        pixels = [(bit, 0, 0) for bit in bits]
        pixels += [(0, 0, 0)] * (64 * 64 - len(pixels))
        image = Image.new("RGB", (64, 64))
        image.putdata(pixels)
        handle = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        handle.close()
        try:
            image.save(handle.name)
            results, error = extract_pixel_planes(handle.name)
            self.assertIsNone(error)
            self.assertTrue(any("DUCTF{pixel_lsb_ok}" in item["output"]
                                for item in results))
        finally:
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()
