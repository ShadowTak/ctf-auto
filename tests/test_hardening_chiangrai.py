"""Regressions from the Cyber Hero Chiang Rai (นครเชียงราย) artifact set.

Every case here is drawn from a real competition file: decoys planted next to
flags, a message smuggled through the IPv4 ID field, and a binary that builds
its flag on the stack one byte at a time.
"""
import shutil
import tempfile
import unittest

from core import flag as flaglib
from modules.image import forensics as image_forensics
from modules.network import pcap
from modules.reverse.stack_strings import recover_stack_strings
from modules.reverse.strings import extract_flag_like_strings, extract_strings


class DecoySuppressionTests(unittest.TestCase):
    def test_inline_decoy_markers_are_dropped(self):
        text = ("Plant vendor: CYBERHEROCTF{dhcp_vendor_class_decoy} "
                "<<DECOY - NOT THE REAL FLAG, DO NOT SUBMIT>>")
        known, candidates = flaglib.extract_flags(text)
        self.assertEqual(known, [])
        self.assertEqual(candidates, [])

    def test_decoy_body_name_is_enough(self):
        text = "note: CYBERHEROCTF{wrong_plc_unit2_decoy_flag}"
        known, candidates = flaglib.extract_flags(text)
        self.assertNotIn("CYBERHEROCTF{wrong_plc_unit2_decoy_flag}", known + candidates)

    def test_real_flag_survives_nearby_decoy(self):
        text = ("draft: CYBERHEROCTF{decoy_one} <<DECOY>>\n"
                "answer: CYBERHEROCTF{L0G1C_4N4LYZ3R_C4PTUR3}\n")
        known, _ = flaglib.extract_flags(text)
        self.assertIn("CYBERHEROCTF{L0G1C_4N4LYZ3R_C4PTUR3}", known)
        self.assertNotIn("CYBERHEROCTF{decoy_one}", known)

    def test_noise_shapes_are_rejected(self):
        for junk in ("CJ{oint}", "TCT{cOcc}", "z222022222{j22}", "uny{dlL}",
                     "Metaspolit{metaspolitmetaspolitmetaspolit}"):
            self.assertTrue(flaglib.looks_like_noise_flag(junk), junk)

    def test_domain_bodied_flag_is_an_ioc_not_an_answer(self):
        # The Blynk APK hides this in a deep-link host; the real answer needs
        # an OSINT look-up of the domain, so it must not be reported as a flag.
        self.assertTrue(flaglib.looks_like_ioc_flag(
            "CYBERHEROCTF{drp32k77.todoinfonet.com}"))
        self.assertFalse(flaglib.looks_like_ioc_flag(
            "CYBERHEROCTF{MkaeX345fsimple}"))
        self.assertFalse(flaglib.looks_like_ioc_flag(
            "CYBERHEROCTF{423945235349405354242495485040}"))

    def test_real_flag_shapes_survive_noise_filter(self):
        # Structureless short bodies are treated as noise on purpose; real
        # flags carry digits, underscores or length.
        for value in ("CYBERHEROCTF{423945235349405354242495485040}",
                      "CYBERHEROCTF{pl3ase_Find_me_r3verSe}",
                      "picoCTF{sh0rt}", "HTB{abc_12}"):
            self.assertFalse(flaglib.looks_like_noise_flag(value), value)


def _packet(ip_id):
    pkt = pcap.Packet()
    pkt.ip_id = ip_id
    return pkt


class HeaderCovertChannelTests(unittest.TestCase):
    def test_ip_id_index_channel_is_recovered(self):
        message = "CYBERHEROCTF{dns_channel_is_a_decoy} <<DECOY>>"
        packets = [_packet(1) for _ in range(6)]  # ordinary traffic
        for index, char in enumerate(message.encode()):
            packets.append(_packet((index << 8) | char))
            packets.append(_packet((index << 8) | 0x7F))  # filler noise
        channels = pcap.detect_header_covert_channels(packets)
        self.assertTrue(channels, "channel not detected")
        self.assertIn("dns_channel_is_a_decoy", channels[0]["message"])
        self.assertTrue(channels[0]["is_decoy"])

    def test_constant_ids_are_not_a_channel(self):
        packets = [_packet(1) for _ in range(40)]
        self.assertEqual(pcap.detect_header_covert_channels(packets), [])


class ExtractedStringTests(unittest.TestCase):
    def test_utf16_text_is_found(self):
        # Compiled Android manifests store text as UTF-16; plain scanning misses it.
        blob = b"\x00\x01\x02" + "CYBERHEROCTF{drp32k77.todoinfonet.com}".encode("utf-16-le")
        self.assertIn("CYBERHEROCTF{drp32k77.todoinfonet.com}", extract_strings(blob))

    def test_flag_like_prefilter(self):
        blob = (b"ordinary text here\x00" +
                "AegisCTF{plane}".encode("utf-16-le") + b"\x00more")
        values = extract_flag_like_strings(blob)
        self.assertTrue(any("AegisCTF{plane}" in v for v in values))
        self.assertFalse(any(v == "ordinary text here" for v in values))


class StegoToolTests(unittest.TestCase):
    def test_stegseek_wordlist_carries_harvested_hints(self):
        # steghide is gone from Homebrew, so the stegseek path must exist and
        # hand the harvested passphrases (plus defaults) to the cracker.
        workdir = tempfile.mkdtemp(prefix="ctf-test-")
        try:
            name, args, _ = image_forensics._stegseek_command(
                "cover.jpg", ["ORAORAORA"], workdir)
            self.assertEqual(name, "stegseek")
            self.assertEqual(args[0], "cover.jpg")
            with open(args[1], encoding="utf-8") as handle:
                lines = handle.read().splitlines()
            self.assertIn("ORAORAORA", lines)
            self.assertIn("password", lines)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


class StackStringTests(unittest.TestCase):
    def test_bytes_written_to_the_stack_are_recovered(self):
        # mov byte ptr [rbp-0x30], imm8 == C6 45 D0 imm
        blob = b"".join(b"\xc6\x45" + bytes([0xD0 + i]) + bytes([c])
                        for i, c in enumerate(b"CYBERHEROCTF{pl3ase_Find_me_r3verSe}"))
        self.assertIn("CYBERHEROCTF{pl3ase_Find_me_r3verSe}",
                      recover_stack_strings(blob))

    def test_random_bytes_do_not_hide_a_flag(self):
        self.assertEqual(recover_stack_strings(b"\x00\x01\x02" * 40), [])


if __name__ == "__main__":
    unittest.main()
