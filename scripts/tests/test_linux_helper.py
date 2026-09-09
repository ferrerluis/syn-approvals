import importlib.util
import json
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "linux_helper", Path(__file__).resolve().parents[1] / "verify-linux-helper.py"
)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)

HEADER = "  Class: ELF64\n  Machine: AArch64\n"
PROGRAM = "      [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]\n"
DYNAMIC = " 0x1 (NEEDED) Shared library: [libc.so.6]\n 0x1 (NEEDED) Shared library: [libgcc_s.so.1]\n"


class LinuxHelperTests(unittest.TestCase):
    def test_bootstrap_loader_inventory(self):
        self.assertEqual(helper.verify_elf(HEADER, PROGRAM, DYNAMIC), {"libc.so.6", "libgcc_s.so.1"})
        for header, program, dynamic in [
            (HEADER.replace("AArch64", "X86-64"), PROGRAM, DYNAMIC),
            (HEADER.replace("ELF64", "ELF32"), PROGRAM, DYNAMIC),
            (HEADER, "", DYNAMIC),
            (HEADER, PROGRAM.replace("/lib/", "/tmp/"), DYNAMIC),
            (HEADER, PROGRAM, ""),
            (HEADER, PROGRAM, DYNAMIC + DYNAMIC),
            (HEADER, PROGRAM, DYNAMIC + "0x1 (NEEDED) Shared library: [libpam.so.0]\n"),
            (HEADER, PROGRAM, DYNAMIC + "0x1 (RUNPATH) Library runpath: [/tmp]\n"),
        ]:
            with self.assertRaises(helper.HelperError):
                helper.verify_elf(header, program, dynamic)

    def test_compiled_identity_and_isolated_configuration_are_required(self):
        expected = {"release_id": "20260906160000", "commit": "a" * 40}
        report = {"schema_version": 1, "release_id": expected["release_id"],
                  "release_commit": expected["commit"], "configuration_state": "absent", "configured": False}
        encode = lambda value: json.dumps({"ok": True, "data": value}).encode()
        helper.verify_status(encode(report), expected)
        for field, wrong in [("release_id", "20260906160001"), ("release_commit", "b" * 40),
                             ("release_commit", ""), ("schema_version", 2),
                             ("configuration_state", "unreadable"), ("configured", True)]:
            with self.assertRaises(helper.HelperError):
                helper.verify_status(encode({**report, field: wrong}), expected)
        for data in [b"{}", b"not JSON", b"[]", b" " * 16_385]:
            with self.assertRaises(helper.HelperError):
                helper.verify_status(data, expected)


if __name__ == "__main__":
    unittest.main()
