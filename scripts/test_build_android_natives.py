# SPDX-License-Identifier: MPL-2.0
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

import build_android_natives as ban


class BuildAndroidNativesTests(unittest.TestCase):
    def test_extract_hevtun_from_aar(self) -> None:
        buf = io.BytesIO()
        elf_payload = b"\x7fELF" + b"\x00" * 64
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
            zf.writestr("jni/arm64-v8a/libhev-socks5-tunnel.so", elf_payload)
            zf.writestr("jni/x86_64/libhev-socks5-tunnel.so", elf_payload + b"\x01")

        with tempfile.TemporaryDirectory() as tmp:
            dest_arm64 = Path(tmp) / "arm64" / "libhev-socks5-tunnel.so"
            ban.extract_hevtun_from_aar(buf.getvalue(), "arm64-v8a", dest_arm64)
            self.assertTrue(dest_arm64.is_file())
            self.assertEqual(dest_arm64.read_bytes(), elf_payload)

            dest_x64 = Path(tmp) / "x64" / "libhev-socks5-tunnel.so"
            ban.extract_hevtun_from_aar(buf.getvalue(), "x86_64", dest_x64)
            self.assertEqual(dest_x64.read_bytes(), elf_payload + b"\x01")

    def test_extract_hevtun_rejects_missing_abi(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("jni/armeabi-v7a/libhev-socks5-tunnel.so", b"\x7fELF" + b"\x00" * 16)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                ban.extract_hevtun_from_aar(buf.getvalue(), "arm64-v8a", Path(tmp) / "out.so")


if __name__ == "__main__":
    unittest.main()
