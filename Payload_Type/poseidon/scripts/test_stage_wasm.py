import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("stage_wasm", Path(__file__).with_name("stage-wasm.py"))
stage_wasm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_wasm)


class StageWasmTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def bundle(self, change=None, special=None):
        wasm = b"\0asm\x01\0\0\0"
        files = {
            "go.mod": b"module github.com/0xd6cb6d73/beaconcrypt\n\ngo 1.25.0\n",
            "go.sum": b"",
            "api.go": b"package beaconcrypt\n",
            stage_wasm.WASM: wasm,
        }
        manifest = {
            "schema_version": 1,
            "wasm_abi_version": 1,
            "module": stage_wasm.MODULE,
            "version": "v0.6.0",
            "source_dirty": True,
            "wasm": {"path": stage_wasm.WASM, "sha256": stage_wasm.digest(wasm), "bytes": len(wasm)},
            "files_sha256": {name: stage_wasm.digest(data) for name, data in files.items()},
        }
        if change:
            change(manifest, files)
        files[stage_wasm.MANIFEST] = json.dumps(manifest).encode()
        archive = self.root / "bundle.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, data in files.items():
                member = tarfile.TarInfo("beaconcrypt-go-v0.6.0/" + name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            if special:
                tar.addfile(special)
        return argparse.Namespace(
            version="v0.6.0", cache_dir=self.root / "cache", manifest=self.root / "pins.txt",
            bundle=archive, sha256=stage_wasm.digest(archive.read_bytes()),
        )

    def test_local_bundle_and_damaged_cache(self):
        args = self.bundle()
        result = stage_wasm.stage(args)
        directory = Path(result["module_directory"])
        self.assertEqual((directory / "api.go").read_bytes(), b"package beaconcrypt\n")
        (directory / "api.go").write_text("damaged cache")
        (directory / "unexpected.go").write_text("unlisted source")
        stage_wasm.stage(args)
        self.assertEqual((directory / "api.go").read_bytes(), b"package beaconcrypt\n")
        self.assertFalse((directory / "unexpected.go").exists())

    def test_local_checksum_required_and_verified(self):
        args = self.bundle()
        for checksum in (None, "", "0" * 64):
            with self.subTest(checksum=checksum):
                args.sha256 = checksum
                with self.assertRaises(ValueError):
                    stage_wasm.stage(args)

    def test_explicit_bad_bundle_does_not_use_cache(self):
        args = self.bundle()
        stage_wasm.stage(args)
        args.bundle.write_bytes(b"invalid replacement")
        with self.assertRaises(ValueError):
            stage_wasm.stage(args)
        args.bundle.unlink()
        with self.assertRaises(FileNotFoundError):
            stage_wasm.stage(args)

    def test_manifest_mismatch_is_rejected(self):
        changes = {
            "module": lambda manifest, files: manifest.update(module="other/module"),
            "version": lambda manifest, files: manifest.update(version="v9.9.9"),
            "schema": lambda manifest, files: manifest.update(schema_version=2),
            "ABI": lambda manifest, files: manifest.update(wasm_abi_version=2),
            "file checksum": lambda manifest, files: files.update({"api.go": b"modified source"}),
            "extra source": lambda manifest, files: files.update({"extra.go": b"package beaconcrypt"}),
            "WASM checksum": lambda manifest, files: manifest["wasm"].update(sha256="0" * 64),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                args = self.bundle(change=change)
                with self.assertRaises(ValueError):
                    stage_wasm.stage(args)

    def test_traversal_and_links_are_rejected(self):
        for name, kind in [("beaconcrypt-go-v0.6.0/../../escaped", tarfile.REGTYPE),
                           ("beaconcrypt-go-v0.6.0/link", tarfile.SYMTYPE),
                           ("beaconcrypt-go-v0.6.0/hardlink", tarfile.LNKTYPE)]:
            with self.subTest(name=name):
                member = tarfile.TarInfo(name)
                member.type, member.linkname = kind, "../../escaped"
                args = self.bundle(special=member)
                with self.assertRaises(ValueError):
                    stage_wasm.stage(args)
                self.assertFalse((self.root / "escaped").exists())

    def test_pinned_download_and_offline_cache(self):
        args = self.bundle(change=lambda manifest, files: manifest.update(source_dirty=False))
        archive = args.bundle.read_bytes()
        args.manifest.write_text(f"v0.6.0 fixture.tar.gz {args.sha256}\n")
        args.bundle = None

        class Download(io.BytesIO):
            def geturl(self):
                return "https://example.invalid/fixture.tar.gz"

        with patch.object(stage_wasm.urllib.request, "urlopen", return_value=Download(archive)) as download:
            result = stage_wasm.stage(args)
            self.assertTrue(Path(result["module_directory"]).is_dir())
            self.assertEqual(download.call_count, 1)
        with patch.object(stage_wasm.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
            stage_wasm.stage(args)

    def test_no_unpublished_release_is_invented(self):
        args = self.bundle()
        args.bundle = None
        args.manifest.write_text("# No published bundles yet\n")
        with self.assertRaisesRegex(ValueError, "no unique published"):
            stage_wasm.stage(args)


if __name__ == "__main__":
    unittest.main()
