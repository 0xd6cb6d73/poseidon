#!/usr/bin/env python3
"""Verify and stage a complete Beaconcrypt Go/WASM release outside GOMODCACHE."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request

MODULE = "github.com/0xd6cb6d73/beaconcrypt"
MANIFEST = "beaconcrypt-wasm-manifest.json"
WASM = "internal/wasm/beaconcrypt.wasm"
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
CHECKSUM = re.compile(r"[0-9a-fA-F]{64}\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative_path(value):
    if not isinstance(value, str) or "\\" in value:
        raise ValueError("invalid bundle path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {".", ".."} for part in value.split("/")):
        raise ValueError(f"unsafe bundle path: {value}")
    return path


def release_pin(path, version):
    matches = []
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3 or not SAFE_COMPONENT.fullmatch(fields[1]) or not CHECKSUM.fullmatch(fields[2]):
            raise ValueError("invalid Beaconcrypt WASM release pin")
        if fields[0] == version:
            matches.append((fields[1], fields[2].lower()))
    if len(matches) != 1:
        raise ValueError(f"no unique published WASM bundle pin for {version}; supply a local bundle and explicit SHA256")
    return matches[0]


def verified_files(archive, version, allow_dirty):
    root = f"beaconcrypt-go-{version}"
    files = {}
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            path = relative_path(member.name)
            if path.parts[0] != root:
                raise ValueError("bundle has an unexpected top-level directory")
            if member.isdir():
                continue
            if not member.isfile() or len(path.parts) < 2:
                raise ValueError("bundle links and special files are forbidden")
            name = str(PurePosixPath(*path.parts[1:]))
            if name in files or member.size > 64 * 1024 * 1024:
                raise ValueError("duplicate or oversized bundle file")
            files[name] = tar.extractfile(member).read()
    manifest = json.loads(files[MANIFEST])
    if manifest.get("schema_version") != 1 or manifest.get("wasm_abi_version") != 1:
        raise ValueError("unsupported Beaconcrypt bundle schema or WASM ABI")
    if manifest.get("module") != MODULE or manifest.get("version") != version:
        raise ValueError("Beaconcrypt bundle module/version does not match the selected dependency")
    if not allow_dirty and manifest.get("source_dirty") is not False:
        raise ValueError("published bundles must not contain a dirty source build")
    hashes = manifest.get("files_sha256")
    if not isinstance(hashes, dict) or set(hashes) != set(files) - {MANIFEST}:
        raise ValueError("bundle file list differs from its manifest")
    for name, checksum in hashes.items():
        relative_path(name)
        if not isinstance(checksum, str) or not CHECKSUM.fullmatch(checksum) or digest(files[name]) != checksum.lower():
            raise ValueError(f"bundle file checksum mismatch: {name}")
    wasm = manifest.get("wasm", {})
    if wasm.get("path") != WASM or WASM not in files:
        raise ValueError("bundle is missing its embedded WASM module")
    if files[WASM][:8] != b"\0asm\x01\0\0\0" or digest(files[WASM]) != wasm.get("sha256") or len(files[WASM]) != wasm.get("bytes"):
        raise ValueError("embedded WASM differs from its manifest")
    if f"module {MODULE}" not in files["go.mod"].decode().splitlines():
        raise ValueError("bundle go.mod has a different module path")
    return root, files


def matching_tree(directory, files):
    if not directory.is_dir() or directory.is_symlink():
        return False
    actual = {}
    for path in directory.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            return False
        if path.is_file():
            actual[str(path.relative_to(directory))] = digest(path.read_bytes())
    return actual == {name: digest(data) for name, data in files.items()}


def stage(args):
    if not SAFE_COMPONENT.fullmatch(args.version):
        raise ValueError("invalid module version")
    if args.bundle:
        if not CHECKSUM.fullmatch(args.sha256 or ""):
            raise ValueError("a local WASM bundle requires its explicit SHA256")
        checksum, asset = args.sha256.lower(), None
        local_data = args.bundle.read_bytes()
        if digest(local_data) != checksum:
            raise ValueError("Beaconcrypt WASM archive SHA256 mismatch")
    else:
        asset, checksum = release_pin(args.manifest, args.version)
    cache = args.cache_dir.resolve() / args.version / checksum
    cache.mkdir(parents=True, exist_ok=True)
    with (cache / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        archive = cache / "bundle.tar.gz"
        if not archive.is_file() or digest(archive.read_bytes()) != checksum:
            if args.bundle:
                data = local_data
            else:
                url = f"https://github.com/0xd6cb6d73/beaconcrypt/releases/download/{args.version}/{asset}"
                with urllib.request.urlopen(url, timeout=120) as response:
                    if not response.geturl().startswith("https://"):
                        raise ValueError("WASM release download redirected away from HTTPS")
                    data = response.read(64 * 1024 * 1024 + 1)
                if len(data) > 64 * 1024 * 1024:
                    raise ValueError("WASM release archive is oversized")
            if digest(data) != checksum:
                raise ValueError("Beaconcrypt WASM archive SHA256 mismatch")
            with tempfile.NamedTemporaryFile(dir=cache, prefix=".bundle-", delete=False) as download:
                temporary = Path(download.name)
                try:
                    download.write(data)
                    download.close()
                    temporary.replace(archive)
                finally:
                    temporary.unlink(missing_ok=True)
        root, files = verified_files(archive, args.version, allow_dirty=bool(args.bundle))
        module = cache / root
        if not matching_tree(module, files):
            temporary = Path(tempfile.mkdtemp(dir=cache, prefix=".module-"))
            try:
                for name, data in files.items():
                    path = temporary / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                if module.is_symlink():
                    module.unlink()
                elif module.exists():
                    shutil.rmtree(module)
                temporary.rename(module)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        return {"module_directory": str(module), "version": args.version, "sha256": checksum}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("beaconcrypt-wasm-releases.txt"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--sha256")
    args = parser.parse_args()
    try:
        result = stage(args)
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        print(f"Cannot stage Beaconcrypt WASM: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
