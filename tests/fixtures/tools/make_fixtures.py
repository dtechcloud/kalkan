# SPDX-License-Identifier: MIT
"""Create the archive fixtures for the kalkan.tools tests.

Run from the repository root: ``python tests/fixtures/tools/make_fixtures.py``.
The output is deterministic (fixed timestamps), so a rerun writes the same files.

Files:

- ``faketool-1.2.3.zip``: good zip, binary at ``faketool-1.2.3/faketool``.
- ``faketool-1.2.3.tar.gz``: good tar.gz, binary at ``faketool``.
- ``faketool-raw.bin``: a raw binary (manifest ``archive: none``).
- ``traversal.zip``, ``traversal.tar.gz``: an extra member with ``..`` in its path.
- ``absolute.tar.gz``: an extra member with an absolute path.
- ``symlink.zip``, ``symlink.tar.gz``: the binary member is a symbolic link.
- ``hardlink.tar.gz``: an extra hard link member.
- ``device.tar.gz``: an extra character device member.
- ``duplicate.zip``: two members with the binary name.
"""

from __future__ import annotations

import gzip
import io
import stat
import tarfile
import warnings
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAKE_BINARY = b"\x7fELF-kalkan-test-binary\x00faketool 1.2.3\n"
README = b"faketool test fixture\n"
DATE = (2026, 1, 1, 0, 0, 0)
MTIME = 1767225600  # 2026-01-01T00:00:00Z


def _zip(name: str, members: list[tuple[str, bytes, int]]) -> None:
    """Write a zip. Each member is (name, data, unix mode with file type bits)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # duplicate.zip repeats a name on purpose
        with zipfile.ZipFile(HERE / name, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for member, data, mode in members:
                info = zipfile.ZipInfo(member, date_time=DATE)
                info.create_system = 3  # Unix, so external_attr carries the mode
                info.external_attr = (mode & 0xFFFF) << 16
                if stat.S_ISDIR(mode):
                    info.external_attr |= 0x10
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, data)


def _tar_gz(name: str, members: list[tarfile.TarInfo | tuple[str, bytes, int]]) -> None:
    """Write a tar.gz with a fixed gzip header. Plain tuples become regular files."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for member in members:
            if isinstance(member, tarfile.TarInfo):
                member.mtime = MTIME
                tf.addfile(member)
                continue
            path, data, mode = member
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = mode
            info.mtime = MTIME
            tf.addfile(info, io.BytesIO(data))
    with open(HERE / name, "wb") as out:
        with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
            gz.write(raw.getvalue())


def _special(path: str, kind: bytes, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.type = kind
    info.linkname = linkname
    info.mode = 0o644
    if kind == tarfile.CHRTYPE:
        info.devmajor, info.devminor = 1, 3
    return info


def main() -> None:
    exe = stat.S_IFREG | 0o755
    doc = stat.S_IFREG | 0o644
    _zip(
        "faketool-1.2.3.zip",
        [
            ("faketool-1.2.3/", b"", stat.S_IFDIR | 0o755),
            ("faketool-1.2.3/faketool", FAKE_BINARY, exe),
            ("faketool-1.2.3/LICENSE", README, doc),
        ],
    )
    _tar_gz(
        "faketool-1.2.3.tar.gz", [("faketool", FAKE_BINARY, 0o755), ("README.md", README, 0o644)]
    )
    (HERE / "faketool-raw.bin").write_bytes(FAKE_BINARY)
    _zip("traversal.zip", [("faketool", FAKE_BINARY, exe), ("../evil.txt", README, doc)])
    _tar_gz(
        "traversal.tar.gz", [("faketool", FAKE_BINARY, 0o755), ("../../evil.txt", README, 0o644)]
    )
    _tar_gz("absolute.tar.gz", [("faketool", FAKE_BINARY, 0o755), ("/tmp/evil.txt", README, 0o644)])
    _zip("symlink.zip", [("faketool", b"/etc/passwd", stat.S_IFLNK | 0o777)])
    _tar_gz("symlink.tar.gz", [_special("faketool", tarfile.SYMTYPE, "/etc/passwd")])
    _tar_gz(
        "hardlink.tar.gz",
        [("faketool", FAKE_BINARY, 0o755), _special("other", tarfile.LNKTYPE, "faketool")],
    )
    _tar_gz(
        "device.tar.gz",
        [("faketool", FAKE_BINARY, 0o755), _special("null", tarfile.CHRTYPE)],
    )
    _zip("duplicate.zip", [("faketool", FAKE_BINARY, exe), ("faketool", README, exe)])


if __name__ == "__main__":
    main()
