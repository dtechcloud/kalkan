# SPDX-License-Identifier: MIT
"""Tests for kalkan.util.safe_io: bounded, symlink-safe reads and atomic writes.

These tests replace the upstream CLI tests that depend on O_NOFOLLOW and O_NONBLOCK (which Node
does not define on Windows): symlink, FIFO and non-regular inputs, the size limit and invalid
UTF-8 are tested on read_bounded and read_text_bounded directly.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from kalkan.errors import UnsafeInputError
from kalkan.util import safe_io
from kalkan.util.safe_io import (
    DEFAULT_MAX_BYTES,
    atomic_write_json,
    atomic_write_text,
    dumps_json,
    read_bounded,
    read_text_bounded,
)

IS_WINDOWS = os.name == "nt"
CONTROL_PAYLOAD = "\x1b\x07\x85\U0000202e\U0000034f\U0000fe0f"


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def make_symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a symlink here: {exc}")


def with_fields(result: os.stat_result, **changes: int) -> os.stat_result:
    names = ["st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size"]
    fields = list(result[:10])
    for name, value in changes.items():
        fields[names.index(name)] = value
    return os.stat_result(fields)


def test_reads_a_regular_file(tmp_path):
    path = write(tmp_path / "findings.json", b"[1, 2]")
    assert read_bounded(path) == b"[1, 2]"
    assert read_bounded(str(path)) == b"[1, 2]"
    assert read_text_bounded(path) == "[1, 2]"
    empty = write(tmp_path / "empty.json", b"")
    assert read_bounded(empty, max_bytes=0) == b""


def test_default_limit_is_five_mebibytes():
    assert DEFAULT_MAX_BYTES == 5 * 1024 * 1024


def test_enforces_the_size_limit_before_reading(tmp_path):
    path = write(tmp_path / "big.json", b" " * 11)
    assert read_bounded(path, max_bytes=11) == b" " * 11
    with pytest.raises(UnsafeInputError, match="^input exceeds 10 byte limit$"):
        read_bounded(path, max_bytes=10)


def test_enforces_the_size_limit_during_the_read(tmp_path, monkeypatch):
    # The file grows after both size checks: the chunked read still stops at the limit.
    path = write(tmp_path / "grows.json", b"x" * 200_000)
    real_lstat, real_fstat = os.lstat, os.fstat
    monkeypatch.setattr(os, "lstat", lambda target: with_fields(real_lstat(target), st_size=0))
    monkeypatch.setattr(os, "fstat", lambda fd: with_fields(real_fstat(fd), st_size=0))
    with pytest.raises(UnsafeInputError, match="^input exceeds 100000 byte limit$"):
        read_bounded(path, max_bytes=100_000)


def test_rejects_a_file_replaced_after_lstat(tmp_path, monkeypatch):
    path = write(tmp_path / "swapped.json", b"[]")
    real_fstat = os.fstat
    monkeypatch.setattr(
        os, "fstat", lambda fd: with_fields(real_fstat(fd), st_ino=real_fstat(fd).st_ino + 1)
    )
    with pytest.raises(UnsafeInputError, match="^input changed while it was being opened$"):
        read_bounded(path)


def test_rejects_a_directory(tmp_path):
    with pytest.raises(UnsafeInputError, match="^input must be a regular file$"):
        read_bounded(tmp_path)


def test_rejects_a_device():
    device = "NUL" if IS_WINDOWS else os.devnull
    with pytest.raises(UnsafeInputError, match="^input must be a regular file$"):
        read_bounded(device)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this platform has no FIFOs")
def test_rejects_a_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "findings.json"
    os.mkfifo(fifo)
    with pytest.raises(UnsafeInputError, match="^input must be a regular file$"):
        read_bounded(fifo)


def test_rejects_a_symlink_without_following_it(tmp_path):
    target = write(tmp_path / "target.json", b"[]")
    link = tmp_path / "findings.json"
    make_symlink(target, link)
    with pytest.raises(UnsafeInputError, match="^input must not be a symlink$"):
        read_bounded(link)


@pytest.mark.skipif(not IS_WINDOWS, reason="junctions exist only on Windows")
def test_rejects_a_windows_junction(tmp_path):
    winapi = pytest.importorskip("_winapi")
    target = tmp_path / "directory"
    target.mkdir()
    junction = tmp_path / "junction"
    try:
        winapi.CreateJunction(str(target), str(junction))
    except OSError as exc:
        pytest.skip(f"cannot create a junction here: {exc}")
    with pytest.raises(UnsafeInputError, match="reparse point"):
        read_bounded(junction)


def test_failure_messages_never_contain_the_path(tmp_path):
    missing = tmp_path / f"missing-{CONTROL_PAYLOAD}.json"
    with pytest.raises(UnsafeInputError) as info:
        read_bounded(missing)
    assert str(info.value) == "input could not be opened or read safely"
    assert isinstance(info.value.__cause__, OSError | ValueError)
    with pytest.raises(UnsafeInputError, match="^input could not be opened or read safely$"):
        read_bounded(tmp_path / "missing.json")


def test_rejects_invalid_arguments(tmp_path):
    path = write(tmp_path / "findings.json", b"[]")
    for limit in (-1, 1.5, True):
        with pytest.raises(ValueError):
            read_bounded(path, limit)
    with pytest.raises(TypeError):
        read_bounded(os.fsencode(path))


@pytest.mark.parametrize(
    "data",
    [b"\x80", b"\xc0\xaf", b"\xed\xa0\x80", b"ok\xff", b"\xe2\x82"],
    ids=["continuation", "overlong", "encoded-surrogate", "invalid-byte", "truncated"],
)
def test_read_text_bounded_is_strict_utf8(tmp_path, data):
    path = write(tmp_path / "findings.json", data)
    with pytest.raises(UnsafeInputError, match="^input is not valid UTF-8$"):
        read_text_bounded(path)


def test_read_text_bounded_keeps_a_byte_order_mark(tmp_path):
    # Like TextDecoder("utf-8", {fatal: true, ignoreBOM: true}): the BOM stays in the text.
    path = write(tmp_path / "bom.json", b"\xef\xbb\xbf[]")
    assert read_text_bounded(path) == "\U0000feff[]"


def test_read_text_bounded_applies_the_limit_to_bytes(tmp_path):
    path = write(tmp_path / "wide.json", "\U0000015f".encode() * 3)  # 6 bytes, 3 characters
    with pytest.raises(UnsafeInputError, match="^input exceeds 5 byte limit$"):
        read_text_bounded(path, max_bytes=5)


def test_atomic_write_text_writes_utf8_with_lf(tmp_path):
    target = tmp_path / "REPORT.md"
    atomic_write_text(target, "sat\U00000131r 1\nline 2\n")
    assert target.read_bytes() == "sat\U00000131r 1\nline 2\n".encode()
    atomic_write_text(target, "replaced\n")
    assert target.read_bytes() == b"replaced\n"
    assert [entry.name for entry in tmp_path.iterdir()] == ["REPORT.md"]


def test_atomic_write_text_needs_an_existing_parent(tmp_path):
    with pytest.raises(FileNotFoundError):
        atomic_write_text(tmp_path / "missing" / "state.json", "{}")
    assert list(tmp_path.iterdir()) == []


def test_atomic_write_text_cleans_up_after_a_failed_replace(tmp_path, monkeypatch):
    target = write(tmp_path / "state.json", b"old")

    def fail(source, destination):
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="replace failed"):
        atomic_write_text(target, "new")
    assert target.read_bytes() == b"old"
    assert [entry.name for entry in tmp_path.iterdir()] == ["state.json"]


def test_atomic_write_retries_permission_errors_on_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_io, "_IS_WINDOWS", True)
    monkeypatch.setattr(safe_io.time, "sleep", lambda seconds: None)
    real_replace = os.replace
    calls: list[str] = []

    def busy_twice(source, destination):
        calls.append(source)
        if len(calls) < 3:
            raise PermissionError("the target is in use")
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", busy_twice)
    target = tmp_path / "state.json"
    atomic_write_text(target, "ok\n")
    assert len(calls) == 3
    assert target.read_bytes() == b"ok\n"


def test_atomic_write_gives_up_after_the_last_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_io, "_IS_WINDOWS", True)
    monkeypatch.setattr(safe_io.time, "sleep", lambda seconds: None)
    calls: list[str] = []

    def always_busy(source, destination):
        calls.append(source)
        raise PermissionError("the target is in use")

    monkeypatch.setattr(os, "replace", always_busy)
    with pytest.raises(PermissionError):
        atomic_write_text(tmp_path / "state.json", "ok\n")
    assert len(calls) == safe_io._REPLACE_ATTEMPTS
    assert list(tmp_path.iterdir()) == []


def test_atomic_write_does_not_retry_off_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_io, "_IS_WINDOWS", False)
    calls: list[str] = []

    def busy(source, destination):
        calls.append(source)
        raise PermissionError("the target is in use")

    monkeypatch.setattr(os, "replace", busy)
    with pytest.raises(PermissionError):
        atomic_write_text(tmp_path / "state.json", "ok\n")
    assert len(calls) == 1


@pytest.mark.skipif(IS_WINDOWS, reason="POSIX permission bits")
def test_atomic_write_keeps_the_permission_bits(tmp_path):
    target = write(tmp_path / "keep.txt", b"x")
    os.chmod(target, 0o640)
    atomic_write_text(target, "y")
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o640


def test_dumps_json_uses_the_engine_format():
    obj = {"b": [1, 2], "a": "caf\U000000e9", "n": None, "nested": {"k": True}}
    assert dumps_json(obj) == json.dumps(obj, ensure_ascii=False, indent=2) + "\n"


def test_dumps_json_escapes_lone_surrogates_and_rejects_non_finite_numbers():
    text = dumps_json({"payload": "\U0000d800x"})
    assert '"\\ud800x"' in text
    assert json.loads(text) == {"payload": "\U0000d800x"}
    for value in (float("nan"), float("inf")):
        with pytest.raises(ValueError):
            dumps_json({"value": value})


def test_atomic_write_json_round_trips(tmp_path):
    target = tmp_path / "findings.json"
    doc = [{"title": "Sahiplik kontrol\U000000fc eksik", "payload": "\U0000dc00"}]
    atomic_write_json(target, doc)
    data = target.read_bytes()
    assert data.endswith(b"\n")
    assert b"\r\n" not in data
    assert json.loads(read_text_bounded(target)) == doc


def test_atomic_write_json_keeps_the_target_on_invalid_data(tmp_path):
    target = tmp_path / "state.json"
    atomic_write_json(target, {"ok": 1})
    with pytest.raises(ValueError):
        atomic_write_json(target, {"bad": float("inf")})
    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": 1}
    assert [entry.name for entry in tmp_path.iterdir()] == ["state.json"]
