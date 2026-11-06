# SPDX-License-Identifier: MIT
"""Tests for kalkan.run.lock: exclusive lock file, contention, stale removal and liveness."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from kalkan.errors import StateError
from kalkan.run import lock
from kalkan.run.ids import format_ts


def write_lock(run_dir, *, pid, host=None, age_seconds=0.0, token="other"):
    created = datetime.now(UTC) - timedelta(seconds=age_seconds)
    content = {
        "pid": pid,
        "host": host if host is not None else lock.hostname(),
        "created_at": format_ts(created),
        "token": token,
    }
    (run_dir / lock.LOCK_NAME).write_text(json.dumps(content), encoding="utf-8")


def test_lock_file_content_and_release(tmp_path):
    with lock.run_lock(tmp_path):
        data = json.loads((tmp_path / lock.LOCK_NAME).read_text(encoding="utf-8"))
        assert data["pid"] == os.getpid()
        assert data["host"] == lock.hostname()
        assert set(data) == {"pid", "host", "created_at", "token"}
    assert not (tmp_path / lock.LOCK_NAME).exists()


def test_lock_is_released_after_an_error(tmp_path):
    with pytest.raises(RuntimeError), lock.run_lock(tmp_path):
        raise RuntimeError("boom")
    assert not (tmp_path / lock.LOCK_NAME).exists()


def test_contention_times_out(tmp_path):
    entered = threading.Event()
    leave = threading.Event()

    def holder():
        with lock.run_lock(tmp_path):
            entered.set()
            leave.wait(5)

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert entered.wait(5)
        started = time.monotonic()
        with pytest.raises(StateError, match="locked by another kalkan process"):
            with lock.run_lock(tmp_path, timeout_seconds=0.3):
                pass
        assert time.monotonic() - started >= 0.25
    finally:
        leave.set()
        thread.join()
    with lock.run_lock(tmp_path, timeout_seconds=1):
        pass


def test_waiter_gets_the_lock_after_release(tmp_path):
    entered = threading.Event()

    def holder():
        with lock.run_lock(tmp_path):
            entered.set()
            time.sleep(0.2)

    thread = threading.Thread(target=holder)
    thread.start()
    assert entered.wait(5)
    with lock.run_lock(tmp_path, timeout_seconds=5):
        assert json.loads((tmp_path / lock.LOCK_NAME).read_text())["pid"] == os.getpid()
    thread.join()


def test_old_lock_of_a_dead_process_is_removed(tmp_path, monkeypatch):
    monkeypatch.setattr(lock, "pid_alive", lambda pid: False)
    write_lock(tmp_path, pid=999_999, age_seconds=600)
    with lock.run_lock(tmp_path, timeout_seconds=1):
        data = json.loads((tmp_path / lock.LOCK_NAME).read_text(encoding="utf-8"))
        assert data["pid"] == os.getpid()
    assert not (tmp_path / lock.LOCK_NAME).exists()
    assert not (tmp_path / (lock.LOCK_NAME + ".break")).exists()


def test_young_lock_of_a_dead_process_is_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(lock, "pid_alive", lambda pid: False)
    write_lock(tmp_path, pid=999_999, age_seconds=10)
    with pytest.raises(StateError):
        with lock.run_lock(tmp_path, timeout_seconds=0.2):
            pass
    assert (tmp_path / lock.LOCK_NAME).exists()


def test_old_lock_of_a_live_process_is_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(lock, "pid_alive", lambda pid: True)
    write_lock(tmp_path, pid=999_999, age_seconds=600)
    with pytest.raises(StateError, match="pid 999999"):
        with lock.run_lock(tmp_path, timeout_seconds=0.2):
            pass
    assert json.loads((tmp_path / lock.LOCK_NAME).read_text())["pid"] == 999_999


def test_old_lock_of_another_host_is_removed(tmp_path, monkeypatch):
    def never_called(pid):
        raise AssertionError("liveness is not checked for another host")

    monkeypatch.setattr(lock, "pid_alive", never_called)
    write_lock(tmp_path, pid=1, host="other-host.example", age_seconds=600)
    with lock.run_lock(tmp_path, timeout_seconds=1):
        pass


def test_young_lock_of_another_host_is_kept(tmp_path):
    write_lock(tmp_path, pid=1, host="other-host.example", age_seconds=5)
    with pytest.raises(StateError):
        with lock.run_lock(tmp_path, timeout_seconds=0.2):
            pass


def test_unreadable_lock_ages_by_file_time(tmp_path):
    path = tmp_path / lock.LOCK_NAME
    path.write_text("", encoding="utf-8")
    with pytest.raises(StateError):
        with lock.run_lock(tmp_path, timeout_seconds=0.2):
            pass
    old = time.time() - 600
    os.utime(path, (old, old))
    with lock.run_lock(tmp_path, timeout_seconds=1):
        pass


def test_old_break_guard_is_cleaned_up(tmp_path, monkeypatch):
    monkeypatch.setattr(lock, "pid_alive", lambda pid: False)
    write_lock(tmp_path, pid=999_999, age_seconds=600)
    guard = tmp_path / (lock.LOCK_NAME + ".break")
    guard.write_text("", encoding="utf-8")
    old = time.time() - 60
    os.utime(guard, (old, old))
    with lock.run_lock(tmp_path, timeout_seconds=2):
        pass
    assert not guard.exists()


def test_release_keeps_a_lock_with_another_token(tmp_path):
    with lock.run_lock(tmp_path):
        write_lock(tmp_path, pid=os.getpid(), token="someone-else")
    assert (tmp_path / lock.LOCK_NAME).exists()


def test_missing_run_folder(tmp_path):
    with pytest.raises(StateError, match="does not exist"):
        with lock.run_lock(tmp_path / "missing"):
            pass


def test_is_stale_rules(monkeypatch):
    now = datetime.now(UTC)
    old = now - timedelta(seconds=lock.STALE_AFTER_SECONDS + 1)
    young = now - timedelta(seconds=lock.STALE_AFTER_SECONDS - 1)
    here = lock.hostname()
    monkeypatch.setattr(lock, "pid_alive", lambda pid: pid == 1)
    assert not lock.is_stale(lock.LockInfo(2, here, young, "t", 0), now)
    assert lock.is_stale(lock.LockInfo(2, here, old, "t", 0), now)
    assert not lock.is_stale(lock.LockInfo(1, here, old, "t", 0), now)
    assert lock.is_stale(lock.LockInfo(1, "elsewhere", old, "t", 0), now)
    assert lock.is_stale(lock.LockInfo(None, None, None, None, old.timestamp()), now)


def test_pid_alive_for_this_and_finished_processes():
    assert lock.pid_alive(os.getpid())
    child = subprocess.run(
        [sys.executable, "-c", "import os; print(os.getpid())"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    assert not lock.pid_alive(int(child.stdout.strip()))
    assert not lock.pid_alive(0)
    assert not lock.pid_alive(-5)
    assert not lock.pid_alive(True)


def test_pid_alive_for_a_running_process():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert lock.pid_alive(child.pid)
    finally:
        child.kill()
        child.wait(timeout=30)
    assert not lock.pid_alive(child.pid)


@pytest.mark.skipif(os.name != "nt", reason="Windows liveness path")
def test_windows_liveness_never_calls_os_kill(monkeypatch):
    def forbidden(*args):
        raise AssertionError("os.kill must not be called on Windows")

    monkeypatch.setattr(os, "kill", forbidden)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert lock.pid_alive(child.pid)
    finally:
        child.terminate()
        child.wait(timeout=30)
    assert not lock.pid_alive(child.pid)


@pytest.mark.skipif(os.name == "nt", reason="POSIX liveness path")
def test_posix_liveness_handles_errno(monkeypatch):
    def denied(pid, signal):
        raise PermissionError

    monkeypatch.setattr(os, "kill", denied)
    assert lock.pid_alive(4242)

    def missing(pid, signal):
        raise ProcessLookupError

    monkeypatch.setattr(os, "kill", missing)
    assert not lock.pid_alive(4242)
