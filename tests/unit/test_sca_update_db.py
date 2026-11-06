# SPDX-License-Identifier: MIT
"""Tests for the freshness check of ``kalkan sca update-db`` (kalkan.sca.vulndb.update).

No network and no tool: OSV-Scanner and Grype run through a fake runner, the Go archive and the
RetireJS repository come from fake fetch functions. Each fake records its database in
``Downloads.calls``, so a test sees exactly which databases were downloaded.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from kalkan import cli
from kalkan.audit import preflight
from kalkan.sca import commands, vulndb
from kalkan.scanners.base import ProcessOutcome

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
BUILT = "2026-10-29T06:23:34Z"
GO_MODIFIED = "2026-10-27T21:16:18Z"
GRYPE_SOURCE = "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_x.tar.zst"
#: The real update function: the CLI test replaces ``vulndb.update`` with a wrapper.
REAL_UPDATE = vulndb.update


def iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(**delta: float) -> str:
    return iso(NOW - timedelta(**delta))


def retire_repository() -> bytes:
    libraries = {
        f"lib{index}": {
            "vulnerabilities": [
                {
                    "below": "1.0.0",
                    "severity": "low",
                    "identifiers": {"summary": "sample"},
                    "info": ["https://example.invalid/lib"],
                }
            ],
            "extractors": {"filename": [f"lib{index}-(§§version§§)(.min)?\\.js"]},
        }
        for index in range(24)
    }
    return json.dumps(libraries).encode("utf-8")


def go_members() -> dict[str, object]:
    item = {
        "id": "GO-2026-0001",
        "modified": GO_MODIFIED,
        "affected": [{"package": {"name": "example.com/m", "ecosystem": "Go"}}],
    }
    return {
        "index/db.json": {"modified": GO_MODIFIED},
        "index/modules.json": [
            {"path": "example.com/m", "vulns": [{"id": item["id"], "modified": GO_MODIFIED}]}
        ],
        "index/vulns.json": [{"id": item["id"], "modified": GO_MODIFIED, "aliases": []}],
        "ID/GO-2026-0001.json": item,
    }


def write_zip(path: Path, members: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as bundle:
        for name, value in members.items():
            bundle.writestr(name, json.dumps(value))


def osv_archive(root: Path, ecosystem: str) -> Path:
    path = root / "osv" / "osv-scalibr" / ecosystem / "all.zip"
    write_zip(path, {"OSV-1.json": {"id": "OSV-1"}})
    return path


def grype_database(root: Path) -> Path:
    folder = root / "grype" / "6"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "vulnerability.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 64)
    source = {"source": GRYPE_SOURCE + "?checksum=sha256%3Aab", "digest": "xxh64:1"}
    (folder / "import.json").write_text(json.dumps(source), encoding="utf-8")
    return folder / "vulnerability.db"


def go_database(root: Path, updated_at: str) -> None:
    folder = root / "go"
    for name, value in go_members().items():
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
    source = {
        "source": "official",
        "url": "https://vuln.go.dev/vulndb.zip",
        "modified": GO_MODIFIED,
        "entries": 1,
        "updated_at": updated_at,
    }
    (folder / "kalkan-source.json").write_text(json.dumps(source), encoding="utf-8")


def retire_database(root: Path, updated_at: str) -> str:
    folder = root / "retire"
    folder.mkdir(parents=True, exist_ok=True)
    data = retire_repository()
    (folder / "jsrepository-v5.json").write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    source = {
        "source": "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/"
        "jsrepository-v5.json",
        "sha256": digest,
        "libraries": 24,
        "updated_at": updated_at,
    }
    (folder / "kalkan-source.json").write_text(json.dumps(source), encoding="utf-8")
    return digest


def fill(root: Path, when: str) -> None:
    """Write valid files of all four databases, downloaded at ``when``."""
    for ecosystem in vulndb.DEFAULT_ECOSYSTEMS:
        osv_archive(root, ecosystem)
    grype_database(root)
    go_database(root, when)
    retire_database(root, when)


def new_status(root: Path, when: dict[str, str] | str, **parts: dict) -> None:
    """Write a status.json of the current format; ``when`` is one time or one per database."""
    times = when if isinstance(when, dict) else dict.fromkeys(vulndb.DATABASES, when)
    status: dict = {"schema_version": 2, "root": root.as_posix(), "updated_at": max(times.values())}
    for name in vulndb.DATABASES:
        status[name] = {
            "database": name,
            "status": "ok",
            "action": "downloaded",
            "downloaded_at": times[name],
            "updated_at": times[name],
        }
    status["grype"]["built"] = BUILT
    for name, extra in parts.items():
        status[name].update(extra)
    (root / "status.json").write_text(json.dumps(status), encoding="utf-8")


def old_status(root: Path, when: str) -> None:
    """Write a status.json of the format before the freshness check (kalkan 1.6.1)."""
    status = {
        "root": root.as_posix(),
        "updated_at": when,
        "osv": {
            "status": "ok",
            "message": "",
            "ecosystems": sorted(vulndb.DEFAULT_ECOSYSTEMS),
            "requested": list(vulndb.DEFAULT_ECOSYSTEMS),
            "missing": [],
            "exit_code": 0,
            "updated_at": when,
        },
        "grype": {"status": "ok", "message": "", "built": BUILT, "updated_at": when},
        "go": {
            "status": "ok",
            "source": "official",
            "modified": GO_MODIFIED,
            "entries": 1,
            "url": "https://vuln.go.dev/vulndb.zip",
            "built_from": None,
            "message": "",
            "ready": True,
            "updated_at": when,
        },
        "retire": {
            "status": "ok",
            "message": "",
            "sha256": "f" * 64,
            "libraries": 24,
            "ready": True,
            "updated_at": when,
        },
    }
    (root / "status.json").write_text(json.dumps(status), encoding="utf-8")


class FakeTool:
    def __init__(self, name: str) -> None:
        self.argv = [f"/opt/{name}"]


class Downloads:
    """Fake downloads of the four databases; ``calls`` lists the databases in order."""

    def __init__(self, *, grype_ok: bool = True) -> None:
        self.calls: list[str] = []
        self.grype_ok = grype_ok

    def runner(self, argv, *, cwd, env, timeout, stdout, stderr):
        if argv[0].endswith("osv-scanner"):
            self.calls.append("osv")
            probe = json.loads(Path(argv[argv.index("-L") + 1]).read_text(encoding="utf-8"))
            cache = Path(env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"]).parent
            for item in probe["components"]:
                ecosystem = next(k for k, v in vulndb.PROBE_PURLS.items() if v == item["purl"])
                osv_archive(cache, ecosystem)
            return ProcessOutcome(0)
        if argv[1:3] == ["db", "update"]:
            self.calls.append("grype")
            if not self.grype_ok:
                stderr.write(b"failed to download the database\n")
                return ProcessOutcome(1)
            grype_database(Path(env["GRYPE_DB_CACHE_DIR"]).parent)
            return ProcessOutcome(0)
        if argv[1:3] == ["db", "status"]:
            stdout.write(json.dumps({"built": BUILT, "valid": True}).encode())
            return ProcessOutcome(0)
        raise AssertionError(argv)

    def fetch(self, url: str, dest: Path, timeout: int) -> dict:
        self.calls.append("go")
        write_zip(dest, go_members())
        return {"url": url, "sha256": "abc", "bytes": dest.stat().st_size, "last_modified": None}

    def retire_fetch(self, url: str, dest: Path, timeout: int) -> dict:
        self.calls.append("retire")
        dest.write_bytes(retire_repository())
        return {"url": url, "etag": None, "last_modified": None}

    def update(self, root: Path, **kwargs) -> dict:
        kwargs.setdefault("now", NOW)
        return REAL_UPDATE(
            root,
            runner=self.runner,
            resolver=FakeTool,
            fetch=self.fetch,
            retire_fetch=self.retire_fetch,
            **kwargs,
        )


@pytest.fixture
def root(tmp_path: Path) -> Path:
    folder = tmp_path / "vulndb"
    folder.mkdir()
    return folder


# --- fresh, old, missing --------------------------------------------------------------------------


def test_fresh_databases_are_kept_and_not_downloaded(root):
    fill(root, ago(hours=3))
    new_status(root, ago(hours=3))
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == []
    for name in vulndb.DATABASES:
        part = summary[name]
        assert part["action"] == "kept" and part["status"] == "ok", name
        assert part["downloaded_at"] == ago(hours=3) and part["age_hours"] == 3.0
        assert part["database"] == name and part["source"] and part["version"]
    assert summary["osv"]["ecosystems"] == sorted(vulndb.DEFAULT_ECOSYSTEMS)
    assert summary["grype"]["version"] == BUILT and summary["grype"]["source"] == GRYPE_SOURCE
    assert summary["go"]["version"] == GO_MODIFIED and summary["go"]["go_source"] == "official"
    assert summary["retire"]["version"] == hashlib.sha256(retire_repository()).hexdigest()
    assert summary["checked_at"] == iso(NOW) and summary["updated_at"] == ago(hours=3)
    written = vulndb.read_status(root)
    assert written["schema_version"] == 2 and written["osv"]["downloaded_at"] == ago(hours=3)
    assert commands.update_line("osv", summary["osv"]) == "kept, 3 hours old (13 ecosystems)"
    assert commands.update_line("grype", summary["grype"]) == f"kept, 3 hours old (built {BUILT})"


def test_old_databases_are_downloaded(root):
    fill(root, ago(hours=30))
    new_status(root, ago(hours=30))
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == ["osv", "grype", "go", "retire"]
    for name in vulndb.DATABASES:
        part = summary[name]
        assert part["action"] == "downloaded" and part["status"] == "ok", name
        assert part["reason"] == "30 hours old"
        assert part["downloaded_at"] == part["updated_at"] == iso(NOW)
    assert summary["updated_at"] == iso(NOW)
    line = commands.update_line("osv", summary["osv"])
    assert line == "ok 13 ecosystems (download reason: 30 hours old)"
    # The next call within the limit downloads nothing.
    again = Downloads()
    second = again.update(root, now=NOW + timedelta(hours=2))
    assert again.calls == [] and second["grype"]["age_hours"] == 2.0


def test_missing_databases_are_downloaded(root):
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == ["osv", "grype", "go", "retire"]
    assert summary["osv"]["reason"].startswith("no local database for npm, PyPI")
    for name in ("grype", "go", "retire"):
        assert summary[name]["reason"] == "no local database", name
    assert all(summary[name]["status"] == "ok" for name in vulndb.DATABASES)
    assert summary["osv"]["source"] == vulndb.OSV_SOURCE
    assert summary["go"]["source"] == "https://vuln.go.dev/vulndb.zip"


def test_files_without_a_status_record_are_downloaded(root):
    fill(root, ago(hours=1))
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == ["osv", "grype", "go", "retire"]
    assert summary["grype"]["reason"] == "no record of an earlier download"


def test_a_missing_ecosystem_downloads_the_osv_databases(root):
    fill(root, ago(hours=1))
    new_status(root, ago(hours=1))
    (root / "osv" / "osv-scalibr" / "NuGet" / "all.zip").unlink()
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == ["osv"]
    assert summary["osv"]["reason"] == "no local database for NuGet"
    # Fewer ecosystems than the folder holds: the older archives keep the older time.
    partial = Downloads().update(root, ecosystems=["npm"], force=True)
    assert partial["osv"]["downloaded_at"] == iso(NOW)  # every archive was downloaded at NOW
    later = Downloads().update(root, ecosystems=["npm"], force=True, now=NOW + timedelta(hours=5))
    assert later["osv"]["downloaded_at"] == iso(NOW)  # the 12 other archives are older


# --- broken status or files ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "damage", "reason"),
    [
        ("osv", "osv_status_failed", "the last download ended failed"),
        ("osv", "osv_not_zip", "broken: npm/all.zip is not a zip archive"),
        ("grype", "grype_not_sqlite", "broken: vulnerability.db is not an SQLite database"),
        ("go", "go_index", "broken: index/db.json has no valid modified time"),
        ("retire", "retire_changed", "broken: the repository file differs from its recorded"),
        ("retire", "retire_no_time", "the time of the last download is unknown"),
        ("grype", "grype_future", "the time of the last download is in the future"),
    ],
)
def test_broken_files_or_status_are_downloaded_again(root, name, damage, reason):
    fill(root, ago(hours=1))
    new_status(root, ago(hours=1))
    status = json.loads((root / "status.json").read_text(encoding="utf-8"))
    if damage == "osv_status_failed":
        status["osv"]["status"] = "failed"
    elif damage == "osv_not_zip":
        (root / "osv" / "osv-scalibr" / "npm" / "all.zip").write_bytes(b"<html>404</html>")
    elif damage == "grype_not_sqlite":
        (root / "grype" / "6" / "vulnerability.db").write_bytes(b"not a database")
    elif damage == "go_index":
        (root / "go" / "index" / "db.json").write_text("{}", encoding="utf-8")
    elif damage == "retire_changed":
        (root / "retire" / "jsrepository-v5.json").write_bytes(b"{}")
    elif damage == "retire_no_time":
        status["retire"].pop("downloaded_at")
        status["retire"]["updated_at"] = "yesterday"
    elif damage == "grype_future":
        status["grype"]["downloaded_at"] = status["grype"]["updated_at"] = ago(hours=-3)
    (root / "status.json").write_text(json.dumps(status), encoding="utf-8")
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == [name]
    assert summary[name]["reason"].startswith(reason)
    assert summary[name]["action"] == "downloaded" and summary[name]["status"] == "ok"


def test_a_broken_status_file_downloads_every_database(root):
    fill(root, ago(hours=1))
    (root / "status.json").write_text("{not json", encoding="utf-8")
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == ["osv", "grype", "go", "retire"]
    assert {summary[name]["reason"] for name in vulndb.DATABASES} == {
        "no record of an earlier download"
    }


def test_a_failed_download_keeps_the_time_of_the_data_that_stays(root):
    fill(root, ago(hours=30))
    new_status(root, ago(hours=30))
    downloads = Downloads(grype_ok=False)
    summary = downloads.update(root, grype=True, osv=False, go=False, retire=False)
    assert downloads.calls == ["grype"]
    grype = summary["grype"]
    assert grype["status"] == "failed" and grype["action"] == "failed"
    assert grype["downloaded_at"] == grype["updated_at"] == ago(hours=30)
    assert summary["updated_at"] == ago(hours=30)  # nothing new was downloaded
    # The next call tries again, even within the age limit.
    retry = Downloads()
    again = retry.update(root, grype=True, osv=False, go=False, retire=False)
    assert retry.calls == ["grype"] and again["grype"]["reason"] == "the last download ended failed"


# --- --force, --max-age and the per-database mix -------------------------------------------------


def test_force_downloads_fresh_databases(root):
    fill(root, ago(minutes=10))
    new_status(root, ago(minutes=10))
    downloads = Downloads()
    summary = downloads.update(root, force=True)
    assert downloads.calls == ["osv", "grype", "go", "retire"]
    assert {summary[name]["reason"] for name in vulndb.DATABASES} == {"--force"}
    assert summary["force"] is True


def test_max_age_sets_the_limit(root):
    fill(root, ago(hours=3))
    new_status(root, ago(hours=3))
    kept = Downloads()
    kept.update(root, max_age_hours=vulndb.SETUP_MAX_AGE_HOURS)
    assert kept.calls == []
    short = Downloads()
    summary = short.update(root, max_age_hours=2, osv=False, go=False, retire=False)
    assert short.calls == ["grype"] and summary["grype"]["reason"] == "3 hours old"
    zero = Downloads()
    zero.update(root, max_age_hours=0, osv=False, grype=False, go=False)
    assert zero.calls == ["retire"]
    with pytest.raises(ValueError, match="0 or more hours"):
        vulndb.update(root, max_age_hours=-1)


def test_a_week_old_install_downloads_nothing_with_the_setup_limit(root):
    # The installers pass the stale limit of kalkan doctor: six days old is kept.
    fill(root, ago(days=6))
    new_status(root, ago(days=6))
    downloads = Downloads()
    summary = downloads.update(root, max_age_hours=vulndb.SETUP_MAX_AGE_HOURS)
    assert downloads.calls == []
    assert commands.update_line("go", summary["go"]).startswith("kept, 6 days old (source")
    stale = Downloads()
    stale.update(root, max_age_hours=vulndb.SETUP_MAX_AGE_HOURS, now=NOW + timedelta(days=2))
    assert stale.calls == ["osv", "grype", "go", "retire"]


def test_per_database_mix(root):
    fill(root, ago(hours=1))
    times = {"osv": ago(hours=2), "grype": ago(hours=40), "go": ago(hours=1)}
    times["retire"] = ago(hours=1)
    new_status(root, times)
    for path in (root / "go").rglob("*"):
        if path.is_file():
            path.unlink()
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == ["grype", "go"]
    assert [summary[name]["action"] for name in vulndb.DATABASES] == [
        "kept",
        "downloaded",
        "downloaded",
        "kept",
    ]
    assert summary["osv"]["downloaded_at"] == ago(hours=2)
    assert summary["grype"]["reason"] == "40 hours old"
    assert summary["go"]["reason"] == "no local database"
    assert summary["retire"]["downloaded_at"] == ago(hours=1)


def test_a_database_that_is_not_selected_keeps_its_record(root):
    fill(root, ago(hours=30))
    new_status(root, ago(hours=30))
    downloads = Downloads()
    summary = downloads.update(root, osv=False, grype=False, go=False)
    assert downloads.calls == ["retire"]
    assert summary["osv"]["downloaded_at"] == ago(hours=30)
    assert summary["osv"]["action"] == "downloaded"  # the record of the earlier download


# --- the format before the freshness check --------------------------------------------------------


def test_the_older_status_format_is_read(root):
    fill(root, ago(hours=3))
    old_status(root, ago(hours=3))
    digest = hashlib.sha256(retire_repository()).hexdigest()
    status = json.loads((root / "status.json").read_text(encoding="utf-8"))
    status["retire"]["sha256"] = digest
    (root / "status.json").write_text(json.dumps(status), encoding="utf-8")
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == []
    for name in vulndb.DATABASES:
        assert summary[name]["action"] == "kept", name
        assert summary[name]["downloaded_at"] == ago(hours=3)
        assert summary[name]["database"] == name and summary[name]["source"], name
    assert summary["go"]["go_source"] == "official"
    assert summary["go"]["source"] == "https://vuln.go.dev/vulndb.zip"
    assert summary["retire"]["version"] == digest
    assert vulndb.read_status(root)["schema_version"] == 2


def test_an_old_database_of_the_older_format_is_downloaded(root):
    fill(root, ago(days=3))
    old_status(root, ago(days=3))
    downloads = Downloads()
    summary = downloads.update(root)
    assert downloads.calls == ["osv", "grype", "go", "retire"]
    assert summary["grype"]["reason"] == "3 days old"


def test_doctor_reads_the_download_time(tmp_path):
    from kalkan.tools import doctor

    home = tmp_path / "home"
    folder = vulndb.db_root(home)
    fill(folder, ago(days=9))
    new_status(folder, ago(days=9))
    status = json.loads((folder / "status.json").read_text(encoding="utf-8"))
    for name in vulndb.DATABASES:
        status[name].pop("updated_at")  # only the field of the current format
    (folder / "status.json").write_text(json.dumps(status), encoding="utf-8")
    check = doctor._check_vulndb(home, now=NOW.timestamp())
    assert check.status == "warn" and "9 days old" in check.detail
    fresh = doctor._check_vulndb(home, now=(NOW - timedelta(days=8)).timestamp())
    assert fresh.status == "ok", fresh.detail


def test_age_text():
    assert vulndb.age_text(59) == "0 minutes"
    assert vulndb.age_text(60) == "1 minute"
    assert vulndb.age_text(3 * 3600 + 10) == "3 hours"
    assert vulndb.age_text(47 * 3600) == "47 hours"
    assert vulndb.age_text(8 * 86400 + 5) == "8 days"


# --- CLI and installers ---------------------------------------------------------------------------


def test_cli_update_db_force_and_max_age(root, monkeypatch, capsys):
    fill(root, ago(hours=3))
    new_status(root, ago(hours=3))
    downloads = Downloads()
    monkeypatch.setattr(vulndb, "update", lambda **kw: Downloads.update(downloads, root, **kw))
    assert cli.main(["sca", "update-db"]) == 0
    err = capsys.readouterr().err
    assert "(a database younger than 24 hours is kept; --force downloads it)" in err
    assert "  osv: kept, 3 hours old (13 ecosystems)" in err
    assert "  retire: kept, 3 hours old (" in err and downloads.calls == []
    assert cli.main(["sca", "update-db", "--max-age", "2", "--no-osv", "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["grype"]["reason"] == "3 hours old"
    assert "  grype: ok built 2026-10-29T06:23:34Z (download reason: 3 hours old)" in captured.err
    assert downloads.calls == ["grype", "go", "retire"]
    assert cli.main(["sca", "update-db", "--force", "--no-grype", "--no-go", "--no-retire"]) == 0
    assert "osv: ok 13 ecosystems (download reason: --force)" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["sca", "update-db", "--max-age", "-1"])


def test_installers_and_the_audit_setup_use_the_stale_limit_of_doctor():
    assert vulndb.SETUP_MAX_AGE_HOURS == vulndb.STALE_DAYS * 24 == 168
    assert preflight.DATABASES_COMMAND == ("sca", "update-db", "--max-age", "168")
    setup = (ROOT / "plugins" / "kalkan" / "bin" / "kalkan-setup").read_text(encoding="utf-8")
    assert '"$engine" sca update-db --max-age 168 ||' in setup
    shell = (ROOT / "scripts" / "bootstrap.sh").read_text(encoding="utf-8")
    assert '"$py" -m kalkan sca update-db --max-age 168 ||' in shell
    powershell = (ROOT / "scripts" / "bootstrap.ps1").read_text(encoding="utf-8")
    assert "@('-m', 'kalkan', 'sca', 'update-db', '--max-age', '168')" in powershell
