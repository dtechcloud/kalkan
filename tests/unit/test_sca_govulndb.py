# SPDX-License-Identifier: MIT
"""Tests for kalkan.sca.govulndb: the local Go vulnerability database of govulncheck.

No network: the official download is replaced by a fake ``fetch`` or a fake ``urlopen``. The
archives follow the layout of https://vuln.go.dev/vulndb.zip (checked on 2026-10-16) and of the
OSV Go archive ``osv-scalibr/Go/all.zip``.
"""

from __future__ import annotations

import io
import json
import ssl
import urllib.request
import zipfile
from email.message import Message
from pathlib import Path

import pytest

from kalkan.sca import govulndb, vulndb


def entry(vuln_id: str, *modules: str, modified: str = "2026-01-02T03:04:05Z", **extra) -> dict:
    return {
        "schema_version": "1.3.1",
        "id": vuln_id,
        "modified": modified,
        "aliases": [f"CVE-{vuln_id[3:]}"],
        "affected": [
            {
                "package": {"name": module, "ecosystem": "Go"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
            }
            for module in modules
        ],
        **extra,
    }


ENTRIES = [
    entry("GO-2022-1059", "golang.org/x/text", modified="2024-05-20T16:03:47Z"),
    entry("GO-2026-6603", "stdlib", "stdlib", modified="2026-10-08T22:31:09Z"),
    entry(
        "GO-2020-0002",
        "github.com/proglottis/gpgme",
        modified="2022-08-29T16:50:59Z",
        withdrawn="2024-05-15T05:37:10.997384Z",
    ),
]


def write_zip(path: Path, members: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as bundle:
        for name, value in members.items():
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            bundle.writestr(name, data)
    return path


def official_members(entries=ENTRIES, **extra) -> dict[str, object]:
    modules: dict[str, list] = {}
    for item in entries:
        for affected in item["affected"]:
            name = affected["package"]["name"]
            modules.setdefault(name, []).append({"id": item["id"], "modified": item["modified"]})
    members: dict[str, object] = {
        "index/db.json": {"modified": "2026-10-08T22:31:09Z"},
        "index/modules.json": [{"path": k, "vulns": v} for k, v in sorted(modules.items())],
        "index/vulns.json": [{"id": e["id"], "modified": e["modified"]} for e in entries],
    }
    for item in entries:
        members[f"ID/{item['id']}.json"] = item
    members.update(extra)
    return members


def fake_fetch(members: dict[str, object]):
    calls: list = []

    def fetch(url: str, dest: Path, timeout: int) -> dict:
        calls.append(url)
        write_zip(dest, members)
        return {"url": url, "sha256": "abc", "bytes": dest.stat().st_size, "last_modified": None}

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


def failing_fetch(url: str, dest: Path, timeout: int) -> dict:
    raise govulndb.GoDbError(f"{url} answered with text/html, not a zip archive")


def osv_zip(root: Path, entries=ENTRIES) -> Path:
    members: dict[str, object] = {f"{item['id']}.json": item for item in entries}
    members["GHSA-xxxx-yyyy-zzzz.json"] = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "modified": "2026-01-01T00:00:00Z",
    }
    return write_zip(root / "osv" / "osv-scalibr" / "Go" / "all.zip", members)


# --- the official archive ----------------------------------------------------------------------


def test_the_official_archive_becomes_the_database(tmp_path):
    root = tmp_path / "vulndb"
    fetch = fake_fetch(official_members(**{"README.txt": b"x", "../escape.json": b"{}"}))
    result = govulndb.update(root, root / "none.zip", fetch=fetch)
    assert fetch.calls == ["https://vuln.go.dev/vulndb.zip"]
    assert result["status"] == "ok" and result["source"] == "official"
    assert (result["modified"], result["entries"]) == ("2026-10-08T22:31:09Z", 3)
    assert govulndb.ready(root) and vulndb.go_db_ready(root)
    folder = root / "go"
    assert sorted(p.name for p in (folder / "ID").iterdir()) == [
        "GO-2020-0002.json",
        "GO-2022-1059.json",
        "GO-2026-6603.json",
    ]
    assert not (tmp_path / "escape.json").exists() and not (folder / "README.txt").exists()
    info = govulndb.info(root)
    assert info["source"] == "official" and info["ignored_members"] == 2
    assert info["modified"] == "2026-10-08T22:31:09Z" and info["url"].startswith("https://")
    assert govulndb.db_uri(root) == folder.resolve().as_uri()
    assert [p.name for p in root.iterdir() if p.name.startswith(".go-")] == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda m: m.pop("index/modules.json"), "no index/modules.json"),
        (lambda m: m.update({"index/db.json": {"modified": "yesterday"}}), "no valid 'modified'"),
        (lambda m: m.pop("ID/GO-2022-1059.json"), "has no ID file"),
        (
            lambda m: m.update({"ID/GO-2022-1059.json": entry("GO-2022-9999", "x")}),
            "does not hold the entry",
        ),
        (lambda m: m.update({"ID/GO-2022-1059.json": b"<html>"}), "not valid JSON"),
    ],
)
def test_a_broken_official_archive_is_refused(tmp_path, change, message):
    members = official_members()
    change(members)
    root = tmp_path / "vulndb"
    result = govulndb.update(root, root / "none.zip", source="official", fetch=fake_fetch(members))
    assert result["status"] == "failed" and message in result["message"]
    assert not govulndb.ready(root)


def test_auto_falls_back_to_the_osv_build(tmp_path):
    root = tmp_path / "vulndb"
    archive = osv_zip(root)
    result = govulndb.update(root, archive, fetch=failing_fetch)
    assert result["status"] == "ok" and result["source"] == "osv"
    assert "built from the OSV Go database" in result["message"]
    assert "text/html" in result["message"]
    info = govulndb.info(root)
    assert info["source"] == "osv" and info["built_from"] == "osv/osv-scalibr/Go/all.zip"
    assert info["modified"] == "2026-10-08T22:31:09Z" and info["entries"] == 3
    folder = root / "go"
    db = json.loads((folder / "index" / "db.json").read_text(encoding="utf-8"))
    assert db == {"modified": "2026-10-08T22:31:09Z"}
    modules = json.loads((folder / "index" / "modules.json").read_text(encoding="utf-8"))
    assert [m["path"] for m in modules] == [
        "github.com/proglottis/gpgme",
        "golang.org/x/text",
        "stdlib",
    ]
    # One record per module and entry, and never a computed "fixed" version.
    assert modules[2]["vulns"] == [{"id": "GO-2026-6603", "modified": "2026-10-08T22:31:09Z"}]
    assert all("fixed" not in vuln for module in modules for vuln in module["vulns"])
    vulns = json.loads((folder / "index" / "vulns.json").read_text(encoding="utf-8"))
    assert [v["id"] for v in vulns] == ["GO-2020-0002", "GO-2022-1059", "GO-2026-6603"]
    assert vulns[1]["aliases"] == ["CVE-2022-1059"]
    assert not (folder / "ID" / "GHSA-xxxx-yyyy-zzzz.json").exists()
    copied = json.loads((folder / "ID" / "GO-2022-1059.json").read_text(encoding="utf-8"))
    assert copied == ENTRIES[0]


def test_osv_source_and_failures_keep_the_old_database(tmp_path):
    root = tmp_path / "vulndb"
    first = govulndb.update(root, osv_zip(root), source="osv", fetch=failing_fetch)
    assert first["status"] == "ok" and first["source"] == "osv"
    again = govulndb.update(root, root / "missing.zip", fetch=failing_fetch)
    assert again["status"] == "failed" and again["ready"] is True
    assert "official archive" in again["message"] and "OSV build" in again["message"]
    assert "the previous database stays" in again["message"]
    assert govulndb.info(root)["source"] == "osv"
    with pytest.raises(ValueError, match="unknown Go database source"):
        govulndb.update(root, root / "missing.zip", source="nope")


def test_info_and_ready_without_a_database(tmp_path):
    assert govulndb.ready(tmp_path) is False
    assert govulndb.info(tmp_path) is None
    (tmp_path / "go" / "index").mkdir(parents=True)
    (tmp_path / "go" / "index" / "db.json").write_text("{}", encoding="utf-8")
    (tmp_path / "go" / "index" / "modules.json").write_text("[]", encoding="utf-8")
    assert govulndb.info(tmp_path) == {"source": "unknown"}


# --- the download ------------------------------------------------------------------------------


class FakeResponse(io.BytesIO):
    """The part of ``http.client.HTTPResponse`` that :func:`govulndb.download` reads."""

    def __init__(self, data: bytes, url: str, content_type: str) -> None:
        super().__init__(data)
        self.url = url
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.headers["Last-Modified"] = "Fri, 16 Oct 2026 10:19:18 GMT"

    def geturl(self) -> str:
        return self.url


def fake_urlopen(data: bytes, url: str, content_type: str, seen: list):
    def urlopen(request, timeout=None, context=None):
        assert isinstance(context, ssl.SSLContext)  # the kalkan context (kalkan.tools.tls)
        seen.append((request.full_url, dict(request.header_items()), timeout))
        return FakeResponse(data, url, content_type)

    return urlopen


def test_download_checks_the_answer(tmp_path, monkeypatch):
    archive = write_zip(tmp_path / "src.zip", official_members()).read_bytes()
    seen: list = []
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        fake_urlopen(archive, govulndb.OFFICIAL_URL, "application/zip", seen),
    )
    meta = govulndb.download(govulndb.OFFICIAL_URL, tmp_path / "a.zip", 30)
    assert meta["url"] == govulndb.OFFICIAL_URL and meta["bytes"] == len(archive)
    assert meta["content_type"] == "application/zip" and len(meta["sha256"]) == 64
    url, headers, timeout = seen[0]
    assert url == "https://vuln.go.dev/vulndb.zip" and timeout == 30
    assert set(headers) == {"User-agent", "Accept"}  # no data of a project
    # The server answered with an HTML page (as vuln.go.dev/vuln.zip did): refused.
    monkeypatch.setattr(
        urllib.request, "urlopen", fake_urlopen(b"<html>", govulndb.OFFICIAL_URL, "text/html", [])
    )
    with pytest.raises(govulndb.GoDbError, match="text/html, not a zip archive"):
        govulndb.download(govulndb.OFFICIAL_URL, tmp_path / "b.zip", 30)
    # A redirect to plain HTTP: refused.
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        fake_urlopen(archive, "http://mirror.example/vulndb.zip", "application/zip", []),
    )
    with pytest.raises(govulndb.GoDbError, match="without HTTPS"):
        govulndb.download(govulndb.OFFICIAL_URL, tmp_path / "c.zip", 30)
    # A zip content type without the zip signature: refused.
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        fake_urlopen(b"not a zip", govulndb.OFFICIAL_URL, "application/zip", []),
    )
    with pytest.raises(govulndb.GoDbError, match="no zip signature"):
        govulndb.download(govulndb.OFFICIAL_URL, tmp_path / "d.zip", 30)


def test_download_reports_http_errors(tmp_path, monkeypatch):
    import urllib.error

    def urlopen(request, timeout=None, context=None):
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    with pytest.raises(govulndb.GoDbError, match="HTTP 404"):
        govulndb.download("https://vuln.go.dev/vuln.zip", tmp_path / "a.zip", 30)

    def offline(request, timeout=None, context=None):
        raise urllib.error.URLError("getaddrinfo failed")

    monkeypatch.setattr(urllib.request, "urlopen", offline)
    with pytest.raises(govulndb.GoDbError, match="getaddrinfo failed"):
        govulndb.download(govulndb.OFFICIAL_URL, tmp_path / "b.zip", 30)


# --- vulndb.update ----------------------------------------------------------------------------


def test_vulndb_update_writes_the_go_part(tmp_path):
    root = tmp_path / "vulndb"
    fetch = fake_fetch(official_members())
    summary = vulndb.update(root, osv=False, grype=False, retire=False, fetch=fetch)
    assert summary["go"]["status"] == "ok" and summary["go"]["go_source"] == "official"
    assert summary["go"]["source"] == govulndb.OFFICIAL_URL
    assert vulndb.read_status(root)["go"]["modified"] == "2026-10-08T22:31:09Z"
    assert vulndb.go_db_info(root)["source"] == "official"
    assert vulndb.go_dir(root) == root / "go"
    kept = vulndb.update(root, osv=False, grype=False, go=False, retire=False)
    assert kept["go"]["go_source"] == "official"  # the last result stays in status.json
    with pytest.raises(ValueError, match="unknown Go database source"):
        vulndb.update(root, osv=False, grype=False, retire=False, go_source="mirror")
    fresh = vulndb.update(root, osv=False, grype=False, retire=False, fetch=failing_fetch)
    assert fresh["go"]["action"] == "kept"  # younger than 24 hours: no download
    built = vulndb.update(
        root, osv=False, grype=False, retire=False, go_source="osv", fetch=failing_fetch, force=True
    )
    assert built["go"]["status"] == "failed"  # no OSV Go archive yet
    assert built["go"]["downloaded_at"] == summary["go"]["downloaded_at"]  # the old one stays
    osv_zip(root)
    built = vulndb.update(
        root, osv=False, grype=False, retire=False, go_source="osv", fetch=failing_fetch, force=True
    )
    assert built["go"]["status"] == "ok" and built["go"]["go_source"] == "osv"


def test_download_names_the_fix_of_a_failed_certificate_check(tmp_path, monkeypatch):
    import urllib.error

    def untrusted(request, timeout=None, context=None):
        raise urllib.error.URLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")

    monkeypatch.setattr(urllib.request, "urlopen", untrusted)
    with pytest.raises(govulndb.GoDbError, match="SSL_CERT_FILE"):
        govulndb.download(govulndb.OFFICIAL_URL, tmp_path / "a.zip", 30)
