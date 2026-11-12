# SPDX-License-Identifier: MIT
"""Tests for kalkan.report.sbom: the joined SBOM deliverables report/sbom.cdx.json (CycloneDX
1.6) and report/sbom.spdx.json (SPDX 2.3)."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from kalkan.cli import main
from kalkan.report import sbom
from kalkan.report.commands import parse_formats, write_report
from kalkan.report.model import build_model

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "report"
RUN_ID = "20261015T120000Z-shop-a1b2"
GENERATED_AT = "2026-10-15T12:30:00Z"


@pytest.fixture
def run(tmp_path, monkeypatch) -> Path:
    shutil.copytree(GOLDEN / "run" / RUN_ID, tmp_path / RUN_ID)
    monkeypatch.setenv("KALKAN_RUNS_DIR", str(tmp_path))
    return tmp_path / RUN_ID


def model_of(run: Path):
    return build_model(run, generated_at=GENERATED_AT, installed_tools=GOLDEN / "installed.json")


def write_json(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def component(name: str, version: str, purl: str, *locations: str, **extra) -> dict:
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "properties": [
            {"name": f"syft:location:{index}:path", "value": value}
            for index, value in enumerate(locations)
        ],
        **extra,
    }


def test_the_sample_run_gives_both_documents_without_secrets(run):
    model = model_of(run)
    written = write_report(run, model, lang="tr", formats=["sbom"])
    assert [path.name for path in written] == ["sbom.cdx.json", "sbom.spdx.json"]
    texts = [path.read_text(encoding="utf-8") for path in written]
    for text in texts:
        for secret in ("s3cr3t", "build:", "someone", "C:/", "outside", "/projects", "../"):
            assert secret not in text, secret
    cyclonedx, spdx = (json.loads(text) for text in texts)
    assert cyclonedx["bomFormat"] == "CycloneDX" and cyclonedx["specVersion"] == "1.6"
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", cyclonedx["serialNumber"])
    purls = [item.get("purl") for item in cyclonedx["components"]]
    assert purls == [
        "pkg:npm/jquery@1.12.4",
        "pkg:npm/lodash@4.17.15",
        "pkg:pypi/flask@3.0.0",
        "pkg:pypi/pyyaml@5.3",
        "pkg:pypi/requests@2.19.0",
    ]
    jquery = cyclonedx["components"][0]
    assert jquery["evidence"] == {"occurrences": [{"location": "web/static/js/jquery.min.js"}]}
    assert {"name": "kalkan:source", "value": "vendored"} in jquery["properties"]
    assert {"name": "kalkan:vendored:library", "value": "jquery"} in jquery["properties"]
    metadata = cyclonedx["metadata"]
    assert metadata["component"] == {
        "type": "application",
        "bom-ref": "kalkan:target",
        "name": "shop",
    }
    assert {"name": "kalkan:run-id", "value": RUN_ID} in metadata["properties"]
    assert [tool["name"] for tool in metadata["tools"]["components"]] == [
        "kalkan",
        "syft",
        "RetireJS jsrepository-v5",
    ]
    assert spdx["spdxVersion"] == "SPDX-2.3" and spdx["dataLicense"] == "CC0-1.0"
    assert spdx["creationInfo"]["creators"][1] == "Tool: syft-1.54.0"
    assert spdx["documentNamespace"].startswith(f"https://kalkan.invalid/spdx/{RUN_ID}-")


def test_spdx_packages_and_relationships_follow_the_specification(run):
    model = model_of(run)
    document = sbom.spdx(model, model.sbom)
    identifiers = [package["SPDXID"] for package in document["packages"]]
    assert len(identifiers) == len(set(identifiers)) == 6
    assert all(re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", value) for value in identifiers)
    for package in document["packages"]:
        assert package["name"] and package["downloadLocation"] == "NOASSERTION"
        assert package["filesAnalyzed"] is False
        assert package["copyrightText"] == "NOASSERTION"
    relationships = document["relationships"]
    assert relationships[0] == {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Target",
    }
    assert sorted(item["relatedSpdxElement"] for item in relationships[1:]) == sorted(
        identifiers[1:]
    )
    declared = {package["name"]: package["licenseDeclared"] for package in document["packages"]}
    assert declared["pyyaml"] == "MIT" and declared["requests"] == "Apache-2.0"
    assert declared["flask"] == "NOASSERTION"
    requests = next(package for package in document["packages"] if package["name"] == "requests")
    assert requests["checksums"][0]["algorithm"] == "SHA256"
    flask = next(package for package in document["packages"] if package["name"] == "flask")
    assert flask["externalRefs"] == [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:pypi/flask@3.0.0",
        },
        {
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:2.3:a:palletsprojects:flask:3.0.0:*:*:*:*:python:*:*",
        },
    ]
    assert sbom.spdx(model, model.sbom) == document  # deterministic


def test_components_join_by_package_identity_across_sources(tmp_path):
    run = tmp_path / "run"
    target = run / "target"
    (target / "lib").mkdir(parents=True)
    (target / "package-lock.json").write_text("{}", encoding="utf-8")
    (target / "requirements.txt").write_text("PyYAML==5.3.0\n", encoding="utf-8")
    syft = {
        "bomFormat": "CycloneDX",
        "metadata": {"tools": {"components": [{"name": "syft", "version": "1.54.0"}]}},
        "components": [
            component("jquery", "1.12.4", "pkg:npm/jquery@1.12.4", "/package-lock.json"),
            component("PyYAML", "5.3.0", "pkg:pypi/PyYAML@5.3.0", "/requirements.txt"),
            component("x", "1.0", "pkg:npm/x@1.0?repository_url=https://u:p@h/&type=tgz#sub/path"),
            {"type": "file", "name": "/requirements.txt", "version": "1"},
            {"type": "library", "name": "no-version"},
            component(
                "lic",
                "2.0",
                "",
                licenses=[
                    {"license": {"id": "MIT"}},
                    {"license": {"id": "Apache-2.0"}},
                    {"license": {"name": "Custom License"}},
                    {"expression": "MIT OR (BAD"},
                ],
            ),
        ],
    }
    write_json(run / "sca" / "sbom.cdx.json", syft)
    pins = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "pyyaml",
                "version": "5.3",
                "purl": "pkg:pypi/pyyaml@5.3",
                "properties": [{"name": "kalkan:manifest:path", "value": "Pipfile"}],
            },
            {
                "type": "library",
                "name": "jquery",
                "version": "1.12.4",
                "purl": "pkg:npm/jquery@1.12.4",
                "properties": [
                    {"name": "kalkan:vendored:path", "value": "lib/jquery.js"},
                    {"name": "kalkan:vendored:path", "value": "/abs/outside.js"},
                    {"name": "kalkan:vendored:library", "value": "jquery"},
                ],
            },
        ],
    }
    write_json(run / "sca" / "manifest-pins.cdx.json", pins)
    inventory = sbom.collect(run, target)
    assert inventory is not None and inventory.producer == ("syft", "1.54.0")
    by_name = {item.name: item for item in inventory.components}
    assert set(by_name) == {"jquery", "PyYAML", "x", "lic"}
    jquery = by_name["jquery"]
    assert jquery.sources == ["syft", "vendored"]
    assert jquery.locations == ["package-lock.json", "lib/jquery.js"]
    assert jquery.libraries == ["jquery"]
    pyyaml = by_name["PyYAML"]  # PEP 503 name and PEP 440 version join the pin
    assert pyyaml.sources == ["syft", "manifest-pin"]
    assert pyyaml.locations == ["requirements.txt", "Pipfile"]
    assert by_name["x"].purl == "pkg:npm/x@1.0?type=tgz#sub/path"
    lic = by_name["lic"]
    assert lic.licenses == [
        {"license": {"id": "MIT"}},
        {"license": {"id": "Apache-2.0"}},
        {"license": {"name": "Custom License"}},
    ]
    assert inventory.by_source() == {"syft": 4, "manifest-pin": 1, "vendored": 1}


def test_a_trivy_sbom_and_missing_inputs(tmp_path):
    run = tmp_path / "run"
    target = run / "target"
    target.mkdir(parents=True)
    (target / "go.mod").write_text("module x\n", encoding="utf-8")
    assert sbom.collect(run, target) is None  # no input at all
    trivy = {
        "bomFormat": "CycloneDX",
        "metadata": {"tools": {"components": [{"name": "trivy", "version": "0.75.0"}]}},
        "components": [
            {
                "type": "library",
                "name": "golang.org/x/text",
                "version": "v0.3.7",
                "purl": "pkg:golang/golang.org/x/text@v0.3.7",
                "properties": [{"name": "aquasecurity:trivy:FilePath", "value": "go.mod"}],
            }
        ],
    }
    write_json(run / "sca" / "sbom.cdx.json", trivy)
    (run / "sca" / "vendored.json").write_text("{broken", encoding="utf-8")
    inventory = sbom.collect(run, target)
    assert inventory is not None and inventory.producer == ("trivy", "0.75.0")
    [item] = inventory.components
    assert item.sources == ["trivy"] and item.locations == ["go.mod"]
    assert any("sca/vendored.json: not JSON" in warning for warning in inventory.warnings)


@pytest.mark.parametrize(
    ("source", "kind", "expected"),
    [
        ("C:/projects/shop", "path", ("shop", "shop")),
        ("C:\\Users\\a\\repos\\api\\", "path", ("api", "api")),
        ("/home/a/src/web", "path", ("web", "web")),
        (
            "https://user:token@github.com/org/repo.git?x=1#frag",
            "git",
            ("repo", "https://github.com/org/repo.git"),
        ),
        ("git@github.com:org/tool.git", "git", ("tool", "tool")),
        ("", "", ("target", "target")),
    ],
)
def test_the_target_never_shows_a_secret_or_a_local_path(source, kind, expected):
    assert sbom.target_label(source, kind) == expected


def test_the_sbom_format_and_the_outputs_lists(run, capsys):
    assert parse_formats("sbom, md") == ["md", "sbom"]
    assert main(["report", "--run", RUN_ID, "--formats", "sbom"]) == 0
    report = run / "report"
    assert sorted(path.name for path in report.iterdir()) == ["sbom.cdx.json", "sbom.spdx.json"]
    assert "wrote report/sbom.cdx.json" in capsys.readouterr().err
    assert main(["report", "--run", RUN_ID, "--formats", "md,exec,json"]) == 0
    text = (report / "REPORT.md").read_text(encoding="utf-8")
    assert "SBOM: `report/sbom.cdx.json` (CycloneDX 1.6)" in text
    assert "`sbom.spdx.json`" in text.split("Rapor dosyaları")[1]
    page = (report / "EXECUTIVE.html").read_text(encoding="utf-8")
    assert "<code>sbom.cdx.json</code> (CycloneDX 1.6)" in page and ">Çıktılar<" in page
    summary = json.loads((report / "summary.json").read_text(encoding="utf-8"))
    assert summary["paths"]["sbom_spdx"] == "report/sbom.spdx.json"


def test_a_run_without_sbom_inputs_writes_no_sbom(run):
    for name in ("sbom.cdx.json", "manifest-pins.cdx.json", "vendored.json"):
        (run / "sca" / name).unlink()
    model = model_of(run)
    assert model.sbom is None
    written = write_report(run, model, lang="tr")
    assert not any(path.name.startswith("sbom.") for path in written)
    summary = json.loads((run / "report" / "summary.json").read_text(encoding="utf-8"))
    assert "sbom_cyclonedx" not in summary["paths"] and summary["sbom"] is None
    assert "SBOM:" not in (run / "report" / "REPORT.md").read_text(encoding="utf-8")
