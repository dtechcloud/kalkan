# SPDX-License-Identifier: MIT
"""Tests for the Turkish letter restoration: the engine rules (kalkan.findings.polish), the step
``polish`` (kalkan.run.polish), the handler (kalkan.run.handlers.polish), the merge rule,
``run reopen --step polish`` and the compatibility with run states of older versions."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from kalkan import plugin_hook
from kalkan.cli import main
from kalkan.errors import StateError
from kalkan.findings.merge import merge_run, merged_records
from kalkan.findings.polish import (
    BATCH_SIZE,
    CODE_TOKEN_CHANGED,
    DUPLICATE_FIELD,
    FOLD_MISMATCH,
    UNCHANGED,
    UNKNOWN_FIELD,
    apply_corrections,
    candidate_text,
    check_correction,
    code_spans,
    fold,
    needs_polish,
    prose_fields,
    select_records,
)
from kalkan.findings.validate import validate_findings
from kalkan.run import budget, commands, events, ids, phases, prompts, queue, state, steps
from kalkan.run import init as init_mod
from kalkan.run.handlers import polish as handler
from kalkan.run.init import init_run
from kalkan.run.polish import BATCHES_NAME, EVENT_UNFUNDED, create_polish_tasks

ROOT = Path(__file__).resolve().parents[2]
PLAIN = "Kullanici kimligi dogrulanmadan `user_id` degeri sorguya ulasir."
RESTORED = "Kullanıcı kimliği doğrulanmadan `user_id` değeri sorguya ulaşır."
TITLE = "Dusuk yetkili kullanici baska hesabin verisine erisir"
TITLE_RESTORED = "Düşük yetkili kullanıcı başka hesabın verisine erişir"


@pytest.fixture
def make_run(tmp_path, monkeypatch):
    monkeypatch.setenv(ids.RUNS_DIR_ENV, str(tmp_path / "runs"))
    monkeypatch.setattr(init_mod, "git_head", lambda directory: None)
    target = tmp_path / "shop"
    (target / "app").mkdir(parents=True)
    (target / "app" / "users.py").write_text("def users():\n    return []\n", encoding="utf-8")

    def make(lang: str = "tr", profile: str = "standard"):
        run = init_run(str(target), runs_dir=tmp_path / "runs", profile=profile, lang=lang)
        with state.transaction(run) as tx:
            tx.state["phase"] = "validate"
        return run

    return make


@pytest.fixture
def ctx(make_run):
    return make_run()


def fid(number: int) -> str:
    return f"KF-{number:016X}"


def record(number, *, verdict="confirmed", overall="high", title=None, description=PLAIN):
    """Return a valid canonical finding whose title and description need the letters."""
    finding = {
        "verdict": verdict,
        "fingerprint": f"idor:app/users.py:line-{number}",
        "title": title or f"{TITLE} {number}",
        "description": description,
        "trace": [
            {
                "kind": "sink",
                "file": "app/users.py",
                "line": 2,
                "scope": "users",
                "description": "x",
            }
        ],
        "evidence": [{"file": "app/users.py", "line": 2, "description": "Sorgu satiri."}],
        "id": fid(number),
        "class": "idor",
        "cwe": [],
        "engines": ["hunter", "verifier"],
    }
    if verdict == "confirmed":
        finding.update(
            root_cause="Kok neden.",
            intended_behavior="Guvenli davranis.",
            conditions=[{"kind": "network_routing", "description": "Erisilebilir."}],
            execution={
                "attacker_perspective": "Bir istemci.",
                "payloads": ["kullanici=2"],
                "instructions": ["Istegi gonder."],
                "observed_result": "Yalnızca statik analiz (PoC çalışmadı): sorgu çalışır.",
            },
            remediation={"strategy": "Sahiplik ekle."},
            severity={
                "likelihood": {"score": "high", "reason": "Kolay."},
                "impact": {"score": overall, "reason": "Etki."},
                "overall_severity": overall,
            },
            confidence={"score": "medium", "reason": "Acik."},
        )
    elif verdict == "needs_validation":
        finding.update(
            claimed_root_cause="Iddia edilen neden.",
            blockers=["confirmed_fields_missing"],
            validation_plan={"local": "Yerel test."},
        )
    else:
        finding.update(claimed_root_cause="Iddia.", reason="Curutuldu.")
    assert validate_findings([finding]) == [], validate_findings([finding])
    return finding


def add_verified(ctx, finding) -> str:
    """Create a done verify task that holds ``finding`` and return its ID."""
    task_id = queue.create_task(ctx, "verify", "validate", {})
    write_finding(ctx, task_id, finding)
    with state.transaction(ctx) as tx:
        tx.state["tasks"][task_id]["status"] = "done"
    return task_id


def write_finding(ctx, task_id, finding):
    (ctx.task_dir(task_id) / "finding.json").write_text(json.dumps(finding), encoding="utf-8")


def polish_tasks(ctx):
    return [
        (task_id, queue.get_task(ctx, task_id))
        for task_id, task in ctx.reload()["tasks"].items()
        if task["type"] == "polish"
    ]


def task_input(ctx, task_id):
    return json.loads((ctx.task_dir(task_id) / "input.json").read_text(encoding="utf-8"))


def complete(ctx, task_id, records):
    result = {"task_id": task_id, "records": records}
    (ctx.task_dir(task_id) / "result.json").write_text(json.dumps(result), encoding="utf-8")
    return queue.complete(ctx, task_id)


def outcome_of(ctx, task_id):
    return json.loads((ctx.task_dir(task_id) / handler.OUTCOME_NAME).read_text("utf-8"))


def findings_by_id(ctx):
    data = json.loads((ctx.run_dir / "findings.json").read_text(encoding="utf-8"))
    return {item["id"]: item for item in data}


# ---------------------------------------------------------------------------------------------
# The letter check


def test_fold_maps_only_the_turkish_letters():
    assert fold("çğıöşü ÇĞİÖŞÜ") == "cgiosu CGIOSU"
    assert fold("é ß x-1 `a`") == "é ß x-1 `a`"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("Dusuk guvenli", "Düşük güvenli"),
        ("kullanici oturum kayitlari", "kullanıcı oturum kayıtları"),
        ("Istek sayisi icin bir sinir yok.", "İstek sayısı için bir sınır yok."),
        # a full stop is no code
        ("Kullanici odedigi tutari gorur.", "Kullanıcı ödediği tutarı görür."),
        ("Bir alan (kullanici) okunur: odeme", "Bir alan (kullanıcı) okunur: ödeme"),
        ("ve sonra (bkz. odeme akisi)", "ve sonra (bkz. ödeme akışı)"),
        (PLAIN, RESTORED),
    ],
)
def test_a_restoration_of_the_letters_is_accepted(old, new):
    assert check_correction(old, new) is None


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("Dusuk guvenli", "Düşük güvenlı!"),  # an added character
        ("Dusuk guvenli", "Düşük güvenlü"),  # i is never ü
        ("dusuk guvenli", "Düşük güvenli"),  # the case changed
        ("Dusuk guvenli", "Düşük  güvenli"),  # the spacing changed
        ("Dusuk guvenli", "Düşük güvenlié"),  # é is not a Turkish letter
        ("Dusuk guvenli", "Düşük güvenli bir"),  # a word added
        ("Dusuk guvenli", "Yüksek güvenli"),  # another word
    ],
)
def test_a_change_beyond_the_letters_is_a_fold_mismatch(old, new):
    assert check_correction(old, new) == FOLD_MISMATCH


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("Saldirgan `sifre` alanini okur", "Saldırgan `şifre` alanını okur"),  # backticks
        ("Kod ``a `sifre` b`` okunur", "Kod ``a `şifre` b`` okunur"),  # a longer backtick run
        ("Kapanmayan `sifre alani", "Kapanmayan `şifre alanı"),  # unmatched: the rest is code
        ("IsEmailVerified alani acik", "İsEmailVerified alanı açık"),  # camelCase
        ("kullaniciId alani acik", "kullanıcıId alanı açık"),  # an inner capital
        ("X-Forwarded-For basligi okunur", "X-Förwarded-For başlığı okunur"),  # a header name
        ("app/odeme.py dosyasi okunur", "app/ödeme.py dosyası okunur"),  # a path
        ("odeme_tutari alani okunur", "ödeme_tutarı alanı okunur"),  # snake_case
        ("dogrula() cagrisi yok", "doğrula() çağrısı yok"),  # a call
        ("kullanici2 hesabi acilir", "kullanıcı2 hesabı açılır"),  # a digit next to a letter
        ("sha256 ozeti tutulur", "şha256 özeti tutulur"),  # a digit next to a letter
        ("SQL'i calistirir", "SQL'ı çalıştırır"),  # an inner capital before a suffix
        ("Ayar KULLANICI_ADI okunur", "Ayar KULLANİCİ_ADİ okunur"),
        ("Deger $odeme olur", "Değer $ödeme olur"),
    ],
)
def test_a_changed_code_token_is_rejected(old, new):
    assert fold(old) == fold(new)  # the letters alone differ
    assert check_correction(old, new) == CODE_TOKEN_CHANGED


def test_code_tokens_stay_while_the_prose_around_them_changes():
    old = "IsEmailVerified ve X-Forwarded-For kontrolu `user_id` ile app/a.py:14 satirinda yok."
    new = "IsEmailVerified ve X-Forwarded-For kontrolü `user_id` ile app/a.py:14 satırında yok."
    assert check_correction(old, new) is None
    spans = [old[start:end] for start, end in code_spans(old)]
    assert spans == ["`user_id`", "IsEmailVerified", "X-Forwarded-For", "`user_id`", "app/a.py:14"]


def test_unchanged_text_is_rejected():
    assert check_correction(PLAIN, PLAIN) == UNCHANGED


def test_candidate_text_composes_combining_marks():
    assert candidate_text("Duşuk") == "Duşuk"
    assert check_correction("Dusuk", candidate_text("Düşük")) is None


# ---------------------------------------------------------------------------------------------
# Prose fields and selection


def test_needs_polish_threshold_and_turkish_letters():
    nineteen = "abcde fghij klmno pqrs"
    assert sum(ch.isalpha() for ch in nineteen) == 19
    assert not needs_polish(nineteen)
    assert needs_polish(nineteen + "t")
    assert not needs_polish("Kullanıcı odedigi tutari gorur ve fatura")  # one Turkish letter
    assert not needs_polish("confirmed_fields_missing")  # only code (22 letters)
    assert not needs_polish("unknown:attacker_control `request.user.id`")
    assert not needs_polish(None)


def test_prose_fields_use_stable_paths_and_skip_code():
    finding = record(1)
    finding["audit_answers"] = {
        key: {"status": "established", "reason": f"Gerekce {key}", "evidence": []}
        for key in ("attacker_control", "privilege_boundary", "unmitigated")
    }
    finding["review"] = {"decision": "verified", "reason": "Inceleme gerekcesi."}
    paths = [path for path, _ in prose_fields(finding)]
    assert paths == [
        "/title",
        "/description",
        "/root_cause",
        "/intended_behavior",
        "/trace/0/description",
        "/evidence/0/description",
        "/conditions/0/description",
        "/execution/attacker_perspective",
        "/execution/instructions/0",
        "/execution/observed_result",
        "/remediation/strategy",
        "/severity/likelihood/reason",
        "/severity/impact/reason",
        "/confidence/reason",
        "/audit_answers/attacker_control/reason",
        "/audit_answers/privilege_boundary/reason",
        "/audit_answers/unmitigated/reason",
        "/review/reason",
    ]
    pending = record(2, verdict="needs_validation")
    pending.update(duplicate_of=fid(1), duplicate_reason="Ayni kok neden ve ayni duzeltme.")
    paths = [path for path, _ in prose_fields(pending)]
    assert "/claimed_root_cause" in paths and "/blockers/0" in paths
    assert "/validation_plan/local" in paths and "/duplicate_reason" in paths
    assert not any("payloads" in path or "quote" in path or "scope" in path for path in paths)


def test_select_records_keeps_only_the_fields_that_need_letters():
    confirmed = record(5, overall="medium")
    folded = record(3, verdict="needs_validation")
    folded.update(duplicate_of=fid(5), duplicate_reason="Ayni kok neden ve ayni duzeltme.")
    done = record(4, title="Düşük güvenli agent", description=RESTORED)
    rejected = record(6, verdict="rejected")
    selected = select_records([folded, rejected, done, confirmed])
    assert [item["id"] for item in selected] == [fid(5), fid(3)]  # confirmed first
    assert selected[0]["title"] == confirmed["title"]
    assert [field["path"] for field in selected[0]["fields"]] == ["/title", "/description"]
    assert [field["path"] for field in selected[1]["fields"]] == [
        "/title",
        "/description",
        "/duplicate_reason",
    ]
    # A field that an earlier task showed to an agent is not selected again.
    skip = {(fid(5), "/title", confirmed["title"])}
    again = select_records([confirmed], skip)
    assert [field["path"] for field in again[0]["fields"]] == ["/description"]


# ---------------------------------------------------------------------------------------------
# The step


def test_the_step_creates_batches_of_eight_in_the_stable_order(ctx):
    numbers = {}
    for number in range(1, 18):
        verdict = "needs_validation" if number % 3 == 0 else "confirmed"
        overall = "critical" if number in (16, 17) else "high" if number % 2 else "low"
        numbers[number] = record(number, verdict=verdict, overall=overall)
        add_verified(ctx, numbers[number])
    summary = create_polish_tasks(ctx)
    assert summary == {
        "records": 17,
        "selected": 17,
        "fields": 34,
        "batches": 3,
        "created": 3,
        "reused": 0,
        "unfunded": 0,
    }
    tasks = polish_tasks(ctx)
    batches = [[item["id"] for item in task_input(ctx, t)["records"]] for t, _ in tasks]
    assert [len(batch) for batch in batches] == [BATCH_SIZE, BATCH_SIZE, 1]
    expected = sorted(
        numbers.values(),
        key=lambda f: (
            f["verdict"] != "confirmed",
            -{"critical": 4, "high": 3, "low": 1}.get(
                (f.get("severity") or {}).get("overall_severity"), -1
            ),
            f["id"],
        ),
    )
    assert [item for batch in batches for item in batch] == [f["id"] for f in expected]
    assert batches[0][:2] == [fid(16), fid(17)]  # the critical records first
    task_id, task = tasks[0]
    assert task["phase"] == "validate" and task["priority"] == 40
    assert task["meta"] == {"findings": batches[0], "fields": 16}
    assert task["dedupe_key"].startswith(f"polish:{' '.join(batches[0])} ")
    view = task_input(ctx, task_id)["records"][0]
    assert view == {
        "id": fid(16),
        "title": numbers[16]["title"],
        "fields": [
            {"path": "/title", "text": numbers[16]["title"]},
            {"path": "/description", "text": PLAIN},
        ],
    }
    prompt = (ctx.task_dir(task_id) / "prompt.md").read_text(encoding="utf-8")
    assert "## Task: restore the Turkish letters in finding texts" in prompt
    assert "#### Glossary" in prompt and "{{" not in prompt
    written = json.loads((ctx.run_dir / BATCHES_NAME).read_text(encoding="utf-8"))
    assert [entry["task"] for entry in written["batches"]] == [t for t, _ in tasks]
    # Idempotent: a second run reuses the tasks.
    again = create_polish_tasks(ctx)
    assert (again["created"], again["reused"]) == (0, 3)


def test_the_title_comes_for_context_when_only_another_field_needs_letters(ctx):
    add_verified(ctx, record(1, title="Kısa başlık"))
    create_polish_tasks(ctx)
    [(task_id, _)] = polish_tasks(ctx)
    [view] = task_input(ctx, task_id)["records"]
    assert view["title"] == "Kısa başlık"
    assert [field["path"] for field in view["fields"]] == ["/description"]


def test_a_non_turkish_run_is_done_without_tasks(make_run):
    run = make_run(lang="en")
    add_verified(run, record(1))
    with state.transaction(run) as tx:
        tx.state["phases"]["validate"]["status"] = "running"
        tx.state["phases"]["validate"]["steps"] = {
            budget.REVIEW_STEP: {"status": "done", "detail": ""},
            budget.CONSOLIDATE_STEP: {"status": "done", "detail": ""},
            budget.POLISH_STEP: {"status": "pending", "detail": ""},
        }
    outcome = steps.run_step(run)
    assert (outcome["step"], outcome["status"]) == ("polish", "done")
    assert outcome["detail"] == "not a Turkish run"
    assert polish_tasks(run) == []
    assert phases.next_action(run, "orchestrator")["phase"] == "poc"


def test_without_budget_the_step_is_skipped_and_never_blocks(ctx):
    add_verified(ctx, record(1))
    with state.transaction(ctx) as tx:
        tx.state["budget"]["used_agent_tasks"] = tx.state["budget"]["max_agent_tasks"]
        tx.state["phases"]["validate"]["status"] = "running"
        tx.state["phases"]["validate"]["steps"] = {
            budget.REVIEW_STEP: {"status": "done", "detail": ""},
            budget.CONSOLIDATE_STEP: {"status": "done", "detail": ""},
            budget.POLISH_STEP: {"status": "pending", "detail": ""},
        }
    outcome = steps.run_step(ctx)
    assert outcome["status"] == "skipped"
    assert outcome["detail"] == "no budget: 1 polish batches (1 records) keep their text"
    assert polish_tasks(ctx) == []
    current = ctx.reload()
    assert current.get("incomplete_pending") is None
    assert any(e["kind"] == EVENT_UNFUNDED for e in events.read_events(ctx.run_dir))
    written = json.loads((ctx.run_dir / BATCHES_NAME).read_text(encoding="utf-8"))
    assert written["unfunded"] == 1 and written["batches"][0]["task"] is None
    assert phases.next_action(ctx, "orchestrator")["phase"] == "poc"


def test_polish_uses_what_is_left_of_the_validation_reserve(ctx):
    state_now = ctx.reload()
    assert "polish" in budget.VALIDATION_TASK_TYPES
    assert budget.available(state_now, "polish") == budget.available(state_now, "consolidate")


# ---------------------------------------------------------------------------------------------
# The handler and merge


def polished_run(ctx):
    """One record: the title and the description need the letters; one polish task."""
    add_verified(ctx, record(1, title=TITLE))
    create_polish_tasks(ctx)
    [(task_id, _)] = polish_tasks(ctx)
    return task_id


def test_the_handler_accepts_only_the_letters_and_lists_every_rejection(ctx):
    task_id = polished_run(ctx)
    records = [
        {
            "id": fid(1),
            "fields": [
                {"path": "/title", "text": TITLE_RESTORED},
                {"path": "/title", "text": TITLE_RESTORED},  # named twice
                {"path": "/description", "text": RESTORED.replace("user_id", "user_ıd")},
                {"path": "/root_cause", "text": "Kök neden."},  # not an input field
            ],
        },
        {"id": fid(9), "fields": [{"path": "/title", "text": "Başka kayıt"}]},
    ]
    assert complete(ctx, task_id, records)["status"] == "done"  # rejections never fail it
    outcome = outcome_of(ctx, task_id)
    assert outcome == {
        "task_id": task_id,
        "applied": [{"id": fid(1), "path": "/title", "old": TITLE, "new": TITLE_RESTORED}],
        "rejected": [
            {"id": fid(1), "path": "/title", "reason": DUPLICATE_FIELD},
            {"id": fid(1), "path": "/description", "reason": CODE_TOKEN_CHANGED},
            {"id": fid(1), "path": "/root_cause", "reason": UNKNOWN_FIELD},
            {"id": fid(9), "path": "/title", "reason": UNKNOWN_FIELD},
        ],
    }


def test_the_handler_rejects_fold_mismatches_and_unchanged_texts(ctx):
    task_id = polished_run(ctx)
    records = [
        {
            "id": fid(1),
            "fields": [
                {"path": "/title", "text": TITLE_RESTORED + "."},
                {"path": "/description", "text": PLAIN},
            ],
        }
    ]
    complete(ctx, task_id, records)
    outcome = outcome_of(ctx, task_id)
    assert outcome["applied"] == []
    assert [item["reason"] for item in outcome["rejected"]] == [FOLD_MISMATCH, UNCHANGED]
    summary = merge_run(ctx.run_dir)
    assert summary["polish_applied"] == 0
    assert findings_by_id(ctx)[fid(1)]["title"] == TITLE


def test_merge_applies_the_corrections_and_keeps_ids_and_quotes(ctx):
    task_id = polished_run(ctx)
    before = merged_records(ctx.run_dir, fold=True)[0]
    complete(
        ctx,
        task_id,
        [
            {
                "id": fid(1),
                "fields": [
                    {"path": "/title", "text": TITLE_RESTORED},
                    {"path": "/description", "text": RESTORED},
                ],
            }
        ],
    )
    summary = merge_run(ctx.run_dir)
    assert summary["polish_applied"] == 2 and summary["inputs"]["polish_files"] == 1
    found = findings_by_id(ctx)[fid(1)]
    assert found["title"] == TITLE_RESTORED and found["description"] == RESTORED
    for key in ("id", "fingerprint", "verdict", "evidence", "trace", "severity"):
        assert found[key] == before[key]
    # merged_records without folding gives the records before the corrections.
    assert merged_records(ctx.run_dir)[0]["title"] == TITLE
    # The step selects nothing again: the fields now hold Turkish letters.
    assert create_polish_tasks(ctx)["batches"] == 0


def test_merge_skips_a_correction_whose_field_changed(ctx):
    task_id = polished_run(ctx)
    complete(ctx, task_id, [{"id": fid(1), "fields": [{"path": "/title", "text": TITLE_RESTORED}]}])
    verify_task = next(t for t, task in ctx.reload()["tasks"].items() if task["type"] == "verify")
    write_finding(ctx, verify_task, record(1, title=TITLE + " yeni"))
    summary = merge_run(ctx.run_dir)
    assert summary["polish_applied"] == 0
    assert any("changed after the polish task" in item for item in summary["warnings"])
    assert findings_by_id(ctx)[fid(1)]["title"] == TITLE + " yeni"


def test_apply_corrections_guards_paths_and_updates_related_titles():
    primary = record(1, title="Birincil kayit basligi burada")
    duplicate = record(2, title=TITLE)
    duplicate.update(duplicate_of=fid(1), duplicate_reason="Ayni kok neden ve ayni duzeltme.")
    primary["related"] = [
        {"id": fid(2), "title": TITLE, "class": "idor", "reason": "Ayni kok neden."}
    ]
    findings = [primary, duplicate]
    corrections = [
        ("a", {"id": fid(2), "path": "/title", "old": TITLE, "new": TITLE_RESTORED}),
        ("b", {"id": fid(2), "path": "/fingerprint", "old": "x", "new": "y"}),  # not prose
        ("c", {"id": fid(2), "path": "/title", "old": TITLE, "new": TITLE_RESTORED}),  # stale
        ("d", {"id": fid(1), "path": "/description", "old": PLAIN, "new": "başka metin"}),
        ("e", {"id": fid(7), "path": "/title", "old": TITLE, "new": TITLE_RESTORED}),
        ("f", {"id": fid(1), "path": "/title"}),
    ]
    stats = apply_corrections(findings, corrections, check=lambda item: validate_findings([item]))
    assert (stats.applied, stats.skipped) == (1, 5)
    assert duplicate["title"] == TITLE_RESTORED
    assert primary["related"][0]["title"] == TITLE_RESTORED  # the copy follows
    assert duplicate["fingerprint"] == "idor:app/users.py:line-2"
    assert [item.split(":", 1)[0] for item in stats.warnings] == ["b", "c", "d", "e", "f"]
    assert "fold_mismatch" in stats.warnings[2]


def test_a_correction_that_breaks_the_record_is_undone():
    finding = record(1, title=TITLE)
    corrections = [("a", {"id": fid(1), "path": "/title", "old": TITLE, "new": TITLE_RESTORED})]
    stats = apply_corrections([finding], corrections, check=lambda item: ["invalid on purpose"])
    assert (stats.applied, stats.skipped) == (0, 1)
    assert finding["title"] == TITLE
    assert "invalid on purpose" in stats.warnings[0]


def test_a_reopened_step_does_not_ask_twice(ctx):
    task_id = polished_run(ctx)
    complete(ctx, task_id, [])  # the agent saw nothing to restore
    again = create_polish_tasks(ctx)
    assert again["batches"] == 0 and len(polish_tasks(ctx)) == 1


# ---------------------------------------------------------------------------------------------
# The phase: order, run reopen and older run states


def finish(ctx, validate_steps):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "done"
        for name in ("validate", "poc", "merge", "report", "done"):
            tx.state["phases"][name].update(
                status="done", started_at=ids.format_ts(), finished_at=ids.format_ts()
            )
        tx.state["phases"]["validate"]["steps"] = {
            name: {"status": "done", "detail": ""} for name in validate_steps
        }
        tx.state["phases"]["merge"]["steps"] = {"merge": {"status": "done", "detail": ""}}
        tx.state["phases"]["report"]["steps"] = {"report:tr": {"status": "done", "detail": ""}}
        tx.state["answers"] = {"english_report": "no"}


ALL_STEPS = (budget.REVIEW_STEP, budget.CONSOLIDATE_STEP, budget.POLISH_STEP)


def validate_steps(ctx):
    return {
        name: item["status"] for name, item in ctx.reload()["phases"]["validate"]["steps"].items()
    }


def test_a_new_validate_phase_lists_polish_last(ctx):
    phases.ensure_entered(ctx)
    assert list(validate_steps(ctx)) == list(ALL_STEPS)
    assert phases.VALIDATE_STEPS == ALL_STEPS
    assert commands.REOPEN_STEP_CHOICES == phases.REOPEN_STEPS


def test_quick_runs_polish_after_its_last_validation_step(make_run):
    run = make_run(profile="fast")
    phases.ensure_entered(run)
    assert validate_steps(run) == {
        budget.REVIEW_STEP: "skipped",
        budget.CONSOLIDATE_STEP: "pending",
        budget.POLISH_STEP: "pending",
    }


def test_reopen_polish_moves_a_finished_run_back_and_is_idempotent(ctx):
    finish(ctx, ALL_STEPS)
    outcome = phases.reopen(ctx, "polish")
    assert outcome == {
        "run_id": ctx.run_id,
        "step": "polish",
        "previous_phase": "done",
        "phase": "validate",
        "reopened": True,
    }
    current = ctx.reload()
    assert current["phases"]["validate"]["status"] == "running"
    assert validate_steps(ctx) == {
        budget.REVIEW_STEP: "done",
        budget.CONSOLIDATE_STEP: "done",  # polish alone runs again
        budget.POLISH_STEP: "pending",
    }
    for later in ("poc", "merge", "report", "done"):
        assert current["phases"][later]["status"] == "pending"
        assert current["phases"][later]["steps"] == {}
    assert current["answers"] == {"english_report": "no"}
    again = phases.reopen(ctx, "polish")
    assert again["reopened"] is False and again["previous_phase"] == "validate"
    assert ctx.reload() == current
    assert phases.next_action(ctx, "orchestrator") == {
        "kind": "engine_step",
        "phase": "validate",
        "step": "polish",
    }
    reopened = [e for e in events.read_events(ctx.run_dir) if e["kind"] == "run_reopened"]
    assert [(e["step"], e["previous_phase"]) for e in reopened] == [("polish", "done")]


def test_reopen_consolidate_also_puts_back_polish(ctx):
    finish(ctx, ALL_STEPS)
    phases.reopen(ctx, "consolidate")
    assert validate_steps(ctx) == {
        budget.REVIEW_STEP: "done",
        budget.CONSOLIDATE_STEP: "pending",
        budget.POLISH_STEP: "pending",
    }


def test_reopen_polish_on_an_older_state_adds_the_step_in_its_place(ctx):
    finish(ctx, (budget.REVIEW_STEP, budget.CONSOLIDATE_STEP))
    phases.reopen(ctx, "polish")
    assert list(validate_steps(ctx)) == list(ALL_STEPS)
    # A state from before the consolidation step: consolidate comes back before polish.
    finish(ctx, (budget.REVIEW_STEP,))
    phases.reopen(ctx, "polish")
    assert list(validate_steps(ctx)) == [budget.REVIEW_STEP, budget.POLISH_STEP]
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "validate", "step": "consolidate"}
    assert list(validate_steps(ctx)) == list(ALL_STEPS)


def test_reopen_polish_refuses_while_a_task_is_leased(ctx):
    finish(ctx, ALL_STEPS)
    task_id = queue.create_task(ctx, "verify", "validate", {})
    queue.claim(ctx, "worker", 1, phases=["validate"])
    with pytest.raises(StateError, match="tasks are leased"):
        phases.reopen(ctx, "polish")
    assert ctx.reload()["phase"] == "done"
    queue.release(ctx, task_id)
    assert phases.reopen(ctx, "polish")["reopened"] is True


def test_run_reopen_command_accepts_polish(ctx, capsys):
    finish(ctx, ALL_STEPS)
    code = main(["run", "reopen", "--run", ctx.run_id, "--step", "polish", "--json"])
    output = json.loads(capsys.readouterr().out)
    assert code == 0 and output["reopened"] is True and output["step"] == "polish"
    code = main(["run", "reopen", "--run", ctx.run_id, "--step", "polish"])
    assert code == 0 and "Nothing to reopen" in capsys.readouterr().err


def test_an_older_run_in_validate_gets_the_polish_step(ctx):
    with state.transaction(ctx) as tx:
        tx.state["phases"]["validate"]["status"] = "running"
        tx.state["phases"]["validate"]["steps"] = {
            budget.REVIEW_STEP: {"status": "done", "detail": ""},
            budget.CONSOLIDATE_STEP: {"status": "done", "detail": ""},
        }
    action = phases.next_action(ctx, "orchestrator")
    assert action == {"kind": "engine_step", "phase": "validate", "step": "polish"}
    added = [e for e in events.read_events(ctx.run_dir) if e["kind"] == "step_added"]
    assert [(e["step"], e["reason"]) for e in added] == [("polish", "older run state")]


def test_an_older_run_after_validate_is_not_changed(ctx):
    with state.transaction(ctx) as tx:
        tx.state["phase"] = "poc"
        tx.state["phases"]["validate"].update(status="done")
        tx.state["phases"]["validate"]["steps"] = {
            budget.REVIEW_STEP: {"status": "done", "detail": ""},
            budget.CONSOLIDATE_STEP: {"status": "done", "detail": ""},
        }
    assert phases.next_action(ctx, "orchestrator")["phase"] == "poc"
    assert budget.POLISH_STEP not in validate_steps(ctx)


# ---------------------------------------------------------------------------------------------
# Prompt, agent and hook


def test_the_prompt_examples_pass_the_engine_check(ctx):
    text = prompts.template("polish")
    rows = re.findall(r"^\| `([^`]+)` \| `([^`]+)` \|$", text, flags=re.MULTILINE)
    examples = [(old, new) for old, new in rows if fold(new) == fold(old) and old != new]
    assert len(examples) >= 4
    for old, new in examples:
        assert check_correction(old, new) is None, (old, new)
    rendered = prompts.render(ctx, "polish", "T0001-polish", {"records": []})
    assert set(re.findall(r"\{\{([A-Z_]+)\}\}", rendered)) == set()
    assert "#### Glossary" in rendered


def test_the_polisher_agent_files_exist():
    for folder in (".claude/agents", "plugins/kalkan/agents"):
        text = (ROOT / folder / "kalkan-polisher.md").read_text(encoding="utf-8")
        assert "tools: Read, Write\n" in text
        assert "Grep, Glob" in text.split("disallowedTools:", 1)[1].split("\n", 1)[0]
        assert "model:" not in text
    assert (ROOT / ".codex" / "agents" / "kalkan-polisher.toml").is_file()
    assert queue.AGENTS["polish"] == "kalkan-polisher"
    assert "kalkan-polisher" in plugin_hook.AGENT_NAMES
    assert plugin_hook._TASK_ID.fullmatch("T0042-polish")
