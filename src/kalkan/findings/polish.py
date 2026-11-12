# SPDX-License-Identifier: MIT
"""Turkish letter restoration of the final records (docs/PHASES.md sections 3 and 4,
docs/ENGINE-SPEC.md sections 15 and 18).

Some agents write Turkish prose without the Turkish letters: "kullanici" for "kullanıcı", "Dusuk
guvenli" for "Düşük güvenli". A program cannot restore them, because one ASCII spelling can stand
for several words ("sinir" is "sinir" (nerve) or "sınır" (limit)). So a ``polish`` agent restores
the letters, and the engine makes sure that the agent changed nothing else. This module holds
the engine rules; it never reads run state.

Prose fields (:func:`prose_fields`), in this order, each addressed by a path in JSON-pointer form
(``/severity/impact/reason``, ``/trace/2/description``): ``/title``, ``/description``,
``/root_cause``, ``/claimed_root_cause``, ``/intended_behavior``, ``/trace/<n>/description``,
``/evidence/<n>/description``, ``/conditions/<n>/description``,
``/execution/attacker_perspective``, ``/execution/instructions/<n>``,
``/execution/observed_result``, ``/remediation/strategy``, ``/severity/likelihood/reason``,
``/severity/impact/reason``, ``/confidence/reason``, ``/blockers/<n>``,
``/validation_plan/local``, ``/validation_plan/deployment``, ``/audit_answers/<key>/reason``
(``attacker_control``, ``privilege_boundary``, ``unmitigated``), ``/review/reason``,
``/duplicate_reason`` and ``/related/<n>/reason``. Ids, fingerprints, verdicts, classes,
scopes, file names, quotes, payloads (``/execution/payloads``), code changes
(``/remediation/code_changes``) and the English ``i18n`` texts are never prose fields.

Records (:func:`eligible`): ``confirmed`` and ``needs_validation`` records with a ``KF-`` id,
folded duplicates included; rejected records never take part.

Selection (:func:`needs_polish`): a field needs the letters when it has at least
:data:`MIN_LETTERS` letters, none of :data:`TURKISH_LETTERS`, and at least one letter outside
the code tokens (a field that is only code, for example the engine blocker
``confirmed_fields_missing``, has nothing to restore). :func:`select_records` lists the records
with at least one such field, confirmed records first, then by overall severity, then by id;
:func:`make_batches` cuts them into batches of at most :data:`BATCH_SIZE` records.

Code tokens (:func:`code_spans`), in the old and in the new text:

1. everything between a backtick run and the next run of the same length (an unmatched run
   makes the rest of the text code);
2. every whitespace-separated token whose core (the token without leading ``"'“‘«(`` and
   trailing ``.,;:!?…"'”’»)``, so that the full stop of a sentence is no code) contains one of
   :data:`CODE_CHARACTERS`, a digit next to a letter, or an uppercase letter after its first
   character (``IsEmailVerified``, ``X-Forwarded-For``, ``SQL'i``).

Correction check (:func:`check_correction`), in this order: the new text differs from the old
one (else :data:`UNCHANGED`); :func:`fold` of both texts is equal, so only the Turkish letters
can differ and the length and every other character stay (else :data:`FOLD_MISMATCH`); every
code token is byte-identical (else :data:`CODE_TOKEN_CHANGED`). The handler compares the NFC
form of the new text (:func:`candidate_text`), so a letter with a combining mark counts as the
letter.

Applying (:func:`apply_corrections`): every correction names a record id and a path of
:func:`prose_fields` of that record; it applies only when the field still holds the old text and
the check still passes. A ``/title`` correction also updates the ``related[].title`` copies of
that title. With ``check``, a record that the corrections make invalid gets its old fields back.
"""

from __future__ import annotations

import copy
import re
import unicodedata
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from kalkan.findings.consolidate import severity_rank

__all__ = [
    "ANSWER_KEYS",
    "BATCH_SIZE",
    "CODE_CHARACTERS",
    "CODE_TOKEN_CHANGED",
    "DUPLICATE_FIELD",
    "ELIGIBLE_VERDICTS",
    "FOLD_MISMATCH",
    "MIN_LETTERS",
    "REJECT_REASONS",
    "TURKISH_LETTERS",
    "UNCHANGED",
    "UNKNOWN_FIELD",
    "PolishStats",
    "apply_corrections",
    "batch_order",
    "candidate_text",
    "check_correction",
    "code_spans",
    "eligible",
    "fold",
    "make_batches",
    "needs_polish",
    "prose_fields",
    "prose_letters",
    "select_records",
]

#: The letters that Turkish has and ASCII lacks.
TURKISH_LETTERS: Final = "çğıöşüÇĞİÖŞÜ"
_FOLD_TABLE: Final = str.maketrans(TURKISH_LETTERS, "cgiosuCGIOSU")
#: A field with fewer letters is too short to judge (an English word, a code, a name).
MIN_LETTERS: Final = 20
#: The most records in one ``polish`` task.
BATCH_SIZE: Final = 8
ELIGIBLE_VERDICTS: Final = ("confirmed", "needs_validation")
ANSWER_KEYS: Final = ("attacker_control", "privilege_boundary", "unmitigated")
#: A token core with one of these characters is code. The task contract names
#: ``_ . / \\ ( ) [ ] { } < > = : # $``; ``@ % & | * + ~ ^ ;`` are code in prose too
#: (``user@host``, ``%s``, ``a&&b``, ``*args``, ``C++``).
CODE_CHARACTERS: Final = frozenset("_./\\()[]{}<>=:#$@%&|*+~^;")
#: Reasons why the handler rejects a returned field (``polish.json`` ``rejected[].reason``).
FOLD_MISMATCH: Final = "fold_mismatch"
CODE_TOKEN_CHANGED: Final = "code_token_changed"
UNKNOWN_FIELD: Final = "unknown_field"
UNCHANGED: Final = "unchanged"
#: A field that the result names a second time (only the first one counts).
DUPLICATE_FIELD: Final = "duplicate_field"
REJECT_REASONS: Final = (
    FOLD_MISMATCH,
    CODE_TOKEN_CHANGED,
    UNKNOWN_FIELD,
    UNCHANGED,
    DUPLICATE_FIELD,
)
_OPENING: Final = "\"'“‘«("
_CLOSING: Final = ".,;:!?…\"'”’»)"
_TOKEN: Final = re.compile(r"\S+")
_BACKTICKS: Final = re.compile(r"`+")
_DIGIT_LETTER: Final = re.compile(r"[^\W\d_]\d|\d[^\W\d_]")
_VERDICT_RANK: Final = {"confirmed": 2, "needs_validation": 1}


def fold(text: str) -> str:
    """Return ``text`` with every Turkish letter replaced by its ASCII base letter
    (``ç`` → ``c``, ``ı`` → ``i``, ``İ`` → ``I`` …); every other character stays."""
    return text.translate(_FOLD_TABLE)


def candidate_text(text: str) -> str:
    """Return the NFC form of an agent text (``s`` plus a combining cedilla becomes ``ş``)."""
    return unicodedata.normalize("NFC", text)


# ---------------------------------------------------------------------------------------------
# Code tokens


def _backtick_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    position = 0
    while True:
        opening = _BACKTICKS.search(text, position)
        if opening is None:
            return spans
        fence = opening.group()
        closing = re.compile(r"(?<!`)" + fence + r"(?!`)").search(text, opening.end())
        if closing is None:
            spans.append((opening.start(), len(text)))
            return spans
        spans.append((opening.start(), closing.end()))
        position = closing.end()


def _is_code(token: str) -> bool:
    core = token.lstrip(_OPENING).rstrip(_CLOSING)
    if any(character in CODE_CHARACTERS for character in core):
        return True
    if _DIGIT_LETTER.search(core):
        return True
    return any(character.isupper() for character in core[1:])


def code_spans(text: str) -> list[tuple[int, int]]:
    """Return the ``(start, end)`` spans of the code in ``text`` (module docstring): the
    backtick spans first, then the code tokens, each in text order."""
    spans = _backtick_spans(text)
    spans.extend(match.span() for match in _TOKEN.finditer(text) if _is_code(match.group()))
    return spans


def prose_letters(text: str) -> int:
    """Return the number of letters of ``text`` outside its code spans."""
    locked = [False] * len(text)
    for start, end in code_spans(text):
        for index in range(start, end):
            locked[index] = True
    return sum(
        1 for index, character in enumerate(text) if character.isalpha() and not locked[index]
    )


def needs_polish(text: object) -> bool:
    """Return True for a text that needs the Turkish letters (module docstring, selection)."""
    if not isinstance(text, str) or any(character in TURKISH_LETTERS for character in text):
        return False
    letters = sum(1 for character in text if character.isalpha())
    return letters >= MIN_LETTERS and prose_letters(text) > 0


def check_correction(old: str, new: str) -> str | None:
    """Return why ``new`` cannot replace ``old`` (:data:`UNCHANGED`, :data:`FOLD_MISMATCH` or
    :data:`CODE_TOKEN_CHANGED`), or None when it can (module docstring)."""
    if new == old:
        return UNCHANGED
    if fold(new) != fold(old):
        return FOLD_MISMATCH
    # Equal folds give equal lengths, so a span of one text addresses the same characters in
    # the other one.
    for start, end in {*code_spans(old), *code_spans(new)}:
        if new[start:end] != old[start:end]:
            return CODE_TOKEN_CHANGED
    return None


# ---------------------------------------------------------------------------------------------
# Prose fields and selection


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _items(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def prose_fields(finding: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Return the ``(path, text)`` pairs of the prose fields of a record, in the order of the
    module docstring. Only string values appear."""
    found: list[tuple[str, str]] = []

    def add(path: str, value: object) -> None:
        if isinstance(value, str):
            found.append((path, value))

    for key in ("title", "description", "root_cause", "claimed_root_cause", "intended_behavior"):
        add(f"/{key}", finding.get(key))
    for key in ("trace", "evidence", "conditions"):
        for index, item in enumerate(_items(finding.get(key))):
            add(f"/{key}/{index}/description", _mapping(item).get("description"))
    execution = _mapping(finding.get("execution"))
    add("/execution/attacker_perspective", execution.get("attacker_perspective"))
    for index, item in enumerate(_items(execution.get("instructions"))):
        add(f"/execution/instructions/{index}", item)
    add("/execution/observed_result", execution.get("observed_result"))
    add("/remediation/strategy", _mapping(finding.get("remediation")).get("strategy"))
    severity = _mapping(finding.get("severity"))
    for key in ("likelihood", "impact"):
        add(f"/severity/{key}/reason", _mapping(severity.get(key)).get("reason"))
    add("/confidence/reason", _mapping(finding.get("confidence")).get("reason"))
    for index, item in enumerate(_items(finding.get("blockers"))):
        add(f"/blockers/{index}", item)
    plan = _mapping(finding.get("validation_plan"))
    for key in ("local", "deployment"):
        add(f"/validation_plan/{key}", plan.get(key))
    answers = _mapping(finding.get("audit_answers"))
    for key in ANSWER_KEYS:
        add(f"/audit_answers/{key}/reason", _mapping(answers.get(key)).get("reason"))
    add("/review/reason", _mapping(finding.get("review")).get("reason"))
    add("/duplicate_reason", finding.get("duplicate_reason"))
    for index, item in enumerate(_items(finding.get("related"))):
        add(f"/related/{index}/reason", _mapping(item).get("reason"))
    return found


def eligible(finding: Mapping[str, Any]) -> bool:
    """Return True for a record that the polish step may select (module docstring)."""
    finding_id = finding.get("id")
    return (
        finding.get("verdict") in ELIGIBLE_VERDICTS
        and isinstance(finding_id, str)
        and bool(finding_id)
    )


def batch_order(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    """The stable record order: confirmed first, then the higher overall severity, then id."""
    return (
        -_VERDICT_RANK.get(str(finding.get("verdict")), 0),
        -severity_rank(finding),
        str(finding.get("id") or ""),
    )


def select_records(
    findings: Iterable[Mapping[str, Any]], skip: Collection[tuple[str, str, str]] = ()
) -> list[dict[str, Any]]:
    """Return the records that need the Turkish letters, as ``polish`` task input records:
    ``{id, title, fields: [{path, text}]}`` with only the fields that need them, in
    :func:`batch_order`.

    ``skip`` holds ``(id, path, text)`` triples that an earlier polish task already showed to an
    agent; such a field is not selected again.
    """
    selected: list[dict[str, Any]] = []
    for finding in sorted((item for item in findings if eligible(item)), key=batch_order):
        fields = [
            {"path": path, "text": text}
            for path, text in prose_fields(finding)
            if needs_polish(text) and (finding["id"], path, text) not in skip
        ]
        if fields:
            selected.append({"id": finding["id"], "title": finding.get("title"), "fields": fields})
    return selected


def make_batches(
    selected: Sequence[dict[str, Any]], size: int = BATCH_SIZE
) -> list[list[dict[str, Any]]]:
    """Cut the selected records into batches of at most ``size`` records, in their order."""
    return [list(selected[start : start + size]) for start in range(0, len(selected), size)]


# ---------------------------------------------------------------------------------------------
# Applying corrections


@dataclass
class PolishStats:
    """What :func:`apply_corrections` did."""

    applied: int = 0
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)


def _set_field(finding: dict[str, Any], path: str, value: str) -> None:
    parts = path.strip("/").split("/")
    node: Any = finding
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    if isinstance(node, list):
        node[int(parts[-1])] = value
    else:
        node[parts[-1]] = value


def apply_corrections(
    findings: Sequence[dict[str, Any]],
    corrections: Iterable[tuple[str, Mapping[str, Any]]],
    *,
    check: Callable[[dict[str, Any]], list[str]] | None = None,
) -> PolishStats:
    """Apply accepted corrections to ``findings`` in place (module docstring).

    ``corrections`` holds ``(where, {id, path, old, new})`` pairs in the order to apply;
    ``where`` names the source for warnings. ``check`` returns the errors of a record (for
    example :func:`kalkan.findings.validate.validate_findings` of one record).
    """
    stats = PolishStats()
    by_id = {item["id"]: item for item in findings if isinstance(item.get("id"), str)}
    before: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    titles: dict[str, tuple[str, str]] = {}
    for where, entry in corrections:
        finding_id, path = entry.get("id"), entry.get("path")
        old, new = entry.get("old"), entry.get("new")
        if not all(isinstance(value, str) for value in (finding_id, path, old, new)):
            stats.skipped += 1
            stats.warnings.append(f"{where}: a polish correction is malformed; skipped")
            continue
        record = by_id.get(finding_id)
        if record is None or not eligible(record):
            stats.skipped += 1
            stats.warnings.append(f"{where}: {finding_id} is not a polished record; skipped")
            continue
        current = dict(prose_fields(record)).get(path)
        if current is None:
            stats.skipped += 1
            stats.warnings.append(f"{where}: {finding_id} has no prose field {path}; skipped")
            continue
        if current != old:
            stats.skipped += 1
            stats.warnings.append(
                f"{where}: {finding_id} {path} changed after the polish task; skipped"
            )
            continue
        reason = check_correction(old, new)
        if reason is not None:
            stats.skipped += 1
            stats.warnings.append(f"{where}: {finding_id} {path}: {reason}; skipped")
            continue
        before.setdefault(finding_id, copy.deepcopy(record))
        _set_field(record, path, new)
        counts[finding_id] = counts.get(finding_id, 0) + 1
        if path == "/title":
            titles[finding_id] = (old, new)
        stats.applied += 1
    if check is not None:
        for finding_id, original in before.items():
            errors = check(by_id[finding_id])
            if errors:
                record = by_id[finding_id]
                record.clear()
                record.update(original)
                titles.pop(finding_id, None)
                stats.applied -= counts[finding_id]
                stats.skipped += counts[finding_id]
                stats.warnings.append(
                    f"{finding_id}: the polished record is invalid ({errors[0]}); "
                    "its corrections are not applied"
                )
    for record in findings:
        for item in _items(record.get("related")):
            if not isinstance(item, dict) or item.get("id") not in titles:
                continue
            old_title, new_title = titles[item["id"]]
            if item.get("title") == old_title:
                item["title"] = new_title
    return stats
