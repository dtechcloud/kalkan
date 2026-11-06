# SPDX-License-Identifier: MIT
"""CLI commands ``verify`` and ``ledger validate`` (docs/ENGINE-SPEC.md section 9).

``verify <file>`` checks either a findings document (a JSON array, validated with
:mod:`kalkan.findings.validate`) or a ``verify`` task result (an object with ``audit_answers``:
schema check, quote verification against the target and the engine verdict). ``ledger validate``
checks a coverage ledger with :mod:`kalkan.findings.ledger`.

Output follows the upstream validators: one ``ERROR: <message>`` line per message on stderr, then
``FAIL: N validation error(s)`` or ``PASS``. Exit code 4 means validation failed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from kalkan.errors import KalkanError, ValidationError
from kalkan.findings import quote_verify
from kalkan.findings.ledger import validate_ledger_file
from kalkan.findings.validate import validate_findings_file
from kalkan.schema.loader import load_schema
from kalkan.schema.validator import parse_json_text, validate
from kalkan.util.safe_io import dumps_json, read_text_bounded

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_VALIDATION = 4
MAX_MESSAGES = 100


def register(subparsers: argparse._SubParsersAction) -> None:
    verify = subparsers.add_parser(
        "verify",
        help="Check an agent result: schema, quotes and verdict.",
        description=(
            "Check a findings document (JSON array) or a verify task result (object with "
            "audit_answers). A task result needs the target folder for the quote check."
        ),
    )
    verify.add_argument("file", help="findings.json or a verify task result.json")
    target = verify.add_mutually_exclusive_group()
    target.add_argument("--target", help="target folder that the quotes refer to")
    target.add_argument("--run", help="run ID whose target copy the quotes refer to")
    verify.add_argument("--json", action="store_true", help="print machine output on stdout")
    verify.set_defaults(func=cmd_verify)

    ledger = subparsers.add_parser(
        "ledger", help="Validate a coverage ledger.", description="Coverage ledger commands."
    )
    ledger_sub = ledger.add_subparsers(dest="ledger_command", metavar="<subcommand>")
    ledger.set_defaults(func=_group_help(ledger))
    validate_cmd = ledger_sub.add_parser(
        "validate",
        help="Validate a coverage ledger file.",
        description="Validate a coverage ledger (default: the ledger of the run).",
    )
    validate_cmd.add_argument("file", nargs="?", help="coverage-ledger.json (default: the run's)")
    validate_cmd.add_argument("--run", help="run ID (default: runs/LATEST)")
    validate_cmd.add_argument("--json", action="store_true", help="print machine output on stdout")
    validate_cmd.set_defaults(func=cmd_ledger_validate)


def _group_help(parser: argparse.ArgumentParser):
    def handler(_args: argparse.Namespace) -> int:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    return handler


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.file)
    document = _load_json(path)
    if isinstance(document, list):
        messages = validate_findings_file(path)
        return _finish("findings", messages, args.json, extra={"findings": len(document)})
    if isinstance(document, dict) and "audit_answers" in document:
        return _verify_task_result(document, args)
    raise ValidationError(
        "unknown document: expected a findings array or a verify task result object"
    )


def _verify_task_result(result: dict[str, Any], args: argparse.Namespace) -> int:
    messages = validate(result, load_schema("task-verify"))
    if messages:
        return _finish("verify-result", messages, args.json)
    target_dir = _target_dir(args)
    from kalkan.run.source import make_get_lines

    outcome = quote_verify.evaluate(result["audit_answers"], make_get_lines(target_dir))
    payload = {
        "kind": "verify-result",
        "valid": True,
        "verdict": outcome["verdict"],
        "answers": {
            question: {
                "status": answer["status"],
                "verified_quotes": len(answer["evidence"]),
                "cited_quotes": len(result["audit_answers"][question]["evidence"]),
            }
            for question, answer in outcome["audit_answers"].items()
        },
        "downgrades": outcome["reasons"],
    }
    if args.json:
        sys.stdout.write(dumps_json(payload))
    else:
        for question, info in payload["answers"].items():
            note = payload["downgrades"].get(question, "")
            print(
                f"{question}: {info['status']} "
                f"({info['verified_quotes']}/{info['cited_quotes']} quotes verified)"
                + (f" [{note}]" if note else ""),
                file=sys.stderr,
            )
        print(f"PASS: verdict {payload['verdict']}", file=sys.stderr)
    return EXIT_OK


def _target_dir(args: argparse.Namespace) -> Path:
    if args.target:
        target = Path(args.target)
    else:
        from kalkan.run.ids import resolve_run

        target = resolve_run(args.run) / "target"
    if not target.is_dir():
        raise KalkanError("target folder not found; pass --target or --run")
    return target


def cmd_ledger_validate(args: argparse.Namespace) -> int:
    if args.file:
        path = Path(args.file)
    else:
        from kalkan.run.ids import resolve_run

        path = resolve_run(args.run) / "coverage-ledger.json"
    messages = validate_ledger_file(path)
    return _finish("ledger", messages, args.json)


def _finish(kind: str, messages: list[str], as_json: bool, extra: dict | None = None) -> int:
    capped = len(messages) >= MAX_MESSAGES
    if as_json:
        payload = {"kind": kind, "valid": not messages, "errors": messages, "capped": capped}
        payload.update(extra or {})
        sys.stdout.write(dumps_json(payload))
    else:
        for message in messages:
            print(f"ERROR: {message}", file=sys.stderr)
        if messages:
            note = f"; output capped at {MAX_MESSAGES}" if capped else ""
            print(f"FAIL: {len(messages)} validation error(s){note}", file=sys.stderr)
        else:
            print("PASS", file=sys.stderr)
    return EXIT_VALIDATION if messages else EXIT_OK


def _load_json(path: Path) -> Any:
    try:
        return parse_json_text(read_text_bounded(path))
    except ValidationError:
        raise
    except (KalkanError, OSError, UnicodeDecodeError) as exc:
        raise KalkanError(f"cannot read the input file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON: {exc.msg}") from exc
