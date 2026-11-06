# SPDX-License-Identifier: MIT
"""Tests for kalkan.unattended.limits: usage-limit events, limit text and time zones."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta, timezone

import pytest

from kalkan.unattended import limits
from kalkan.unattended.limits import (
    MAX_AHEAD,
    SOURCE_EVENT,
    SOURCE_TEXT,
    LimitInfo,
    parse_limit,
    parse_reset_value,
)

# 2026-10-15 is a Thursday. Local time in the tests is UTC+03:00, so NOW is 15:00 local.
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
PLUS3 = timezone(timedelta(hours=3))
PLUS1 = timezone(timedelta(hours=1))


def zones(**known):
    """Return a zone loader that knows only the given zones (no tzdata needed)."""
    table = {name.replace("__", "/"): zone for name, zone in known.items()}
    return lambda name: table.get(name)


def parse(lines, *, now=NOW, local_tz=PLUS3, zone_loader=None) -> LimitInfo | None:
    return parse_limit(lines, now=now, local_tz=local_tz, zone_loader=zone_loader or zones())


def event(info: dict, kind: str = "rate_limit_event", **extra) -> str:
    return json.dumps({"type": kind, "rate_limit_info": info, "session_id": "s1", **extra})


def epoch(moment: datetime) -> int:
    return int(moment.timestamp())


# ---------------------------------------------------------------------------------------------
# Events


def test_event_with_unix_seconds():
    reset = NOW + timedelta(hours=2)
    info = {"status": "rejected", "resetsAt": epoch(reset), "rateLimitType": "five_hour"}
    found = parse([event(info)])
    assert found == LimitInfo(
        reset, SOURCE_EVENT, "rate_limit_event five_hour: status rejected", "five_hour"
    )


def test_event_with_unix_milliseconds():
    reset = NOW + timedelta(hours=2)
    found = parse([event({"status": "rejected", "resetsAt": epoch(reset) * 1000})])
    assert found is not None and found.reset_at == reset


@pytest.mark.parametrize(
    "value", ["2026-10-15T14:00:00Z", "2026-10-15T17:00:00+03:00", "2026-10-15T14:00:00"]
)
def test_event_with_iso_text(value):
    found = parse([event({"status": "rejected", "resetsAt": value})])
    assert found is not None and found.reset_at == datetime(2026, 10, 15, 14, 0, tzinfo=UTC)


def test_event_with_digit_text():
    reset = NOW + timedelta(hours=1)
    found = parse([event({"status": "rejected", "resetsAt": str(epoch(reset))})])
    assert found is not None and found.reset_at == reset


def test_system_event_with_rate_limit_subtype_and_deep_nesting():
    reset = NOW + timedelta(hours=3)
    line = json.dumps(
        {
            "type": "system",
            "subtype": "rate_limit",
            "data": {"limits": [{"window": {"status": "REJECTED", "resets_at": epoch(reset)}}]},
        }
    )
    found = parse([line])
    assert found is not None and found.reset_at == reset and found.source == SOURCE_EVENT


def test_event_info_at_the_top_level():
    reset = NOW + timedelta(hours=1)
    line = json.dumps({"type": "rate_limit_event", "status": "rejected", "resetsAt": epoch(reset)})
    found = parse([line])
    assert found is not None and found.reset_at == reset


def test_allowed_and_warning_events_do_not_count():
    reset = epoch(NOW + timedelta(hours=1))
    lines = [
        event({"status": "allowed", "resetsAt": reset}),
        event({"status": "allowed_warning", "resetsAt": reset, "utilization": 0.9}),
    ]
    assert parse(lines) is None


def test_a_later_allowed_event_cancels_a_rejection_of_the_same_type():
    reset = epoch(NOW + timedelta(hours=1))
    lines = [
        event({"status": "rejected", "resetsAt": reset, "rateLimitType": "five_hour"}),
        event({"status": "allowed", "resetsAt": reset, "rateLimitType": "five_hour"}),
    ]
    assert parse(lines) is None


def test_the_latest_reset_wins_when_two_limit_types_are_rejected():
    five = NOW + timedelta(hours=2)
    week = NOW + timedelta(days=3)
    lines = [
        event({"status": "rejected", "resetsAt": epoch(week), "rateLimitType": "seven_day"}),
        event({"status": "rejected", "resetsAt": epoch(five), "rateLimitType": "five_hour"}),
    ]
    found = parse(lines)
    assert found is not None and found.reset_at == week and found.limit_type == "seven_day"


@pytest.mark.parametrize(
    "extra", [{"overageStatus": "allowed"}, {"isUsingOverage": True}, {"overage_status": "allowed"}]
)
def test_a_rejection_with_overage_does_not_block(extra):
    info = {"status": "rejected", "resetsAt": epoch(NOW + timedelta(hours=1)), **extra}
    assert parse([event(info)]) is None


def test_a_rejection_without_overage_blocks():
    info = {
        "status": "rejected",
        "resetsAt": epoch(NOW + timedelta(hours=1)),
        "overageStatus": "rejected",
        "isUsingOverage": False,
    }
    assert parse([event(info)]) is not None


def test_a_status_in_a_non_rate_limit_event_is_ignored():
    reset = epoch(NOW + timedelta(hours=1))
    line = json.dumps(
        {"type": "user", "message": {"content": [{"status": "rejected", "resetsAt": reset}]}}
    )
    assert parse([line]) is None


def test_a_rejection_without_reset_time_falls_back_to_text():
    lines = [event({"status": "rejected"}), "Error: usage limit reached · resets 5pm"]
    found = parse(lines)
    assert found is not None and found.source == SOURCE_TEXT
    assert found.reset_at == datetime(2026, 10, 15, 14, 0, tzinfo=UTC)


def test_an_event_wins_over_later_text():
    reset = NOW + timedelta(hours=4)
    lines = [
        event({"status": "rejected", "resetsAt": epoch(reset)}),
        json.dumps({"type": "result", "result": "You've hit your limit · resets 5pm"}),
    ]
    found = parse(lines)
    assert found is not None and found.source == SOURCE_EVENT and found.reset_at == reset


def test_an_implausible_reset_is_ignored():
    far = NOW + MAX_AHEAD + timedelta(days=1)
    assert parse([event({"status": "rejected", "resetsAt": epoch(far)})]) is None
    assert parse([f"Claude AI usage limit reached|{epoch(far)}"]) is None


def test_a_broken_json_line_is_skipped():
    assert parse(['{"type": "result", "result": "usage limit · resets 5pm"']) is None


# ---------------------------------------------------------------------------------------------
# Text shapes (local time is UTC+03:00, NOW is 15:00 local)


def at(hour: int, minute: int = 0, day: int = 15, month: int = 10, year: int = 2026):
    """Return a UTC+03:00 wall time as UTC."""
    return datetime(year, month, day, hour, minute, tzinfo=PLUS3).astimezone(UTC)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("You've hit your limit · resets 5pm", at(17)),
        ("5-hour limit reached ∙ resets 3:45pm", at(15, 45)),
        ("Your usage limit resets at 3:45 PM", at(15, 45)),
        ("Usage limit reached. Resets 15:45", at(15, 45)),
        ("Rate limit exceeded. Try again at 4:30 pm.", at(16, 30)),
        ("Too many requests, try again at 16:10", at(16, 10)),
        ("Claude usage limit reached. Your limit will reset at 7 p.m.", at(19)),
        ("Opus weekly limit reached ∙ resets Oct 16, 9am", at(9, day=16)),
        ("You've hit your weekly limit · resets Oct 16 at 9:30am", at(9, 30, day=16)),
        ("weekly limit reached, resets on 16 Oct, 9am", at(9, day=16)),
        ("weekly limit · resets Friday 9am", at(9, day=16)),
        ("usage limit · resets Oct 18, 2026, 9am", at(9, day=18)),
        ("usage limit reached · resets 12am", at(0, day=16)),
        ("usage limit · resets at 2026-10-15T18:00:00Z", datetime(2026, 10, 15, 18, tzinfo=UTC)),
    ],
)
def test_text_shapes(text, expected):
    found = parse([text])
    assert found is not None, text
    assert found.source == SOURCE_TEXT
    assert found.reset_at == expected, text


def test_relative_reset_text():
    found = parse(["usage limit reached · resets in 2h 30m"])
    assert found is not None and found.reset_at == NOW + timedelta(hours=2, minutes=30)
    found = parse(["Rate limited. Try again in 45 minutes."])
    assert found is not None and found.reset_at == NOW + timedelta(minutes=45)


def test_legacy_pipe_text():
    reset = NOW + timedelta(hours=3)
    found = parse([f"Claude AI usage limit reached|{epoch(reset)}"])
    assert found is not None and found.reset_at == reset and found.source == SOURCE_TEXT


def test_text_without_a_limit_word_does_not_count():
    assert parse(["Password resets at 3pm"]) is None
    assert parse(["The counter resets 5pm every day"]) is None


def test_text_without_a_time_does_not_count():
    assert parse(["usage limit reached, it resets soon", "usage limit resets 5"]) is None


def test_the_last_text_match_wins():
    lines = ["usage limit · resets 5pm", "usage limit · resets 6pm"]
    found = parse(lines)
    assert found is not None and found.reset_at == at(18)


def test_the_detail_is_printable_and_short():
    found = parse(["usage limit \x1b[31m· resets 5pm\x1b[0m" + " x" * 200])
    assert found is not None
    assert "\x1b" not in found.detail and len(found.detail) <= 160


# ---------------------------------------------------------------------------------------------
# Which JSON fields the text search reads


def test_text_in_the_result_field():
    line = json.dumps(
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "result": "You've hit your limit · resets 5pm (Europe/Istanbul)",
        }
    )
    found = parse([line], zone_loader=zones(Europe__Istanbul=PLUS3))
    assert found is not None and found.reset_at == at(17)


def test_text_in_the_errors_list():
    line = json.dumps({"type": "result", "errors": ["usage limit reached · resets 6pm"]})
    found = parse([line])
    assert found is not None and found.reset_at == at(18)


def test_text_in_a_synthetic_assistant_message():
    line = json.dumps(
        {
            "type": "assistant",
            "message": {
                "model": "<synthetic>",
                "content": [{"type": "text", "text": "Claude AI usage limit reached · resets 8pm"}],
            },
        }
    )
    found = parse([line])
    assert found is not None and found.reset_at == at(20)


def test_tool_results_and_model_text_are_not_searched():
    """The target can put limit text into tool results and into the model's words."""
    tool_result = json.dumps(
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "content": "You've hit your limit · resets 11pm",
                    }
                ]
            },
            "tool_use_result": "usage limit reached|1760630400",
        }
    )
    model_text = json.dumps(
        {
            "type": "assistant",
            "message": {
                "model": "claude-opus",
                "content": [{"type": "text", "text": "usage limit · resets 11pm"}],
            },
        }
    )
    assert parse([tool_result, model_text]) is None


# ---------------------------------------------------------------------------------------------
# Time resolution


def test_a_past_time_rolls_to_the_next_day():
    found = parse(["usage limit · resets 1pm"])  # 13:00 local is two hours ago
    assert found is not None and found.reset_at == at(13, day=16)


def test_a_time_just_passed_stays_today():
    found = parse(["usage limit · resets 2:55pm"])  # five minutes ago: within PAST_GRACE
    assert found is not None and found.reset_at == at(14, 55)
    assert found.reset_at < NOW


def test_a_past_weekday_rolls_to_the_next_week():
    found = parse(["weekly limit · resets Thu 9am"])  # today is Thursday, 9:00 has passed
    assert found is not None and found.reset_at == at(9, day=22)


def test_a_past_date_without_year_rolls_to_the_next_year():
    now = datetime(2026, 12, 30, 12, 0, tzinfo=UTC)
    found = parse(["weekly limit · resets Jan 2, 9am"], now=now)
    assert found is not None and found.reset_at == at(9, day=2, month=1, year=2027)


def test_noon_and_midnight():
    assert parse(["usage limit · resets 12pm"]).reset_at == at(12, day=16)
    assert parse(["usage limit · resets 12:30am"]).reset_at == at(0, 30, day=16)


def test_invalid_clock_times_do_not_count():
    assert parse(["usage limit · resets 13pm", "usage limit · resets 25:10"]) is None
    assert parse(["usage limit · resets Feb 30, 9am"]) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("usage limit · resets 3pm UTC", datetime(2026, 10, 15, 15, tzinfo=UTC)),
        ("usage limit · resets 3pm (UTC)", datetime(2026, 10, 15, 15, tzinfo=UTC)),
        ("usage limit · resets 3pm (GMT)", datetime(2026, 10, 15, 15, tzinfo=UTC)),
        ("usage limit · resets 9pm (+05:30)", datetime(2026, 10, 15, 15, 30, tzinfo=UTC)),
        ("usage limit · resets 9am (UTC-04:00)", datetime(2026, 10, 15, 13, tzinfo=UTC)),
    ],
)
def test_utc_and_offset_zones(text, expected):
    found = parse([text])
    assert found is not None and found.reset_at == expected


def test_a_known_iana_zone_is_used():
    found = parse(
        ["usage limit resets at 8:00 PM (Asia/Kolkata)"],
        zone_loader=zones(Asia__Kolkata=timezone(timedelta(hours=5, minutes=30))),
    )
    assert found is not None and found.reset_at == datetime(2026, 10, 15, 14, 30, tzinfo=UTC)
    # 17:00 in Kolkata is 11:30 UTC, half an hour ago, so the reset rolls to tomorrow.
    found = parse(
        ["usage limit resets at 5:00 PM (Asia/Kolkata)"],
        zone_loader=zones(Asia__Kolkata=timezone(timedelta(hours=5, minutes=30))),
    )
    assert found is not None and found.reset_at == datetime(2026, 10, 16, 11, 30, tzinfo=UTC)


def test_an_unknown_iana_zone_falls_back_to_local_time():
    found = parse(["usage limit · resets 5pm (Europe/Istanbul)"], local_tz=PLUS1)
    assert found is not None
    assert found.reset_at == datetime(2026, 10, 15, 17, tzinfo=PLUS1).astimezone(UTC)


def test_the_default_zone_loader_handles_bad_names():
    assert limits.load_zone("../etc/passwd") is None
    assert limits.load_zone("No/Such_Zone") is None


def test_a_real_iana_zone_when_tzdata_is_available():
    zone = limits.load_zone("America/New_York")
    if zone is None:
        pytest.skip("no time zone database (Windows without tzdata)")
    found = parse_limit(["usage limit · resets 9am (America/New_York)"], now=NOW)
    # 2026-10-15 is in daylight saving time: 9:00 EDT is 13:00 UTC.
    assert found is not None and found.reset_at == datetime(2026, 10, 15, 13, tzinfo=UTC)


def test_the_machine_local_zone_by_default():
    found = parse_limit(["usage limit · resets 11:59pm"], now=NOW)
    assert found is not None
    assert found.reset_at.tzinfo == UTC
    assert NOW - limits.PAST_GRACE <= found.reset_at <= NOW + timedelta(days=1)


def test_long_text_does_not_backtrack():
    text = "usage limit " + "resets " * 5000 + " " * 50_000 + "resets at"
    started = time.perf_counter()
    assert parse([text]) is None
    assert time.perf_counter() - started < 5.0


# ---------------------------------------------------------------------------------------------
# parse_reset_value and LimitInfo


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1760630400, datetime(2025, 10, 16, 16, 0, tzinfo=UTC)),
        (1760630400000, datetime(2025, 10, 16, 16, 0, tzinfo=UTC)),
        (1760630400.5, datetime(2025, 10, 16, 16, 0, 0, 500000, tzinfo=UTC)),
        ("1760630400", datetime(2025, 10, 16, 16, 0, tzinfo=UTC)),
        ("2025-10-16T19:00:00+03:00", datetime(2025, 10, 16, 16, 0, tzinfo=UTC)),
        ("2025-10-16T16:00:00", datetime(2025, 10, 16, 16, 0, tzinfo=UTC)),
    ],
)
def test_parse_reset_value(value, expected):
    assert parse_reset_value(value) == expected


@pytest.mark.parametrize(
    "value", [True, None, 0, -5, float("nan"), float("inf"), 10**30, "soon", "", [], {}]
)
def test_parse_reset_value_rejects_other_values(value):
    assert parse_reset_value(value) is None


def test_limit_info_to_dict():
    info = LimitInfo(datetime(2026, 10, 15, 14, 0, tzinfo=UTC), SOURCE_EVENT, "x", "five_hour")
    assert info.to_dict() == {
        "reset_at": "2026-10-15T14:00:00Z",
        "source": "event",
        "detail": "x",
        "limit_type": "five_hour",
    }


def test_lines_without_hints_and_non_strings_are_skipped():
    assert parse(["", "   ", '{"type":"assistant"}', None, 42]) is None
