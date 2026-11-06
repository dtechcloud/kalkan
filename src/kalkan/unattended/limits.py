# SPDX-License-Identifier: MIT
"""Usage-limit detection in the output of one unattended round (docs/ENGINE-SPEC.md, section 22).

:func:`parse_limit` reads the output lines of one host round. It returns the time at which the
usage limit resets, or None. It uses two sources, in this order:

1. **Rate-limit events.** A stream-json line whose ``type`` is ``rate_limit_event``, or
   ``system`` with a rate-limit ``subtype``. Somewhere in the event (at most eight levels deep)
   an object holds ``status`` = ``rejected`` and a reset time in ``resetsAt`` (Unix seconds,
   Unix milliseconds or ISO 8601 text). The schema is not documented, so the search accepts
   several shapes. A later event of the same limit type (``rateLimitType``) with another status
   cancels an earlier rejection. A rejection with ``overageStatus`` = ``allowed`` or
   ``isUsingOverage`` = true does not block the session, so it does not count. When more than
   one limit type is rejected, the latest reset wins.
2. **Limit text.** A reset phrase, case-insensitive: ``resets 3:45pm``,
   ``resets at 3:45 PM (Europe/Istanbul)``, ``resets 15:45``, ``try again at 4pm``,
   ``You've hit your limit · resets 5pm``, ``resets Oct 16, 9am``, ``resets Thu 9am``,
   ``resets in 2h 30m`` and the older ``Claude AI usage limit reached|<Unix time>``. The same
   text must also name a limit (``limit``, ``rate``, ``quota``, ``usage``, ``credits``,
   ``spend cap``, ``429`` or ``too many requests``). The last match in the output wins.
   Codex writes ``Try again at 3:45 PM.`` and ``Try again at Oct 17th, 2026 9:05 AM.``
   (:func:`parse_limit_text`).

When neither source gives a reset time, the caller backs off (:mod:`kalkan.unattended.loop`).

**Trusted text only.** The text search reads plain-text lines (for example stderr), the
``result``, ``error`` and ``errors`` fields of a JSON line, and the text of a synthetic
assistant message (model ``<synthetic>``: an error message that Claude Code writes itself). It
skips tool results and normal assistant messages. They can quote the audit target, and the
target is untrusted data. A line that starts with ``{`` but does not parse is skipped.

**Time zones.** A time without a date resolves to its next occurrence in the named IANA zone
when :mod:`zoneinfo` knows the zone, else in the local time zone. (Windows has no time zone
database unless the ``tzdata`` package is installed.) A bare time at most :data:`PAST_GRACE` in
the past is a message from just before the reset: the result stays in the past, and the caller
waits only its safety margin. A date without a year more than half a year in the past moves to
the next year. A reset more than :data:`MAX_AHEAD` in the future is not plausible and does not
count.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import Any, Final
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

__all__ = [
    "MAX_AHEAD",
    "PAST_GRACE",
    "SOURCE_EVENT",
    "SOURCE_TEXT",
    "LimitInfo",
    "ZoneLoader",
    "load_zone",
    "parse_limit",
    "parse_limit_text",
    "parse_reset_value",
    "printable",
]

SOURCE_EVENT: Final = "event"
SOURCE_TEXT: Final = "text"

#: A bare reset time at most this far in the past counts as just passed, not as tomorrow.
PAST_GRACE: Final = timedelta(minutes=10)
#: A reset further ahead than this is not plausible. The weekly limits reset within 7 days.
MAX_AHEAD: Final = timedelta(days=8)

#: A date without a year further back than this means the same date in the next year.
_YEAR_ROLLOVER: Final = timedelta(days=183)
#: Epoch values from this size up are milliseconds (1e11 seconds is the year 5138).
_EPOCH_MS_FROM: Final = 100_000_000_000
_MAX_LINE_CHARS: Final = 4_000_000
_MAX_TEXT_CHARS: Final = 65_536
_MAX_DEPTH: Final = 8
_MAX_ITEMS: Final = 200
_DETAIL_CHARS: Final = 160
_MAX_OFFSET: Final = timedelta(hours=14)

_RESET_KEYS: Final = ("resetsAt", "resets_at", "resetAt", "reset_at")
_TYPE_KEYS: Final = ("rateLimitType", "rate_limit_type", "limitType", "limit_type")
#: A line that contains none of these (lower case) cannot report a limit.
_HINTS: Final = ("limit", "reset", "try again", "rejected")

#: Maps an IANA zone name to a tzinfo, or to None when the zone is unknown.
ZoneLoader = Callable[[str], "tzinfo | None"]

_MONTH_NUMBERS: Final = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}
_WEEKDAY_NUMBERS: Final = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}

_MONTH: Final = (
    r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
    r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
)
_WEEKDAY: Final = (
    r"(?:mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:r(?:s(?:day)?)?)?"
    r"|fri(?:day)?|sat(?:urday)?|sun(?:day)?)"
)
_TRIGGER: Final = r"\b(?:resets?|try\s+again|available\s+again)\b"

_LIMIT_WORDS: Final = re.compile(
    r"\b(?:limits?|limited|rate|quota|usage|credits?|429)\b|too\s+many\s+requests"
    r"|\bspend(?:ing)?\s+cap\b",
    re.IGNORECASE,
)
_LEGACY: Final = re.compile(r"\blimit\s+reached\s*\|\s*(?P<epoch>[0-9]{9,13})\b", re.IGNORECASE)
# The text is whitespace-normalized before the search (one space between words), so every
# whitespace quantifier below matches at most one character and cannot backtrack far.
_ABSOLUTE: Final = re.compile(
    _TRIGGER
    + r"(?:\s+(?:at|after|on|by))?\s?[:,]?\s?"
    + r"(?:(?P<iso>[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}"
    + r"(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)"
    + rf"|(?:(?P<weekday>{_WEEKDAY})\.?,?\s)?"
    + rf"(?:(?:(?P<month>{_MONTH})\.?\s(?P<day>[0-9]{{1,2}})(?:st|nd|rd|th)?"
    + rf"|(?P<day2>[0-9]{{1,2}})(?:st|nd|rd|th)?\s(?P<month2>{_MONTH})\.?)"
    + r"(?:,?\s(?P<year>[0-9]{4}))?,?\s(?:at\s)?)?"
    + r"(?:(?P<h12>[0-9]{1,2})(?:[:.](?P<m12>[0-9]{2}))?\s?(?P<ampm>[ap])\.?\s?m\b\.?"
    + r"|(?P<h24>[0-9]{1,2}):(?P<m24>[0-9]{2})(?::[0-9]{2})?\b))"
    + r"(?:\s?\(\s?(?P<tz>[A-Za-z0-9_+:/-]{1,64})\s?\)|\s(?P<tz2>UTC|GMT)\b)?",
    re.IGNORECASE,
)
_RELATIVE: Final = re.compile(
    _TRIGGER
    + r"\sin\s(?:(?P<days>[0-9]{1,2})\s?(?:days?|d)(?![a-z]),?\s?(?:and\s)?)?"
    + r"(?:(?P<hours>[0-9]{1,3})\s?(?:hours?|hrs?|h)(?![a-z]),?\s?(?:and\s)?)?"
    + r"(?:(?P<minutes>[0-9]{1,4})\s?(?:minutes?|mins?|m)(?![a-z]))?",
    re.IGNORECASE,
)
_NUMBER_TEXT: Final = re.compile(r"\A[0-9]{1,16}(?:\.[0-9]+)?\Z")
_ZONE_KEY: Final = re.compile(r"\A[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+){0,3}\Z")
_OFFSET: Final = re.compile(r"\A(?:utc|gmt)?([+-])([0-9]{1,2})(?::?([0-9]{2}))?\Z", re.IGNORECASE)
_UTC_NAMES: Final = frozenset(
    {"utc", "gmt", "z", "zulu", "universal", "etc/utc", "etc/gmt", "etc/universal", "etc/zulu"}
)
_UNPRINTABLE: Final = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u200b-\u200f"
    r"\u2028-\u202e\u2060-\u206f\ufeff]"
)
_LIMIT_TYPE_TEXT: Final = re.compile(r"\A[A-Za-z0-9_.-]{1,40}\Z")


@dataclass(frozen=True)
class LimitInfo:
    """A usage limit found in the output of a round.

    ``reset_at`` is an aware UTC datetime. ``source`` is :data:`SOURCE_EVENT` or
    :data:`SOURCE_TEXT`. ``detail`` is a short printable description. ``limit_type`` is the
    ``rateLimitType`` of the event, when it has one.
    """

    reset_at: datetime
    source: str
    detail: str
    limit_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return {
            "reset_at": self.reset_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": self.source,
            "detail": self.detail,
            "limit_type": self.limit_type,
        }


@dataclass(frozen=True)
class _Context:
    now: datetime
    local_tz: tzinfo | None
    loader: ZoneLoader


def parse_limit(
    lines: Iterable[str],
    *,
    now: datetime | None = None,
    local_tz: tzinfo | None = None,
    zone_loader: ZoneLoader | None = None,
) -> LimitInfo | None:
    """Return the usage limit that the round output reports, or None.

    ``now`` (default: the current time) resolves times without a date. ``local_tz`` replaces the
    local time zone of the machine (tests use it). ``zone_loader`` maps an IANA zone name to a
    ``tzinfo`` or None (default: :func:`load_zone`).
    """
    moment = _as_utc(now)
    context = _Context(moment, local_tz, zone_loader or load_zone)
    events: dict[str | None, tuple[bool, datetime | None, str]] = {}
    texts: list[tuple[datetime, str]] = []
    for raw in lines:
        if not isinstance(raw, str):
            continue
        line = raw.strip()
        if not line or len(line) > _MAX_LINE_CHARS:
            continue
        lowered = line.lower()
        if not any(hint in lowered for hint in _HINTS):
            continue
        if line.startswith("{"):
            document = _json_object(line)
            if document is None:
                continue
            if _is_rate_limit_event(document):
                _record_event(document, events)
            for text in _host_texts(document):
                texts.extend(_scan_text(text, context))
            continue
        texts.extend(_scan_text(line, context))
    found = _pick_event(events, moment)
    if found is not None:
        return found
    plausible = [item for item in texts if item[0] <= moment + MAX_AHEAD]
    if plausible:
        reset, detail = plausible[-1]
        return LimitInfo(reset, SOURCE_TEXT, detail)
    return None


def parse_limit_text(
    texts: Iterable[str],
    *,
    now: datetime | None = None,
    local_tz: tzinfo | None = None,
    zone_loader: ZoneLoader | None = None,
) -> LimitInfo | None:
    """Return the usage limit in messages that the host wrote itself, or None.

    Each text is a plain message, never a JSON line: a host class extracts the trusted
    messages from its own output format first (for example
    :meth:`kalkan.unattended.hosts.CodexHost.parse_limit`). The text rules and the time rules
    are the same as in :func:`parse_limit`. The last match wins.
    """
    moment = _as_utc(now)
    context = _Context(moment, local_tz, zone_loader or load_zone)
    found: list[tuple[datetime, str]] = []
    for text in texts:
        if isinstance(text, str) and text.strip():
            found.extend(_scan_text(text, context))
    plausible = [item for item in found if item[0] <= moment + MAX_AHEAD]
    if not plausible:
        return None
    reset, detail = plausible[-1]
    return LimitInfo(reset, SOURCE_TEXT, detail)


def printable(text: str, limit: int = _DETAIL_CHARS) -> str:
    """Return ``text`` on one line, without control or invisible characters, cut to ``limit``."""
    return " ".join(_UNPRINTABLE.sub(" ", text).split())[:limit]


def parse_reset_value(value: object) -> datetime | None:
    """Return a reset time as an aware UTC datetime, or None.

    Accepts Unix seconds, Unix milliseconds (as a number or as digit text) and ISO 8601 text. An
    ISO time without an offset counts as UTC.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return _from_epoch(float(value))
        except OverflowError:
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 64:
        return None
    if _NUMBER_TEXT.match(text):
        return _from_epoch(float(text))
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def load_zone(name: str) -> tzinfo | None:
    """Return the IANA time zone ``name``, or None when :mod:`zoneinfo` does not know it."""
    if not _ZONE_KEY.match(name):
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


# ---------------------------------------------------------------------------------------------
# Events


def _json_object(line: str) -> dict[str, Any] | None:
    try:
        document = json.loads(line)
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


def _names_rate_limit(value: object) -> bool:
    if not isinstance(value, str):
        return False
    key = re.sub(r"[^a-z]", "", value.lower())
    return "ratelimit" in key or "usagelimit" in key


def _is_rate_limit_event(document: Mapping[str, Any]) -> bool:
    kind = document.get("type")
    if _names_rate_limit(kind):
        return True
    return kind == "system" and _names_rate_limit(document.get("subtype"))


def _status_objects(node: object, depth: int) -> Iterator[Mapping[str, Any]]:
    """Yield the objects at most :data:`_MAX_DEPTH` levels deep that hold a string status."""
    if depth > _MAX_DEPTH:
        return
    if isinstance(node, Mapping):
        if isinstance(node.get("status"), str):
            yield node
        children = list(node.values())[:_MAX_ITEMS]
    elif isinstance(node, list):
        children = node[:_MAX_ITEMS]
    else:
        return
    for child in children:
        if isinstance(child, (Mapping, list)):
            yield from _status_objects(child, depth + 1)


def _reset_in(info: Mapping[str, Any]) -> datetime | None:
    for key in _RESET_KEYS:
        if key in info:
            reset = parse_reset_value(info[key])
            if reset is not None:
                return reset
    return None


def _limit_type(info: Mapping[str, Any]) -> str | None:
    for key in _TYPE_KEYS:
        value = info.get(key)
        if isinstance(value, str) and _LIMIT_TYPE_TEXT.match(value):
            return value
    return None


def _uses_overage(info: Mapping[str, Any]) -> bool:
    status = info.get("overageStatus", info.get("overage_status"))
    using = info.get("isUsingOverage", info.get("is_using_overage"))
    return using is True or (isinstance(status, str) and status.strip().lower() == "allowed")


def _record_event(
    document: Mapping[str, Any], events: dict[str | None, tuple[bool, datetime | None, str]]
) -> None:
    fallback = _reset_in(document)
    kind = _printable(str(document.get("type")))
    if kind == "system":
        kind = f"system/{_printable(str(document.get('subtype')))}"
    for info in _status_objects(document, 0):
        status = info["status"].strip().lower()
        limit_type = _limit_type(info)
        blocking = status == "rejected" and not _uses_overage(info)
        detail = f"{kind} {limit_type or 'limit'}: status {_printable(status)}"
        events[limit_type] = (blocking, _reset_in(info) or fallback, detail)


def _pick_event(
    events: Mapping[str | None, tuple[bool, datetime | None, str]], now: datetime
) -> LimitInfo | None:
    candidates = [
        (reset, limit_type, detail)
        for limit_type, (blocking, reset, detail) in events.items()
        if blocking and reset is not None and reset <= now + MAX_AHEAD
    ]
    if not candidates:
        return None
    reset, limit_type, detail = max(candidates, key=lambda item: item[0])
    return LimitInfo(reset, SOURCE_EVENT, detail, limit_type)


# ---------------------------------------------------------------------------------------------
# Text


def _host_texts(document: Mapping[str, Any]) -> Iterator[str]:
    """Yield the strings of a JSON line that the host itself writes (see the module docs)."""
    for key in ("result", "error"):
        value = document.get(key)
        if isinstance(value, str):
            yield value
    errors = document.get("errors")
    if isinstance(errors, list):
        yield from (item for item in errors[:20] if isinstance(item, str))
    if document.get("type") != "assistant":
        return
    message = document.get("message")
    if not isinstance(message, Mapping):
        return
    synthetic = (
        message.get("model") == "<synthetic>"
        or document.get("isApiErrorMessage") is True
        or message.get("isApiErrorMessage") is True
    )
    if not synthetic:
        return
    content = message.get("content")
    if isinstance(content, str):
        yield content
    elif isinstance(content, list):
        for block in content[:20]:
            if (
                isinstance(block, Mapping)
                and block.get("type") == "text"
                and isinstance(block.get("text"), str)
            ):
                yield block["text"]


def _scan_text(text: str, context: _Context) -> list[tuple[datetime, str]]:
    sample = " ".join(text[-_MAX_TEXT_CHARS:].split())
    if not _LIMIT_WORDS.search(sample):
        return []
    found: list[tuple[int, datetime, str]] = []
    for match in _LEGACY.finditer(sample):
        reset = _from_epoch(float(match.group("epoch")))
        if reset is not None:
            found.append((match.start(), reset, match.group(0)))
    for match in _ABSOLUTE.finditer(sample):
        reset = _resolve_absolute(match, context)
        if reset is not None:
            found.append((match.start(), reset, match.group(0)))
    for match in _RELATIVE.finditer(sample):
        days, hours, minutes = match.group("days", "hours", "minutes")
        if days is None and hours is None and minutes is None:
            continue
        delta = timedelta(days=int(days or 0), hours=int(hours or 0), minutes=int(minutes or 0))
        found.append((match.start(), context.now + delta, match.group(0)))
    found.sort(key=lambda item: item[0])
    return [(reset, _printable(detail)) for _, reset, detail in found]


def _clock_time(match: re.Match[str]) -> tuple[int, int] | None:
    if match.group("h12") is not None:
        hour = int(match.group("h12"))
        minute = int(match.group("m12") or 0)
        if not 1 <= hour <= 12 or minute > 59:
            return None
        afternoon = match.group("ampm").lower() == "p"
        return hour % 12 + (12 if afternoon else 0), minute
    hour = int(match.group("h24"))
    minute = int(match.group("m24"))
    if hour > 23 or minute > 59:
        return None
    return hour, minute


def _resolve_absolute(match: re.Match[str], context: _Context) -> datetime | None:
    zone = _zone_for(match.group("tz") or match.group("tz2"), context)
    if match.group("iso"):
        try:
            moment = datetime.fromisoformat(match.group("iso"))
        except ValueError:
            return None
        if moment.tzinfo is None:
            return _to_utc(moment, zone)
        return moment.astimezone(UTC)
    clock = _clock_time(match)
    if clock is None:
        return None
    hour, minute = clock
    now = context.now
    wall_now = _wall_now(now, zone)
    month_text = match.group("month") or match.group("month2")
    if month_text:
        month = _MONTH_NUMBERS[month_text[:3].lower()]
        day = int(match.group("day") or match.group("day2"))
        year_text = match.group("year")
        year = int(year_text) if year_text else wall_now.year
        try:
            wall = datetime(year, month, day, hour, minute)
        except ValueError:
            return None
        reset = _to_utc(wall, zone)
        if reset is not None and not year_text and reset < now - _YEAR_ROLLOVER:
            try:
                reset = _to_utc(wall.replace(year=year + 1), zone)
            except ValueError:
                return None
        return reset
    base = wall_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    weekday = match.group("weekday")
    if weekday:
        days = (_WEEKDAY_NUMBERS[weekday[:3].lower()] - wall_now.weekday()) % 7
        wall, step = base + timedelta(days=days), timedelta(days=7)
    else:
        wall, step = base, timedelta(days=1)
    reset = _to_utc(wall, zone)
    if reset is not None and reset < now - PAST_GRACE:
        reset = _to_utc(wall + step, zone)
    return reset


# ---------------------------------------------------------------------------------------------
# Time helpers


def _as_utc(moment: datetime | None) -> datetime:
    if moment is None:
        return datetime.now(UTC)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _from_epoch(number: float) -> datetime | None:
    if not math.isfinite(number) or number <= 0:
        return None
    seconds = number / 1000.0 if number >= _EPOCH_MS_FROM else number
    try:
        return datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _zone_for(name: str | None, context: _Context) -> tzinfo | None:
    """Return the zone of a reset phrase. None means the local time zone of the machine."""
    if not name:
        return context.local_tz
    key = name.strip()
    if key.lower() in _UTC_NAMES:
        return UTC
    offset = _OFFSET.match(key)
    if offset:
        sign, hours, minutes = offset.groups()
        delta = timedelta(hours=int(hours), minutes=int(minutes or 0))
        if delta > _MAX_OFFSET:
            return context.local_tz
        return timezone(-delta if sign == "-" else delta)
    zone = context.loader(key)
    return zone if zone is not None else context.local_tz


def _wall_now(now: datetime, zone: tzinfo | None) -> datetime:
    """Return ``now`` as a naive wall time in ``zone`` (None: the local time zone)."""
    local = now.astimezone(zone) if zone is not None else now.astimezone()
    return local.replace(tzinfo=None)


def _to_utc(wall: datetime, zone: tzinfo | None) -> datetime | None:
    """Return the naive wall time ``wall`` in ``zone`` (None: local time) as aware UTC."""
    try:
        if zone is None:
            return wall.astimezone(UTC)  # Python reads a naive value as local time.
        return wall.replace(tzinfo=zone).astimezone(UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _printable(text: str) -> str:
    return printable(text)
