"""Evidence-based weakness and potential-impact aggregation.

Impact fields follow FIRST CVSS v2, v3.1, and v4.0 specifications:
https://www.first.org/cvss/v2/guide
https://www.first.org/cvss/v3.1/specification-document
https://www.first.org/cvss/v4.0/specification-document

CVSS describes potential technical impact, not observed organizational loss.
CWE annotations describe reported weakness types, not proven incident causes.
Missing or malformed vectors remain unknown; no impact is inferred from prose.
"""

from __future__ import annotations

import calendar
from datetime import datetime, timezone
import re
from typing import Any, Iterable


SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")
IMPACT_NAMES = ("confidentiality", "integrity", "availability")


def bins() -> list[int]:
    """Severity counts followed by matching KEV severity counts."""
    return [0] * 10


def insight_stats() -> dict[str, Any]:
    return {"causes": {}, "causeKnown": bins(), "impactKnown": bins(),
            "impacts": {name: bins() for name in IMPACT_NAMES},
            "remoteUnauthenticated": bins(), "reachKnown": bins()}


def parse_vector(version: str | None, vector: str | None) -> dict[str, str] | None:
    """Validate metric syntax/enumerations without guessing missing metrics.

Impact triples are checked independently below. Other base metrics can be
absent, but any supplied field must be valid. Duplicate keys are rejected even
when their values agree, so ambiguous vectors never contribute insights.
"""
    if version not in ("2.0", "3.0", "3.1", "4.0") or not isinstance(vector, str):
        return None
    if not vector or len(vector) > 1024 or any(char.isspace() for char in vector):
        return None
    value = vector
    if version == "2.0":
        if value.startswith("(") and value.endswith(")"):
            value = value[1:-1]
        if value.startswith("CVSS:2.0/"):
            value = value[len("CVSS:2.0/"):]
        allowed = {"AV": {"L", "A", "N"}, "AC": {"H", "M", "L"}, "Au": {"M", "S", "N"},
                   "C": {"N", "P", "C"}, "I": {"N", "P", "C"}, "A": {"N", "P", "C"},
                   "E": {"ND", "U", "POC", "F", "H"}, "RL": {"ND", "OF", "TF", "W", "U"},
                   "RC": {"ND", "UC", "UR", "C"}, "CDP": {"ND", "N", "L", "LM", "MH", "H"},
                   "TD": {"ND", "N", "L", "M", "H"},
                   **{key: {"ND", "L", "M", "H"} for key in ("CR", "IR", "AR")}}
    elif version in ("3.0", "3.1"):
        prefix = f"CVSS:{version}/"
        if not value.startswith(prefix):
            return None
        value = value[len(prefix):]
        base = {"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "PR": {"N", "L", "H"},
                "UI": {"N", "R"}, "S": {"U", "C"},
                **{key: {"N", "L", "H"} for key in ("C", "I", "A")}}
        allowed = {**base, **{f"M{key}": values | {"X"} for key, values in base.items()},
                   "E": {"X", "U", "P", "F", "H"}, "RL": {"X", "O", "T", "W", "U"},
                   "RC": {"X", "U", "R", "C"},
                   **{key: {"X", "L", "M", "H"} for key in ("CR", "IR", "AR")}}
    else:
        if not value.startswith("CVSS:4.0/"):
            return None
        value = value[len("CVSS:4.0/"):]
        base = {"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"},
                "PR": {"N", "L", "H"}, "UI": {"N", "P", "A"},
                **{key: {"N", "L", "H"} for key in ("VC", "VI", "VA", "SC", "SI", "SA")}}
        allowed = {**base, **{f"M{key}": values | {"X"} for key, values in base.items()},
                   "E": {"X", "A", "P", "U"},
                   **{key: {"X", "H", "M", "L"} for key in ("CR", "IR", "AR")},
                   "S": {"X", "N", "P"}, "AU": {"X", "N", "Y"}, "R": {"X", "A", "U", "I"},
                   "V": {"X", "D", "C"}, "RE": {"X", "L", "M", "H"},
                   "U": {"X", "Clear", "Green", "Amber", "Red"}}
        allowed["MSI"].add("S")
        allowed["MSA"].add("S")
    metrics = {}
    for field in value.split("/"):
        if field.count(":") != 1:
            return None
        key, metric = field.split(":")
        if key in metrics or key not in allowed or metric not in allowed[key]:
            return None
        metrics[key] = metric
    return metrics or None


def record_insights(weaknesses: Iterable[str], version: str | None, vector: str | None,
                    valid_cwes: set[str] | None = None) -> dict[str, Any]:
    causes = sorted({value for value in weaknesses if isinstance(value, str)
                     and re.fullmatch(r"CWE-[1-9]\d{0,5}", value)
                     and (valid_cwes is None or value in valid_cwes)})
    result: dict[str, Any] = {"causes": causes, "impacts": [], "impactKnown": False,
                              "remoteUnauthenticated": None}
    metrics = parse_vector(version, vector)
    if metrics is None:
        return result
    fields = ("VC", "VI", "VA") if version == "4.0" else ("C", "I", "A")
    secondary = ("SC", "SI", "SA") if version == "4.0" else ()
    complete = all(key in metrics for key in fields)
    # CVSS v4 requires all six vulnerable/subsequent-system base impacts.
    if secondary:
        complete = complete and all(key in metrics for key in secondary)
    if complete:
        result["impactKnown"] = True
        result["impacts"] = [name for index, name in enumerate(IMPACT_NAMES)
                             if metrics[fields[index]] != "N" or
                             (secondary and metrics.get(secondary[index], "N") != "N")]
    authentication = "Au" if version == "2.0" else "PR"
    if "AV" in metrics and authentication in metrics:
        result["remoteUnauthenticated"] = metrics["AV"] == "N" and metrics[authentication] == "N"
    return result


def increment_insights(target: dict[str, Any], record: dict[str, Any]) -> None:
    evidence = record["insights"]
    index = SEVERITIES.index(record["severity"])
    indexes = (index, index + 5) if record["kev"] else (index,)

    def add(values: list[int]) -> None:
        for offset in indexes:
            values[offset] += 1

    causes = set(evidence["causes"])
    if causes:
        add(target["causeKnown"])
    for cause in causes:
        add(target["causes"].setdefault(cause, bins()))
    if evidence["impactKnown"]:
        add(target["impactKnown"])
        for name in set(evidence["impacts"]):
            add(target["impacts"][name])
    if evidence["remoteUnauthenticated"] is True:
        add(target["remoteUnauthenticated"])
    if evidence["remoteUnauthenticated"] is not None:
        add(target["reachKnown"])


def comparison_window(end: Any) -> dict[str, Any] | None:
    """Expose the covered partial year and its UTC month/day/time cutoff."""
    if end is None:
        return None
    parsed = utc_time(end)
    # Any completed final day is effectively full-year publication coverage.
    if parsed.month == 12 and parsed.day == 31 and parsed.hour == 23 and parsed.minute == 59:
        return None
    time_text = parsed.isoformat().split("T")[1].replace("+00:00", "Z")
    return {"partialYear": parsed.year, "endMonthDay": parsed.strftime("%m-%d"), "endTime": time_text}


def utc_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def within_comparison(published: str, window: dict[str, Any] | None) -> bool:
    if window is None:
        return True
    parsed = utc_time(published)
    month, day = map(int, window["endMonthDay"].split("-"))
    # February 29 uses February 28 for a non-leap comparison year.
    day = min(day, calendar.monthrange(parsed.year, month)[1])
    cutoff = utc_time(f"{parsed.year:04}-{month:02}-{day:02}T{window['endTime']}")
    return parsed <= cutoff
