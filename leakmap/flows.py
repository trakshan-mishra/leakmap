"""Aggregate per-request events into one entry per receiving company."""

from fnmatch import fnmatch

from .detect import labels
from .model import CONFIDENCE_RANK, Event
from .vendors import resolve

MAX_FIELDS = 8


def aggregate(events: list[Event], min_confidence: str = "medium", ignore_hosts=()) -> dict:
    floor = CONFIDENCE_RANK[min_confidence]
    names = labels()
    processors: dict[str, dict] = {}
    hidden = 0
    for ev in events:
        if any(fnmatch(ev.host, pat) for pat in ignore_hosts):
            continue
        vendor = resolve(ev.host)
        p = processors.setdefault(vendor.id, {
            "id": vendor.id,
            "name": vendor.name,
            "kind": vendor.kind,
            "country": vendor.country,
            "hosts": [],
            "requests": 0,
            "uninspected": 0,
            "data": {},
        })
        if ev.host not in p["hosts"]:
            p["hosts"].append(ev.host)
        p["requests"] += 1
        if ev.inspected in ("binary", "too_large", "error"):
            p["uninspected"] += 1
        for f in ev.findings:
            if CONFIDENCE_RANK[f.confidence] < floor:
                hidden += 1
                continue
            d = p["data"].setdefault(f.category, {
                "label": names.get(f.category, f.category),
                "occurrences": 0,
                "fields": [],
                "example": f.masked,
                "endpoint": f"{ev.method} {ev.host}{ev.path}",
            })
            d["occurrences"] += f.count
            if f.field not in d["fields"] and len(d["fields"]) < MAX_FIELDS:
                d["fields"].append(f.field)
    ordered = sorted(processors.values(), key=lambda p: (-len(p["data"]), p["name"].lower()))
    return {
        "events": len(events),
        "hidden_low_confidence": hidden,
        "processors": ordered,
    }
