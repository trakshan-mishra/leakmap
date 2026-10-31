"""leakmap.yaml (settings and deny rules) and leakmap.lock (the reviewed baseline)."""

import json
from fnmatch import fnmatch
from pathlib import Path

import yaml

DEFAULTS = {
    "home_country": "IN",
    "min_confidence": "medium",
    "ignore_hosts": [],
    "deny": [],
    "fail_on_new_processor": False,
}

LOCK_VERSION = 1


class ConfigError(ValueError):
    pass


def load_config(path: Path) -> dict:
    config = dict(DEFAULTS)
    if path.exists():
        data = yaml.safe_load(path.read_text()) or {}
        unknown = set(data) - set(DEFAULTS)
        if unknown:
            raise ConfigError(f"{path}: unknown keys {sorted(unknown)}")
        config.update(data)
    if config["min_confidence"] not in ("low", "medium", "high"):
        raise ConfigError("min_confidence must be low, medium or high")
    return config


def lock_from_run(run: dict) -> dict:
    return {
        "version": LOCK_VERSION,
        "processors": {
            p["id"]: {"name": p["name"], "country": p["country"], "data": sorted(p["data"])}
            for p in sorted(run["processors"], key=lambda p: p["id"])
        },
    }


def write_lock(run: dict, path: Path) -> dict:
    lock = lock_from_run(run)
    path.write_text(json.dumps(lock, indent=2) + "\n")
    return lock


def read_lock(path: Path) -> dict:
    lock = json.loads(path.read_text())
    if lock.get("version") != LOCK_VERSION:
        raise ConfigError(f"{path}: unsupported lock version {lock.get('version')}")
    return lock


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _rule_matches(rule: dict, processor: dict, category: str) -> bool:
    if "data" in rule and category not in _as_list(rule["data"]):
        return False
    if "processor" in rule and not any(fnmatch(processor["id"], p) for p in _as_list(rule["processor"])):
        return False
    if "country" in rule and processor["country"] not in _as_list(rule["country"]):
        return False
    if "country_not" in rule and processor["country"] in _as_list(rule["country_not"]):
        return False
    return True


def check(run: dict, lock: dict | None, config: dict) -> list[dict]:
    """Return issues; any issue with level "fail" should fail CI."""
    issues = []
    locked = (lock or {}).get("processors", {})
    for p in run["processors"]:
        cats = sorted(p["data"])
        for cat in cats:
            for rule in config["deny"]:
                if _rule_matches(rule, p, cat):
                    reason = rule.get("reason", "matches a deny rule in leakmap.yaml")
                    issues.append(_issue("fail", "denied", p, cat, f"{p['data'][cat]['label']} sent to {p['name']} ({p['country']}): {reason}"))
        if lock is None:
            continue
        if p["id"] not in locked:
            if cats:
                issues.append(_issue("fail", "new_processor", p, None, f"New recipient of personal data: {p['name']} ({p['country']}) receives {', '.join(p['data'][c]['label'] for c in cats)}"))
            else:
                level = "fail" if config["fail_on_new_processor"] else "warn"
                issues.append(_issue(level, "new_processor", p, None, f"New third party contacted: {p['name']} ({p['country']}), no personal data seen"))
            continue
        for cat in cats:
            if cat not in locked[p["id"]]["data"]:
                d = p["data"][cat]
                issues.append(_issue("fail", "new_data", p, cat, f"{p['name']} ({p['country']}) now receives {d['label']} via {', '.join(d['fields'][:3])}"))
    seen = {p["id"]: p for p in run["processors"]}
    for pid, entry in locked.items():
        gone = [c for c in entry["data"] if pid not in seen or c not in seen[pid]["data"]]
        if gone:
            issues.append({"level": "info", "code": "not_seen", "processor": pid, "data": None,
                           "message": f"Not seen this run (update the baseline if removed for good): {entry['name']}: {', '.join(gone)}"})
    return issues


def _issue(level, code, p, cat, message) -> dict:
    return {"level": level, "code": code, "processor": p["id"], "data": cat, "message": message}
