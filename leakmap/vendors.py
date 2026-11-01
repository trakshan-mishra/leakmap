"""Map a hostname to the company that receives the data."""

from dataclasses import dataclass
from fnmatch import fnmatch
from functools import lru_cache
from importlib import resources

import yaml


@dataclass(frozen=True)
class Vendor:
    id: str
    name: str
    kind: str
    country: str


UNKNOWN_COUNTRY = "??"


@lru_cache(maxsize=1)
def _catalog() -> tuple[list[tuple[str, Vendor]], list[tuple[str, Vendor]]]:
    text = resources.files("leakmap.data").joinpath("vendors.yaml").read_text()
    exact: list[tuple[str, Vendor]] = []
    globs: list[tuple[str, Vendor]] = []
    for entry in yaml.safe_load(text):
        vendor = Vendor(entry["id"], entry["name"], entry["kind"], entry["country"])
        for host in entry["hosts"]:
            (globs if "*" in host else exact).append((host.lower(), vendor))
    # Longest suffix first so api.eu.mailgun.net beats a shorter entry.
    exact.sort(key=lambda hv: -len(hv[0]))
    return exact, globs


def catalog_size() -> int:
    exact, globs = _catalog()
    return len({v.id for _, v in exact + globs})


@lru_cache(maxsize=4096)
def resolve(host: str) -> Vendor:
    host = host.lower().rstrip(".")
    exact, globs = _catalog()
    for pattern, vendor in exact:
        if host == pattern or host.endswith("." + pattern):
            return vendor
    for pattern, vendor in globs:
        if fnmatch(host, pattern):
            return vendor
    return Vendor(f"host:{host}", host, "unclassified", UNKNOWN_COUNTRY)
