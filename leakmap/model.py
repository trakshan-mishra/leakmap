"""Records passed between capture, aggregation and reporting.

Raw values never appear here. A Finding carries the category, where it was
seen and a masked sample, so run files are safe to keep as CI artifacts.
"""

from dataclasses import asdict, dataclass, field

CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Finding:
    category: str
    field: str
    masked: str
    confidence: str
    count: int = 1


@dataclass
class Event:
    ts: float
    method: str
    host: str
    path: str
    inspected: str  # json | ndjson | form | multipart | protobuf | text | empty | binary | too_large
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        return cls(**{**d, "findings": [Finding(**f) for f in d.get("findings", [])]})


def mask(value: str) -> str:
    """Keep enough to recognise the value in your own fixtures, not enough to reuse it."""
    value = value.strip()
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) < 8:
        return value[0] + "*" * (len(value) - 1)
    keep = 2
    return value[:keep] + "*" * (len(value) - 2 * keep) + value[-keep:]
