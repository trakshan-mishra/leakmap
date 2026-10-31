"""Schema-less protobuf reader for OTLP exports.

Most AI tracing SDKs (Langfuse v3+, Logfire, Arize, Traceloop) send
OpenTelemetry protobuf. Prompts live in span attributes, which are KeyValue
messages: field 1 is the key, field 2 an AnyValue whose field 1 is the string.
We read the wire format directly and name each string by its attribute key, so
no generated OTLP classes are needed.
"""

MAX_DEPTH = 32


class _Bad(Exception):
    pass


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        if i >= len(buf) or shift > 63:
            raise _Bad
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _fields(buf: bytes) -> list[tuple[int, object]]:
    """Parse one message. Length-delimited values are returned as bytes."""
    out, i = [], 0
    while i < len(buf):
        tag, i = _varint(buf, i)
        num, wire = tag >> 3, tag & 7
        if num == 0:
            raise _Bad
        if wire == 0:
            _, i = _varint(buf, i)
            out.append((num, None))
        elif wire == 1:
            i += 8
            out.append((num, None))
        elif wire == 2:
            n, i = _varint(buf, i)
            if i + n > len(buf):
                raise _Bad
            out.append((num, buf[i:i + n]))
            i += n
        elif wire == 5:
            i += 4
            out.append((num, None))
        else:
            raise _Bad
    if i != len(buf):
        raise _Bad
    return out


def _as_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and all(c.isprintable() or c in "\n\r\t" for c in text):
        return text
    return None


def _as_message(raw: bytes):
    try:
        return _fields(raw) if raw else None
    except _Bad:
        return None


def _leaves(fields, path: str, depth: int):
    if depth > MAX_DEPTH:
        return
    # KeyValue: {1: key string, 2: AnyValue message}
    keys = [v for n, v in fields if n == 1 and isinstance(v, bytes)]
    vals = [v for n, v in fields if n == 2 and isinstance(v, bytes)]
    if len(keys) == 1 and len(vals) == 1:
        key = _as_text(keys[0])
        inner = _as_message(vals[0]) if key else None
        if key and inner is not None:
            yield from _leaves(inner, f"{path}.{key}" if path else key, depth + 1)
            return
    for num, raw in fields:
        if not isinstance(raw, bytes):
            continue
        text = _as_text(raw)
        if text is not None:
            yield path or f"field{num}", (path.rsplit(".", 1)[-1] if path else ""), text
            continue
        inner = _as_message(raw)
        if inner is not None:
            yield from _leaves(inner, path, depth + 1)


def parses(buf: bytes) -> bool:
    return _as_message(buf) is not None


def strings(buf: bytes):
    """Yield (path, key, text) for every string in a protobuf message, or nothing if it isn't one."""
    fields = _as_message(buf)
    if fields is None:
        return
    for path, key, text in _leaves(fields, "", 0):
        yield f"otlp.{path}", key, text


def grpc_payloads(buf: bytes):
    """Split gRPC length-prefixed frames (1 byte flag + 4 bytes length)."""
    i = 0
    while i + 5 <= len(buf):
        n = int.from_bytes(buf[i + 1:i + 5], "big")
        yield buf[i + 5:i + 5 + n]
        i += 5 + n
