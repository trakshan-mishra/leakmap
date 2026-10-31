"""mitmproxy addon loaded by `leakmap run`.

Each request is inspected in-process and only the resulting Event (categories,
field paths, masked samples) is written. Bodies and headers are never stored.
"""

import json
import time

from mitmproxy import ctx, http

from leakmap.detect import inspect_request
from leakmap.model import Event


class Leakmap:
    def __init__(self):
        self._out = None

    def load(self, loader):
        loader.add_option("leakmap_out", str, "", "File to append events to (JSON lines).")
        loader.add_option("leakmap_stub", bool, False, "Answer every request locally instead of forwarding it.")

    def configure(self, updated):
        if "leakmap_out" in updated and ctx.options.leakmap_out:
            self._out = open(ctx.options.leakmap_out, "a", buffering=1)

    def request(self, flow: http.HTTPFlow):
        req = flow.request
        try:
            content_type = req.headers.get("content-type", "")
            form = None
            if "multipart/form-data" in content_type:
                form = [
                    (k.decode("utf-8", "replace") if isinstance(k, bytes) else k, v)
                    for k, v in req.multipart_form.items(multi=True)
                ]
            event = inspect_request(
                req.method,
                req.pretty_host,
                req.path,
                list(req.query.items(multi=True)),
                content_type,
                req.get_content(strict=False) or b"",
                form,
            )
        except Exception:
            # Never break the app under test; record that this request was not inspected.
            event = Event(time.time(), req.method, req.pretty_host.lower(), req.path.split("?", 1)[0], "error")
        if self._out:
            self._out.write(json.dumps(event.to_dict()) + "\n")
        if ctx.options.leakmap_stub:
            flow.response = http.Response.make(200, b"{}", {"content-type": "application/json"})


addons = [Leakmap()]
