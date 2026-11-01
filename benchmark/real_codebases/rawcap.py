"""Ground-truth capture: same options and stub as leakmap's addon, but saves raw bodies."""
import base64
import json
from mitmproxy import ctx, http

class RawCap:
    def load(self, loader):
        loader.add_option("leakmap_out", str, "", "")
        loader.add_option("leakmap_stub", bool, False, "")
    def request(self, flow):
        r = flow.request
        with open(ctx.options.leakmap_out + ".raw.jsonl", "a") as f:
            f.write(json.dumps({"host": r.pretty_host, "method": r.method, "path": r.path,
                                "ct": r.headers.get("content-type", ""),
                                "body": base64.b64encode(r.raw_content or b"").decode()}) + "\n")
        if ctx.options.leakmap_stub:
            flow.response = http.Response.make(200, b"{}", {"content-type": "application/json"})

addons = [RawCap()]
