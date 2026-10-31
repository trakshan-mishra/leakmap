"""A small fake AI support bot with realistic leaks, used by `leakmap demo` and the tests.

All values are fake. It only runs under leakmap in stub mode, so nothing it
sends ever reaches the real services.
"""

import json
import os
import sys
import urllib.request

CUSTOMER = {
    "first_name": "Rahul",
    "email": "rahul.k@example.com",
    "phone": "+91 98765 43210",
    "aadhaar": "2000 0000 0009",  # fake, but passes the Verhoeff check
    "pan": "ABCPK1234F",
    "upi": "rahul.demo@okaxis",
}


def post(url: str, payload, content_type: str = "application/json") -> None:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": content_type})
    urllib.request.urlopen(req, timeout=10).read()


def main() -> int:
    if os.environ.get("LEAKMAP_ACTIVE") != "1":
        print("demo_app only runs under `leakmap demo` (stub mode).", file=sys.stderr)
        return 2
    c = CUSTOMER
    question = f"Hi, I'm {c['first_name']}. Please update my KYC, Aadhaar {c['aadhaar']}, call me on {c['phone']}."

    # 1. The whole customer message goes into the LLM prompt.
    post("https://api.openai.com/v1/chat/completions", {
        "model": "gpt-4.1-mini",
        "messages": [{"role": "system", "content": "You are a support agent."}, {"role": "user", "content": question}],
    })

    # 2. The tracing SDK ships the same prompt, JSON-encoded inside its own payload.
    post("https://cloud.langfuse.com/api/public/ingestion", {"batch": [{
        "type": "trace-create",
        "body": {"name": "support-chat", "userId": c["email"], "input": json.dumps({"messages": [{"role": "user", "content": question}]})},
    }]})

    # 3. An exception message and user context end up in the error tracker.
    envelope = "\n".join(json.dumps(x) for x in [
        {"event_id": "9ec79c33ec9942ab8353589fcb2e04dc"},
        {"type": "event"},
        {"exception": {"values": [{"type": "ValueError", "value": f"KYC lookup failed for PAN {c['pan']}"}]},
         "user": {"email": c["email"], "ip_address": "49.36.12.7"}},
    ])
    post("https://o450123.ingest.us.sentry.io/api/4505/envelope/", envelope.encode(), "application/x-sentry-envelope")

    # 4. Product analytics with "helpful" properties.
    post("https://api.mixpanel.com/track", [{
        "event": "refund_requested",
        "properties": {"distinct_id": "u_1842", "first_name": c["first_name"], "upi_id": c["upi"], "phone": c["phone"]},
    }])

    # 5. Payment provider in India: expected, stays in the country.
    post("https://api.razorpay.com/v1/orders", {"amount": 49900, "currency": "INR", "notes": {"phone": c["phone"], "email": c["email"]}})

    # 6. A vendor nobody added to the inventory.
    post("https://api.acme-crm.example/v2/contacts", {"full_name": "Rahul Kumar", "dob": "1996-04-12", "address": "12 MG Road, Bengaluru"})

    # 7. Analytics ping without personal data.
    post("https://www.google-analytics.com/g/collect?v=2&en=page_view", b"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
