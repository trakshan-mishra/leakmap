"""Generate the labeled benchmark corpus.

Two splits with disjoint sentence templates and field names:
  dev   used while tuning detectors
  test  held out; only scored, never tuned against

Every sample is a real request body (chat JSON, analytics JSON, log line,
Sentry envelope, form body, OTLP JSON with JSON inside) carrying 1-3 items.
Items are positives (labeled personal data or secrets) or hard negatives
(values that look similar but are not personal data). Values are synthetic
but valid: Aadhaar passes Verhoeff, cards pass Luhn with real issuer ranges,
GSTIN has a correct check character.

    python benchmark/generate.py   # writes benchmark/data/{dev,test}.jsonl
"""

import ipaddress
import json
import random
import string
import uuid
from pathlib import Path
from urllib.parse import urlencode

from leakmap.validators import _GSTIN_CHARS, verhoeff_check_digit

OUT = Path(__file__).parent / "data"
N_SAMPLES = 1500

# ---------------------------------------------------------------- values --


def luhn_complete(prefix: str, length: int, rng) -> str:
    body = prefix + "".join(rng.choice(string.digits) for _ in range(length - len(prefix) - 1))
    for d in string.digits:
        digits = body + d
        total = 0
        for i, ch in enumerate(reversed(digits)):
            n = int(ch)
            if i % 2 == 1:
                n = n * 2 - 9 if n * 2 > 9 else n * 2
            total += n
        if total % 10 == 0:
            return digits
    raise AssertionError


def group(digits: str, sizes, sep: str) -> str:
    out, i = [], 0
    for s in sizes:
        out.append(digits[i:i + s])
        i += s
    return sep.join(out)


class Values:
    FIRST = ["Rahul", "Priya", "Amit", "Sneha", "Arjun", "Kavya", "Rohan", "Ananya", "Vikram", "Meera", "Imran", "Fatima", "Harpreet", "Lakshmi", "Suresh", "Neha"]
    LAST = ["Sharma", "Verma", "Iyer", "Reddy", "Khan", "Singh", "Patel", "Nair", "Gupta", "Das", "Mehta", "Kulkarni", "Banerjee", "Joshi"]
    DOMAINS = ["gmail.com", "yahoo.co.in", "outlook.com", "rediffmail.com", "hotmail.com", "acme.in", "zoho.com", "proton.me", "iitp.ac.in"]
    HANDLES = ["okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "ibl", "axl", "paytm", "upi", "apl"]
    BANKS = ["HDFC", "SBIN", "ICIC", "UTIB", "PUNB", "KKBK", "BARB", "CNRB", "IDIB", "YESB"]
    CITIES = ["Noida", "Pune", "Bengaluru", "Chennai", "Kolkata", "Jaipur", "Lucknow", "Kochi"]

    def __init__(self, rng: random.Random):
        self.r = rng

    def digits(self, n, first=string.digits):
        return self.r.choice(first) + "".join(self.r.choice(string.digits) for _ in range(n - 1))

    def aadhaar(self):
        while True:
            base = self.digits(11, "23456789")
            num = base + verhoeff_check_digit(base)
            if not (num.startswith("91") and num[2] in "6789"):
                break
        return self.r.choice([num, group(num, (4, 4, 4), " "), group(num, (4, 4, 4), "-")])

    def pan(self, holder=None):
        L = string.ascii_uppercase
        return "".join(self.r.choice(L) for _ in range(3)) + (holder or self.r.choice("PPPPPPCFHT")) + self.r.choice(L) + self.digits(4) + self.r.choice(L)

    def gstin(self):
        head = f"{self.r.randint(1, 37):02d}" + self.pan(self.r.choice("CFP")) + self.r.choice("123456789") + "Z"
        total = 0
        for i, ch in enumerate(head):
            p = _GSTIN_CHARS.index(ch) * (1 if i % 2 == 0 else 2)
            total += p // 36 + p % 36
        return head + _GSTIN_CHARS[(36 - total % 36) % 36]

    def name(self):
        return f"{self.r.choice(self.FIRST)} {self.r.choice(self.LAST)}"

    def email(self):
        f, l = self.r.choice(self.FIRST).lower(), self.r.choice(self.LAST).lower()
        local = self.r.choice([f"{f}.{l}", f"{f}{l}{self.r.randint(1, 99)}", f"{f[0]}{l}", f"{f}_{l}", f"{f}+orders"])
        return f"{local}@{self.r.choice(self.DOMAINS)}"

    def upi(self):
        f = self.r.choice(self.FIRST).lower()
        return f"{self.r.choice([f, f + str(self.r.randint(1, 999)), self.digits(10, '6789')])}@{self.r.choice(self.HANDLES)}"

    def phone(self):
        n = self.digits(10, "6789")
        return self.r.choice([
            n, "+91" + n, "+91 " + n, "+91-" + n, "0" + n, "91" + n,
            "+91 " + n[:5] + " " + n[5:], n[:5] + " " + n[5:],
        ])

    def card(self):
        kind = self.r.choice(["visa", "mc", "mc2", "amex", "rupay", "rupay2"])
        if kind == "amex":
            num = luhn_complete(self.r.choice(["34", "37"]), 15, self.r)
            return self.r.choice([num, group(num, (4, 6, 5), " ")])
        prefix = {"visa": "4", "mc": str(self.r.randint(51, 55)), "mc2": str(self.r.randint(2221, 2720)),
                  "rupay": self.r.choice(["60", "65", "81", "82"]), "rupay2": "508"}[kind]
        num = luhn_complete(prefix, 16, self.r)
        return self.r.choice([num, group(num, (4, 4, 4, 4), " "), group(num, (4, 4, 4, 4), "-")])

    def ip(self):
        while True:
            ip = ipaddress.IPv4Address(self.r.randint(1, 2**32 - 1))
            if ip.is_global:
                return str(ip)

    def ifsc(self):
        return self.r.choice(self.BANKS) + "0" + self.r.choice([self.digits(6), "".join(self.r.choice(string.ascii_uppercase + string.digits) for _ in range(6))])

    def secret(self):
        a = string.ascii_letters + string.digits
        return self.r.choice([
            "sk-proj-" + "".join(self.r.choice(a + "_-") for _ in range(48)),
            "sk-ant-api03-" + "".join(self.r.choice(a + "_-") for _ in range(93)),
            "AKIA" + "".join(self.r.choice(string.ascii_uppercase + string.digits) for _ in range(16)),
            "ghp_" + "".join(self.r.choice(a) for _ in range(36)),
            "AIza" + "".join(self.r.choice(a + "_-") for _ in range(35)),
            "rzp_live_" + "".join(self.r.choice(a) for _ in range(14)),
        ])

    def dob(self):
        return f"{self.r.randint(1960, 2006)}-{self.r.randint(1, 12):02d}-{self.r.randint(1, 28):02d}"

    def address(self):
        return f"{self.r.randint(1, 300)}, {self.r.choice(['MG Road', 'Sector 62', 'Anna Salai', 'Park Street', 'FC Road'])}, {self.r.choice(self.CITIES)}"

    # ---- hard negatives: (sentence, key, value) producers
    def imei(self):
        return luhn_complete(self.r.choice(["35", "86", "01"]), 15, self.r)

    def iccid(self):
        return luhn_complete("8991", self.r.choice([19, 20]), self.r)


# ------------------------------------------------------------- templates --
# {v} is the value. DEV and TEST never share a template or a field name.

POS = {
    "dev": {
        "aadhaar": (["My Aadhaar number is {v}", "aadhar {v} hai mera, KYC update karo", "UIDAI no: {v}", "Please verify Aadhaar {v} for the account"],
                    ["aadhaar", "aadhaar_number", "uid"]),
        "pan": (["PAN: {v}", "my pan card is {v}", "Kindly link PAN {v}"], ["pan", "pan_number"]),
        "gstin": (["GSTIN {v} for the invoice", "our gst no is {v}"], ["gstin", "gst_number"]),
        "upi_id": (["send the refund to {v}", "UPI: {v}", "pay me at {v}"], ["upi", "vpa"]),
        "email": (["reach me at {v}", "my email is {v}", "Mail the invoice to {v} please"], ["email", "user_email", "contact_email"]),
        "phone_in": (["call me on {v}", "my mobile is {v}", "WhatsApp {v} after 6pm", "contact: {v}"], ["phone", "mobile", "whatsapp_number"]),
        "card": (["charge my card {v}", "card number {v} exp 08/29", "Use the debit card {v}"], ["card_number", "cc_number"]),
        "ip_address": (["login from IP {v}", "client ip: {v}"], ["ip", "client_ip"]),
        "ifsc": (["IFSC code {v}", "bank IFSC: {v}"], ["ifsc", "ifsc_code"]),
        "secret": (["here is my key {v}", "export OPENAI_API_KEY={v}", "token={v}"], ["password", "client_secret"]),
    },
    "test": {
        "aadhaar": (["Aadhaar card no. {v} attached", "mera aadhaar {v} hai", "aadhaar: {v}", "UID {v} linked to the wallet"],
                    ["aadhaar_no", "aadhar_id"]),
        "pan": (["PAN number {v}", "Pan card - {v}", "attach pan {v} to profile"], ["pan_card", "pan_no"]),
        "gstin": (["GST registration {v}", "supplier GSTIN: {v}"], ["gstin_no", "supplier_gstin"]),
        "upi_id": (["my upi id is {v}", "refund via {v}", "VPA {v}"], ["upi_id", "payee_vpa"]),
        "email": (["email: {v}", "you can write to {v}", "send OTP to {v}"], ["email_address", "customer_email"]),
        "phone_in": (["phone {v}", "ping me on whatsapp {v}", "mob: {v}", "my number is {v}, call anytime"], ["phone_number", "mobile_no", "contact_number"]),
        "card": (["credit card {v}", "pay using card {v}", "card: {v} cvv 123"], ["card", "card_no"]),
        "ip_address": (["request came from ip {v}", "remote addr {v}"], ["ip_address", "user_ip"]),
        "ifsc": (["ifsc {v}", "branch IFSC is {v}"], ["bank_ifsc", "ifsc_no"]),
        "secret": (["my api key is {v}", "Authorization uses {v}", "leaked key {v}"], ["secret_key", "private_key"]),
    },
}
STRUCT_ONLY = {
    "dev": {"person_name": ["first_name", "full_name"], "date_of_birth": ["dob"], "address": ["address", "shipping_address"]},
    "test": {"person_name": ["customer_name", "last_name"], "date_of_birth": ["date_of_birth"], "address": ["billing_address", "street"]},
}
GEN = {"aadhaar": "aadhaar", "pan": "pan", "gstin": "gstin", "upi_id": "upi", "email": "email", "phone_in": "phone",
       "card": "card", "ip_address": "ip", "ifsc": "ifsc", "secret": "secret", "person_name": "name",
       "date_of_birth": "dob", "address": "address"}

# Hard negatives: (sentence template, key, value factory)
NEG = {
    "dev": [
        ("Order #{v} has shipped", "order_id", lambda v: v.digits(10, "6789")),
        ("tracking number {v}", "tracking_number", lambda v: v.digits(12, "23456789")),
        ("device IMEI {v}", "imei", lambda v: v.imei()),
        ("SIM ICCID {v}", "iccid", lambda v: v.iccid()),
        ("session {v} started", "session_id", lambda v: str(uuid.UUID(int=v.r.getrandbits(128)))),
        ("trace {v}", "trace_id", lambda v: "%032x" % v.r.getrandbits(128)),
        ("ts={v}", "timestamp", lambda v: str(v.r.randint(1_700_000_000_000, 1_800_000_000_000))),
        ("build version {v}", "version", lambda v: f"{v.r.randint(1, 20)}.{v.r.randint(0, 9)}.{v.r.randint(0, 9)}.{v.r.randint(0, 99)}"),
        ("loading icon@2x.png", "asset", lambda v: "logo@2x.png"),
        ("cloned git@github.com:acme/app.git", "remote", lambda v: "git@github.com:acme/app.git"),
        ("from noreply@acme.in", "sender", lambda v: "noreply@acme.in"),
        ("amount {v} paise", "amount", lambda v: str(v.r.randint(100, 9_999_999))),
        ("OTP is {v}", "otp", lambda v: v.digits(6)),
        ("PNR {v}", "pnr", lambda v: v.digits(10, "6789")),
        ("dsn https://{v}@o4505.ingest.sentry.io/1", "dsn", lambda v: "%032x" % v.r.getrandbits(128)),
        ("phc key {v}", "api_key", lambda v: "phc_" + "".join(v.r.choice(string.ascii_letters) for _ in range(43))),
        ("model gpt-4.1-mini answered in {v} ms", "latency_ms", lambda v: str(v.r.randint(100, 9999))),
        ("ISBN {v}", "isbn", lambda v: "978" + v.digits(10)),
        ("ticket {v} resolved", "ticket_id", lambda v: v.digits(12, "23456789")),
        ("sha {v}", "digest", lambda v: "%064x" % v.r.getrandbits(256)),
    ],
    "test": [
        ("Your booking ref {v} is confirmed", "booking_ref", lambda v: v.digits(10, "6789")),
        ("AWB {v} out for delivery", "awb", lambda v: v.digits(12, "23456789")),
        ("imei: {v}", "device_imei", lambda v: v.imei()),
        ("serial no {v}", "serial", lambda v: v.digits(16, "3456")),
        ("request {v}", "request_id", lambda v: str(uuid.UUID(int=v.r.getrandbits(128)))),
        ("span {v}", "span_id", lambda v: "%016x" % v.r.getrandbits(64)),
        ("created_at {v}", "created_at", lambda v: str(v.r.randint(1_700_000_000, 1_800_000_000))),
        ("v{v} released", "release", lambda v: f"{v.r.randint(1, 20)}.{v.r.randint(0, 9)}.{v.r.randint(0, 9)}"),
        ("avatar@3x.webp missing", "file", lambda v: "avatar@3x.webp"),
        ("do-not-reply@bank.in sent it", "from", lambda v: "do-not-reply@bank.in"),
        ("price {v}", "price", lambda v: str(v.r.randint(100, 99_999_999))),
        ("verification code {v}", "otp_code", lambda v: v.digits(6)),
        ("invoice no {v}", "invoice_no", lambda v: v.digits(10, "6789")),
        ("product sku {v}", "sku", lambda v: v.digits(13, "8")),
        ("policy number {v}", "policy_no", lambda v: v.digits(12, "23456789")),
        ("short key sk-fake-123", "note", lambda v: "sk-fake-123"),
        ("took {v} bytes", "bytes", lambda v: str(v.r.randint(1000, 99_999_999))),
        ("EAN {v}", "ean", lambda v: "890" + v.digits(10)),
        ("txn id {v}", "txn_id", lambda v: v.digits(12, "23456789")),
        ("commit {v}", "commit", lambda v: "%040x" % v.r.getrandbits(160)),
    ],
}

# --------------------------------------------------------------- carriers --


def carrier(rng, items, split):
    """items: list of (sentence, key, value). Returns (content_type, body str)."""
    kind = rng.choice(["chat", "props", "log", "sentry", "form", "otlp"])
    text = ". ".join(s for s, _, _ in items)
    if kind == "chat":
        return "application/json", json.dumps({"model": "gpt-4.1-mini", "messages": [
            {"role": "system", "content": "You are a helpful support agent for an Indian fintech app."},
            {"role": "user", "content": text}]})
    if kind == "props":
        return "application/json", json.dumps({"event": "profile_updated", "distinct_id": str(uuid.UUID(int=rng.getrandbits(128))),
                                               "properties": {k: v for _, k, v in items}})
    if kind == "log":
        return "text/plain", f"2026-10-31T10:22:{rng.randint(10, 59)}Z INFO svc=checkout {text}"
    if kind == "sentry":
        return "application/x-sentry-envelope", "\n".join(json.dumps(x) for x in [
            {"event_id": "%032x" % rng.getrandbits(128)}, {"type": "event"},
            {"exception": {"values": [{"type": "ValueError", "value": text}]}, "platform": "python"}])
    if kind == "form":
        return "application/x-www-form-urlencoded", urlencode({k: v for _, k, v in items})
    return "application/json", json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "chat", "attributes": [
        {"key": "gen_ai.prompt", "value": {"stringValue": json.dumps({"messages": [{"role": "user", "content": text}]})}}]}]}]}]})


def build(split: str, seed: int):
    rng = random.Random(seed)
    v = Values(rng)
    pos_cats = list(POS[split]) + list(STRUCT_ONLY[split])
    samples = []
    for i in range(N_SAMPLES):
        items, labels = [], []
        used_keys = set()
        for _ in range(rng.choice([1, 1, 2, 3])):
            if rng.random() < 0.55:
                cat = rng.choice(pos_cats)
                value = getattr(v, GEN[cat])()
                if cat in POS[split]:
                    templates, keys = POS[split][cat]
                    items.append((rng.choice(templates).format(v=value), rng.choice(keys), value))
                else:
                    key = rng.choice(STRUCT_ONLY[split][cat])
                    items.append((None, key, value))
                labels.append({"category": cat, "value": value})
            else:
                template, key, make = rng.choice(NEG[split])
                value = make(v)
                items.append((template.format(v=value), key, value))
        # Keys must be unique or a dict carrier would drop values.
        uniq = []
        for s_, k, val in items:
            while k in used_keys:
                k += "_2"
            used_keys.add(k)
            uniq.append((s_, k, val))
        items = uniq
        # Field-name-only items cannot be expressed as sentences; force a structured carrier.
        if any(s is None for s, _, _ in items):
            items = [(s or "", k, val) for s, k, val in items]
            ct, body = ("application/json", json.dumps({"customer": {k: val for _, k, val in items}}))
        else:
            ct, body = carrier(rng, items, split)
        samples.append({"id": f"{split}-{i}", "content_type": ct, "body": body, "labels": labels})
    return samples


def main():
    OUT.mkdir(exist_ok=True)
    for split, seed in (("dev", 1), ("test", 2)):
        samples = build(split, seed)
        with open(OUT / f"{split}.jsonl", "w") as f:
            for s in samples:
                f.write(json.dumps(s) + "\n")
        n_pos = sum(len(s["labels"]) for s in samples)
        print(f"{split}: {len(samples)} samples, {n_pos} labeled values")


if __name__ == "__main__":
    main()
