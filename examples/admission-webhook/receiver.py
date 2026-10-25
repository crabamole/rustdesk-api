"""Example admission webhook receiver for rustdesk-api (docs/admission-webhook.md).

This is an example, not a supported product. It verifies the api-server's Ed25519 signature
and decides by rules from a YAML file. Copy it and adapt it to your own inventory.
"""
import base64
import fnmatch
import ipaddress
import json
import logging
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HEADER = "X-Admission-Signature"
MAX_BODY = 64 * 1024
_HEADER_RE = re.compile(r"^t=(\d+),ed25519=([A-Za-z0-9+/=]+)$")


def load_keys(value: str) -> list:
    """Public keys from a comma-separated list of base64 raw Ed25519 keys."""
    return [Ed25519PublicKey.from_public_bytes(base64.b64decode(k.strip())) for k in value.split(",") if k.strip()]


def verify(header: str, body: bytes, keys: list, now: float, max_age: int):
    """None when `header` is a fresh signature of "<t>.<body>" by one of `keys`, else the reason."""
    m = _HEADER_RE.match(header or "")
    if not m:
        return "missing or malformed signature"
    t = int(m.group(1))
    if abs(now - t) > max_age:
        return "signature too old"
    try:
        sig = base64.b64decode(m.group(2))
    except ValueError:
        return "malformed signature"
    message = f"{t}.".encode() + body
    for key in keys:
        try:
            key.verify(sig, message)
            return None
        except InvalidSignature:
            continue
    return "bad signature"


def _matches(device: dict, match: dict) -> bool:
    host = (device.get("hostname") or "").lower()
    if host and any(fnmatch.fnmatchcase(host, p.lower()) for p in match.get("hostnames", [])):
        return True
    try:
        ip = ipaddress.ip_address(device.get("ip") or "")
    except ValueError:
        ip = None
    if ip and any(ip in ipaddress.ip_network(n, strict=False) for n in match.get("subnets", [])):
        return True
    group = ((device.get("owner") or {}).get("group")) or ""
    return bool(group) and group in match.get("owner_groups", [])


def decide(device: dict, rules: dict):
    """(decision, reason): the first matching rule's decision, else the default."""
    for i, rule in enumerate(rules.get("rules") or [], start=1):
        if _matches(device, rule.get("match") or {}):
            return rule["decision"], f"rule {i}: {rule['decision']}"
    return rules.get("default", "pending"), "default"


def validate_rules(rules) -> None:
    """Raise ValueError with a clear message when the rules file is not usable."""
    if not isinstance(rules, dict):
        raise ValueError("rules file must be a mapping")
    if rules.get("default", "pending") not in ("admit", "reject", "pending"):
        raise ValueError("default must be admit, reject or pending")
    for i, rule in enumerate(rules.get("rules") or [], start=1):
        if not isinstance(rule, dict) or rule.get("decision") not in ("admit", "reject"):
            raise ValueError(f"rule {i}: decision must be admit or reject")
        for net in (rule.get("match") or {}).get("subnets", []):
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError:
                raise ValueError(f"rule {i}: invalid subnet {net!r}") from None


class Handler(BaseHTTPRequestHandler):
    keys: list = []
    rules: dict = {}
    max_age: int = 300
    timeout = 10

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, {"error": "invalid Content-Length"})
        if length < 0:
            return self._send(400, {"error": "invalid Content-Length"})
        if length > MAX_BODY:
            return self._send(413, {"error": "body too large"})
        body = self.rfile.read(length)
        problem = verify(self.headers.get(HEADER, ""), body, self.keys, time.time(), self.max_age)
        if problem:
            logging.info("401 %s", problem)
            return self._send(401, {"error": problem})
        try:
            device = json.loads(body)
        except ValueError:
            return self._send(400, {"error": "invalid JSON"})
        if not isinstance(device, dict):
            return self._send(400, {"error": "body must be a JSON object"})
        decision, reason = decide(device, self.rules)
        logging.info("%s %s (%s)", device.get("id", "?"), decision, reason)
        self._send(200, {"decision": decision, "reason": reason})

    def _send(self, status: int, payload: dict):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    Handler.keys = load_keys(os.environ["PUBLIC_KEYS"])
    with open(os.environ.get("RULES_FILE", "/etc/admission-webhook/rules.yaml")) as f:
        Handler.rules = yaml.safe_load(f) or {}
    try:
        validate_rules(Handler.rules)
    except ValueError as e:
        raise SystemExit(f"invalid rules file: {e}")
    Handler.max_age = int(os.environ.get("MAX_AGE", "300"))
    port = int(os.environ.get("PORT", "8080"))
    logging.info("listening on %d with %d key(s), %d rule(s)", port, len(Handler.keys), len(Handler.rules.get("rules") or []))
    ThreadingHTTPServer(("", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
