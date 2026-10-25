# Admission webhook

With `DEVICE_ADMISSION=Y`, a new device is pending until someone admits it.
The webhook lets a service that you own decide.
The api-server asks the webhook. The webhook answers admit, reject or pending.

## Turn it on

Set `ADMISSION_WEBHOOK_URL` and `ADMISSION_WEBHOOK_KEY`.
The webhook runs only with `DEVICE_ADMISSION=Y` (case-insensitive). Without it the webhook is off.
With an empty URL the webhook is off.
Do not put a secret in the webhook URL: administrators see it in the console.
If the URL is set and the key is missing or wrong, the server does not start.

Create the key:

```
rustdesk-api admission keygen
id_ed25519=<private key>
id_ed25519.pub=<public key>
```

Store both lines in a Secret with the keys `id_ed25519` and `id_ed25519.pub`.
`ADMISSION_WEBHOOK_KEY` holds the private value.
This key is used for nothing else.

Give the public key to the receiver.
Get it again with `rustdesk-api admission pubkey` (reads `ADMISSION_WEBHOOK_KEY`)
or from `GET /api/admission/webhook` (admin only).

## When the api-server calls it

Only for pending devices, after:

- a system info upload from the device;
- an owner login on the device;
- `POST /api/peers/<id>/admission-check` (admin) or `rustdesk-api peer admission-check <id>`.

System info and login calls run in the background. The device does not wait.
These device-triggered calls are limited to one per device every 30 seconds, across all replicas.
The console button and the CLI are not limited.
There are no automatic retries.
A failed call leaves the device pending until the next event or until an administrator asks again.

## Request

`POST <url>` with a JSON body:

| Field | Value |
|---|---|
| `id` | the device ID |
| `hostname`, `os`, `username` | from the device's system info (reported by the device) |
| `ip` | the address hbbs saw when the device registered |
| `owner` | `{name, email, group}` of the device's owner, or `null` |
| `first_seen` | when the device first registered |

Header:

```
X-Admission-Signature: t=<unix seconds>,ed25519=<base64 signature of "<t>.<body>">
```

The receiver verifies the signature with the public key.
The receiver refuses a request when `t` is more than 5 minutes old.

## Response

Answer `200` with:

```json
{"decision": "admit", "reason": "known hostname"}
```

`decision` is `admit`, `reject` or `pending`.
`reason` is free text. It goes to the console log.

A timeout (10 s), another status, a redirect or an invalid body is an error.
An error changes nothing. The device stays pending.
The server stores the time and the result (or the error) on the device.
The server checks the receiver's TLS certificate.

The api-server changes the state only while the device is pending.
An admit or reject by an administrator always stands; a device an administrator sets back to pending can be decided by the webhook again.

## Key rotation

1. Run `admission keygen` and note the new public key.
2. Make the receiver accept both public keys.
3. Replace the Secret and restart the api-server.
4. Remove the old public key from the receiver.

## Example receiver

This is an example, not a product.
It admits a device by hostname or by source address.
Change the lists, and add TLS and logging before you use any of it.

```python
import base64, ipaddress, json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PUBLIC_KEY = Ed25519PublicKey.from_public_bytes(base64.b64decode(sys.argv[1]))
HOSTNAMES = {"office-pc-1", "office-pc-2"}
SUBNET = ipaddress.ip_network("192.0.2.0/24")


def verify(header, body):
    parts = dict(p.split("=", 1) for p in header.split(","))
    t = int(parts["t"])
    if abs(time.time() - t) > 300:
        return False
    try:
        PUBLIC_KEY.verify(base64.b64decode(parts["ed25519"]), f"{t}.".encode() + body)
    except InvalidSignature:
        return False
    return True


def decide(device):
    if device.get("hostname") in HOSTNAMES:
        return "admit", "known hostname"
    if ipaddress.ip_address(device["ip"]) in SUBNET:
        return "admit", "address in the office subnet"
    return "pending", "unknown device"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            ok = verify(self.headers.get("X-Admission-Signature", ""), body)
            decision, reason = decide(json.loads(body)) if ok else (None, None)
        except (KeyError, ValueError):
            ok = False
        if not ok:
            self.send_response(401)
            self.end_headers()
            return
        out = json.dumps({"decision": decision, "reason": reason}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
```

Run it with the public key as the only argument.

A runnable example with YAML rules and tests is in `examples/admission-webhook/`.
