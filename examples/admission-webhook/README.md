# Example admission webhook receiver

This is an example, not a supported product.
It shows how to receive the rustdesk-api admission webhook (see `docs/admission-webhook.md`).
Copy it and adapt it to your own inventory.

The receiver checks the Ed25519 signature of each request.
It answers `401` to an unsigned request, a wrongly signed request, or a request older than `MAX_AGE`.
A signed request gets `200` with `{"decision": "admit|reject|pending", "reason": "..."}`.
A body that is not a JSON object, or a bad `Content-Length`, gets `400`. A body over 64 KiB gets `413`.
Any URL path is accepted.

## Environment

| Variable | Meaning | Default |
|---|---|---|
| `PUBLIC_KEYS` | Comma-separated base64 Ed25519 public keys. Any one may verify (key rotation). | required |
| `RULES_FILE` | Path to the rules YAML | `/etc/admission-webhook/rules.yaml` |
| `PORT` | Listen port | `8080` |
| `MAX_AGE` | Largest accepted age of the signature, in seconds | `300` |

## Rules

See `rules.example.yaml`.
`rules` is a list. Each rule has a `decision` (`admit` or `reject`) and a `match`.
A `match` has `hostnames` (globs, not case-sensitive), `subnets` (CIDR) and `owner_groups`.
The first rule with any true condition wins.
An empty `ip` never matches a subnet. An owner of `null` never matches an owner group.
`default` is used when no rule matches (`pending` if absent).
The `reason` in the answer names the rule, for example `rule 1: admit`, or `default`.

Hostnames are reported by the device itself. Anyone can set one.
Do not use a hostname alone to admit devices in a real deployment.

## Run

```
PUBLIC_KEYS=$(rustdesk-api admission pubkey) RULES_FILE=rules.example.yaml python3 receiver.py
```

Install the requirements first: `pip install -r requirements.txt`.

## Test

```
python3 -m unittest test_receiver.py -v
```

## Build the image

```
docker build -t admission-webhook-example .
```

Mount the rules file at `/etc/admission-webhook/rules.yaml` and set `PUBLIC_KEYS`.
The container runs as uid 1000, so the mounted rules file must be readable by uid 1000.
The receiver exits with an error at start when the rules file is invalid.
