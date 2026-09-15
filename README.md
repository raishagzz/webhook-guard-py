# webhook-guard-py

A signature-verified webhook receiver in Python: HMAC verification with
constant-time comparison, replay-window enforcement, and idempotent
delivery handling.

Python port of [webhook-guard](https://github.com/raishagzz/webhook-guard)
(TypeScript). Both implement the same contract and the same test scenarios.

![CI](https://github.com/raishagzz/webhook-guard-py/actions/workflows/ci.yml/badge.svg)

## Why

Webhook endpoints are public URLs. Anything that reaches one is untrusted
until proven otherwise. This service answers four questions before a payload
is allowed to do anything:

1. Is the signature authentic?
2. Is the delivery recent?
3. Has this event already been processed?
4. Are we verifying the original bytes, or a re-serialized copy?

## Request flow

```mermaid
flowchart TD
    A[POST /webhooks/provider] --> B[Capture raw body bytes]
    B --> C{Signature valid?}
    C -->|No| D[400 — reject, do not retry]
    C -->|Yes| E{Within replay window?}
    E -->|No| D
    E -->|Yes| F{Event ID already processed?}
    F -->|Yes| G[200 — already handled, stop retrying]
    F -->|No| H[Dispatch to handler]
    H --> I[Record event ID]
    I --> J[200 — acknowledged]
    H -->|Handler failed| K[500 — retry welcome]
```

## Status

- [x] Project scaffold and CI
- [ ] Signature verification
- [ ] Replay-window enforcement
- [ ] Idempotency store
- [ ] FastAPI receiver
- [ ] Threat model and OpenAPI spec

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

## License

MIT
