"""FastAPI receiver wiring signature, replay, and idempotency guards together.

The raw request body is read before anything parses it. The signature covers
the exact bytes the provider sent, and re-serializing parsed JSON produces
different bytes — different key order or spacing is enough to break every
signature.

Status codes are instructions to the provider's retry machinery:

* 400 — the delivery is invalid and will never become valid; stop retrying.
* 200 — accepted, or already processed; stop retrying.
* 500 — the handler failed; retry is welcome.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel

from webhook_guard.config import Settings, get_settings
from webhook_guard.idempotency import IdempotencyStore, InMemoryIdempotencyStore
from webhook_guard.replay import ReplayError, verify_timestamp
from webhook_guard.signature import SignatureError, verify_signature

SIGNATURE_HEADER = "X-Webhook-Signature"
TIMESTAMP_HEADER = "X-Webhook-Timestamp"

_store = InMemoryIdempotencyStore()


def get_store() -> IdempotencyStore:
    return _store


class DeliveryAccepted(BaseModel):
    """Acknowledgment returned for both accepted and duplicate deliveries."""

    event_id: str
    status: str


app = FastAPI(
    title="webhook-guard",
    version="0.1.0",
    description=(
        "Signature-verified webhook receiver with replay protection and "
        "idempotent delivery handling."
    ),
)


def handle_event(event: dict[str, Any]) -> None:
    """Application handler. Replace with real work.

    Runs at most once per event under normal operation, but may run twice if
    the process dies between completing and recording the claim.
    """


@app.post(
    "/webhooks/provider",
    response_model=DeliveryAccepted,
    status_code=status.HTTP_200_OK,
    summary="Receive a signed webhook delivery",
    responses={
        400: {"description": "Signature, timestamp, or payload rejected"},
        500: {"description": "Handler failed; retry is welcome"},
    },
)
async def receive(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[IdempotencyStore, Depends(get_store)],
    signature: Annotated[str | None, Header(alias=SIGNATURE_HEADER)] = None,
    timestamp: Annotated[str | None, Header(alias=TIMESTAMP_HEADER)] = None,
) -> DeliveryAccepted:
    body = await request.body()

    try:
        verify_signature(settings.signing_secret, timestamp or "", body, signature or "")
        verify_timestamp(timestamp or "", settings.replay_tolerance_seconds)
    except (SignatureError, ReplayError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    try:
        event = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "payload is not valid JSON") from exc

    if not isinstance(event, dict) or not event.get("id"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "payload is missing an event id")

    event_id = str(event["id"])

    if not store.claim(event_id):
        return DeliveryAccepted(event_id=event_id, status="duplicate")

    try:
        handle_event(event)
    except Exception as exc:
        store.release(event_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "handler failed") from exc

    return DeliveryAccepted(event_id=event_id, status="accepted")
