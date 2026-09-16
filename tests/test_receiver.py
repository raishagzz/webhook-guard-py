"""End-to-end coverage of the receiver over signed raw payloads."""

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

from webhook_guard.config import Settings
from webhook_guard.idempotency import InMemoryIdempotencyStore
from webhook_guard.receiver import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    app,
    get_settings,
    get_store,
)

SECRET = "whsec_test_secret"
ENDPOINT = "/webhooks/provider"


@pytest.fixture
def store():
    return InMemoryIdempotencyStore()


@pytest.fixture
def client(store):
    app.dependency_overrides[get_settings] = lambda: Settings(signing_secret=SECRET)
    app.dependency_overrides[get_store] = lambda: store
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def deliver(client, body: bytes, secret: str = SECRET, timestamp: str | None = None):
    stamp = timestamp or str(int(time.time()))
    payload = stamp.encode("utf-8") + b"." + body
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return client.post(
        ENDPOINT,
        content=body,
        headers={
            SIGNATURE_HEADER: digest,
            TIMESTAMP_HEADER: stamp,
            "Content-Type": "application/json",
        },
    )


def event(event_id: str = "evt_123") -> bytes:
    return json.dumps({"id": event_id, "type": "payment.succeeded"}).encode("utf-8")


def test_accepts_a_signed_delivery(client):
    response = deliver(client, event())
    assert response.status_code == 200
    assert response.json() == {"event_id": "evt_123", "status": "accepted"}


def test_repeat_delivery_is_acknowledged_without_reprocessing(client):
    body = event()
    assert deliver(client, body).json()["status"] == "accepted"
    second = deliver(client, body)
    assert second.status_code == 200
    assert second.json()["status"] == "duplicate"


def test_rejects_a_bad_signature(client):
    response = deliver(client, event(), secret="whsec_wrong")
    assert response.status_code == 400


def test_rejects_a_tampered_body(client):
    stamp = str(int(time.time()))
    payload = stamp.encode("utf-8") + b"." + event()
    digest = hmac.new(SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    response = client.post(
        ENDPOINT,
        content=event("evt_999"),
        headers={SIGNATURE_HEADER: digest, TIMESTAMP_HEADER: stamp},
    )
    assert response.status_code == 400


def test_rejects_a_stale_delivery(client):
    stale = str(int(time.time()) - 600)
    assert deliver(client, event(), timestamp=stale).status_code == 400


def test_rejects_missing_headers(client):
    assert client.post(ENDPOINT, content=event()).status_code == 400


def test_rejects_invalid_json_that_is_correctly_signed(client):
    assert deliver(client, b"not json at all").status_code == 400


def test_rejects_a_payload_without_an_event_id(client):
    assert deliver(client, json.dumps({"type": "ping"}).encode()).status_code == 400


def test_handler_failure_returns_500_and_releases_the_claim(client, monkeypatch, store):
    from webhook_guard import receiver

    def boom(_event):
        raise RuntimeError("downstream unavailable")

    monkeypatch.setattr(receiver, "handle_event", boom)
    assert deliver(client, event()).status_code == 500

    monkeypatch.undo()
    retry = deliver(client, event())
    assert retry.status_code == 200
    assert retry.json()["status"] == "accepted"


def test_openapi_schema_is_generated(client):
    schema = client.get("/openapi.json").json()
    assert ENDPOINT in schema["paths"]
    assert "400" in schema["paths"][ENDPOINT]["post"]["responses"]
