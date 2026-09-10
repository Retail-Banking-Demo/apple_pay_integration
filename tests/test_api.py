import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def setup():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    settings = Settings(jwt_public_key=public, jwt_issuer="bank", jwt_audience="wallet",
                        issuer_base_url="https://issuer.example/", issuer_api_key="secret", _env_file=None)
    state = {"calls": [], "eligible": True, "status": 200}

    def upstream(request):
        state["calls"].append(request)
        if state["status"] != 200:
            return httpx.Response(state["status"], json={"secret": "never expose"})
        if request.method == "GET":
            return httpx.Response(200, json={"cards": [{"id": "card_1", "cardholder_name": "Alex",
                "primary_account_suffix": "1234", "primary_account_identifier": "opaque_id",
                "payment_network": "visa", "eligible": state["eligible"], "pan": "never expose"}]})
        return httpx.Response(200, json=state.get("response", {
            "activation_data": "YQ==", "encrypted_pass_data": "Yg==", "ephemeral_public_key": "Yw=="}))

    def token(**overrides):
        claims = {"sub": "customer_1", "iss": "bank", "aud": "wallet", "iat": int(time.time()),
                  "exp": int(time.time()) + 300, "scope": "wallet:provision", **overrides}
        return jwt.encode(claims, key, algorithm="RS256")

    with TestClient(create_app(settings, httpx.MockTransport(upstream))) as client:
        yield client, state, token


def headers(token):
    return {"Authorization": f"Bearer {token}", "Idempotency-Key": "unique-request-1234"}


CHALLENGE = {"certificates": ["YQ==", "Yg=="], "nonce": "Yw==", "nonce_signature": "ZA=="}
PATH = "/v1/cards/card_1/apple-wallet/provision"


def test_provision_and_retry(setup):
    client, state, token = setup
    for _ in range(2):
        response = client.post(PATH, json=CHALLENGE, headers=headers(token()))
        assert response.status_code == 200
        assert response.json()["encrypted_pass_data"] == "Yg=="
        assert response.headers["cache-control"] == "no-store"
    posts = [r for r in state["calls"] if r.method == "POST"]
    assert posts[0].headers["Idempotency-Key"] == posts[1].headers["Idempotency-Key"]
    assert state["calls"][0].url.params["customer_id"] == "customer_1"


@pytest.mark.parametrize("claims,code", [({"exp": 1}, 401), ({"aud": "other"}, 401),
    ({"iss": "other"}, 401), ({"scope": "read"}, 403), ({"scope": None}, 403)])
def test_auth_claims(setup, claims, code):
    client, state, token = setup
    assert client.get("/v1/cards", headers=headers(token(**claims))).status_code == code
    assert not state["calls"]


def test_missing_auth_and_safe_card_response(setup):
    client, state, token = setup
    assert client.get("/v1/cards").status_code == 401
    response = client.get("/v1/cards", headers=headers(token()))
    assert response.status_code == 200
    assert "pan" not in response.text


def test_card_ownership_and_eligibility(setup):
    client, state, token = setup
    assert client.post(PATH.replace("card_1", "other"), json=CHALLENGE, headers=headers(token())).status_code == 404
    state["eligible"] = False
    assert client.post(PATH, json=CHALLENGE, headers=headers(token())).status_code == 409
    assert all(r.method == "GET" for r in state["calls"])


@pytest.mark.parametrize("changes", [{"nonce": "invalid!"}, {"certificates": []}, {"customer_id": "other"}, {"encryption_scheme": "RSA_V2"}])
def test_bad_challenge(setup, changes):
    client, state, token = setup
    response = client.post(PATH, json={**CHALLENGE, **changes}, headers=headers(token()))
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request fields"}
    assert not state["calls"]


def test_issuer_failure_and_malformed_response(setup):
    client, state, token = setup
    state["status"] = 500
    response = client.post(PATH, json=CHALLENGE, headers=headers(token()))
    assert response.status_code == 502
    assert "never expose" not in response.text
    state["status"] = 200
    state["response"] = {"encrypted_pass_data": "wrong"}
    assert client.post(PATH, json=CHALLENGE, headers=headers(token())).status_code == 502


def test_idempotency_required(setup):
    client, state, token = setup
    assert client.post(PATH, json=CHALLENGE, headers={"Authorization": f"Bearer {token()}"}).status_code == 422
    assert not state["calls"]


def test_idempotency_is_scoped_to_customer(setup):
    client, state, token = setup
    for subject in ["customer_1", "customer_2"]:
        assert client.post(PATH, json=CHALLENGE, headers=headers(token(sub=subject))).status_code == 200
    posts = [r for r in state["calls"] if r.method == "POST"]
    assert posts[0].headers["Idempotency-Key"] != posts[1].headers["Idempotency-Key"]


def test_tampered_signature(setup):
    client, state, token = setup
    encoded = token()
    head, body, signature = encoded.split(".")
    bad = f"{head}.{body}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"
    assert client.get("/v1/cards", headers=headers(bad)).status_code == 401
    assert not state["calls"]


def test_openapi_and_health(setup):
    client, _, _ = setup
    assert client.get("/healthz").json() == {"status": "ok"}
    assert "/v1/cards/{card_id}/apple-wallet/provision" in client.get("/openapi.json").json()["paths"]
