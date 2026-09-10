import hashlib
from contextlib import asynccontextmanager
from typing import Annotated
from urllib.parse import quote

import httpx
import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

from app.config import Settings
from app.models import Card, Challenge, Identifier, ProvisioningData


def create_app(settings: Settings | None = None, transport=None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings or Settings()
        async with httpx.AsyncClient(
            base_url=str(app.state.settings.issuer_base_url).rstrip("/") + "/",
            headers={"Authorization": f"Bearer {app.state.settings.issuer_api_key.get_secret_value()}"},
            timeout=httpx.Timeout(15, connect=5),
            follow_redirects=False,
            transport=transport,
        ) as client:
            app.state.issuer = client
            yield

    app = FastAPI(title="Apple Wallet Card Provisioning", version="0.1.0", lifespan=lifespan)

    @app.middleware("http")
    async def no_cache(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        # FastAPI's default validation response echoes submitted challenge data.
        return JSONResponse(status_code=422, content={"detail": "Invalid request fields"})

    bearer = HTTPBearer(auto_error=False)

    def customer(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        try:
            if credentials is None:
                raise ValueError("Missing credentials")
            config = app.state.settings
            claims = jwt.decode(
                credentials.credentials, config.jwt_public_key, algorithms=["RS256"],
                issuer=config.jwt_issuer, audience=config.jwt_audience,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject or len(subject) > 256:
                raise ValueError("Invalid subject")
        except (jwt.InvalidTokenError, ValueError):
            raise HTTPException(401, "Invalid access token", headers={"WWW-Authenticate": "Bearer"}) from None
        scope = claims.get("scope", "")
        if not isinstance(scope, str) or "wallet:provision" not in scope.split():
            raise HTTPException(403, "Missing wallet:provision scope")
        return subject

    async def issuer_request(method, path, **kwargs):
        try:
            result = await app.state.issuer.request(method, path, **kwargs)
        except httpx.TimeoutException:
            raise HTTPException(504, "Issuer timed out") from None
        except httpx.RequestError:
            raise HTTPException(502, "Issuer unavailable") from None
        if result.status_code == 404:
            raise HTTPException(404, "Card not found")
        if result.status_code == 409:
            raise HTTPException(409, "Provisioning request conflicts with issuer state")
        if result.status_code == 429:
            raise HTTPException(503, "Issuer temporarily unavailable")
        if not 200 <= result.status_code < 300:
            raise HTTPException(502, "Issuer request failed")
        try:
            return result.json()
        except ValueError:
            raise HTTPException(502, "Invalid issuer response") from None

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    async def cards_for(subject):
        # Owner is derived exclusively from the verified bank access token.
        payload = await issuer_request("GET", "v1/cards", params={"customer_id": subject})
        try:
            return [Card.model_validate(card) for card in payload["cards"]]
        except (ValidationError, KeyError, TypeError):
            raise HTTPException(502, "Invalid issuer response") from None

    @app.get("/v1/cards", response_model=list[Card])
    async def cards(subject: Annotated[str, Depends(customer)]):
        return await cards_for(subject)

    @app.post("/v1/cards/{card_id}/apple-wallet/provision", response_model=ProvisioningData)
    async def provision(
        card_id: Identifier, challenge: Challenge,
        subject: Annotated[str, Depends(customer)],
        idempotency_key: Annotated[str, Header(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")],
    ):
        owned = next((card for card in await cards_for(subject) if card.id == card_id), None)
        if owned is None:
            raise HTTPException(404, "Card not found")
        if not owned.eligible:
            raise HTTPException(409, "Card is not eligible for Apple Wallet")
        key = hashlib.sha256(f"{subject}\0{card_id}\0{idempotency_key}".encode()).hexdigest()
        payload = await issuer_request(
            "POST", f"v1/cards/{quote(card_id, safe='')}/apple-wallet/provision",
            headers={"Idempotency-Key": key},
            json={"customer_id": subject, **challenge.model_dump()},
        )
        try:
            return ProvisioningData.model_validate(payload)
        except ValidationError:
            raise HTTPException(502, "Invalid issuer response") from None

    return app


app = create_app()
