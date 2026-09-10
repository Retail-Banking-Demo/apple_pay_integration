# Apple Wallet card provisioning

Python/FastAPI microservice for adding a bank's issued cards to Apple Wallet via
PassKit (ECC_V2). Implements the mobile API and an HTTP issuer adapter contract.
A real bank/processor implementation of that contract is required to provision cards.

## Run

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
# Configure bank JWT public key, issuer, audience and processor credentials.
uvicorn app.main:app --reload
pytest -q
```

Interactive API docs: http://localhost:8000/docs. `GET /healthz` checks process
health only. Configuration is required at startup. JWTs must use RS256 and contain
`sub`, `iss`, `aud`, `iat`, `exp` and the space-delimited `wallet:provision` scope.
The bank-authenticated `sub` must map to the processor's customer identifier.
Never embed issuer credentials or JWT signing keys in the mobile app.

Build with `docker build -t apple-wallet-provisioning .`. Inject the environment
variables via your deployment secret manager and expose container port 8000.
`JWT_PUBLIC_KEY` is a PEM string; .env supports quoted escaped newlines, while
Docker environment injection should provide actual newlines.

## Mobile API

Both routes require `Authorization: Bearer <bank-access-token>`.

| Route | Response |
| --- | --- |
| `GET /v1/cards` | Owned cards, display fields and eligibility |
| `POST /v1/cards/{card_id}/apple-wallet/provision` | Encrypted provisioning data |

POST requires `Idempotency-Key` (16–128 letters, digits, underscores or hyphens).
Use a fresh UUID for each PassKit challenge and reuse it only for exact retries.

```json
{
  "certificates": ["<Base64 DER leaf>", "<Base64 DER intermediate>"],
  "nonce": "<Base64 nonce>",
  "nonce_signature": "<Base64 signature>",
  "encryption_scheme": "ECC_V2"
}
```

The response contains standard Base64 `activation_data`, `encrypted_pass_data`
and `ephemeral_public_key`. Certificate ordering is preserved. The service checks
encoding; the issuer processor performs cryptographic validation. No PAN/CVV is
accepted. Responses are marked `Cache-Control: no-store`.

Errors: 401 invalid token, 403 missing scope, 404 unavailable card, 409 ineligible
card/conflicting state, 422 invalid fields, 502/503 issuer failure, 504 timeout.

## Required issuer adapter

`ISSUER_BASE_URL` must be an HTTPS bank-controlled service. Requests carry
`Authorization: Bearer <ISSUER_API_KEY>`. Implement these endpoints or adapt the
HTTP integration in `app/main.py` to your processor's documented API:

* `GET v1/cards?customer_id=<verified-subject>` returns `{"cards": [...]}`. Each
  card has `id`, `cardholder_name`, `primary_account_suffix` (four digits),
  `primary_account_identifier` (opaque issuer ID), `payment_network` (e.g. `visa`)
  and boolean `eligible`. Extra fields are filtered from mobile responses.
* `POST v1/cards/{id}/apple-wallet/provision` accepts the challenge above plus
  `customer_id` and returns the three Base64 provisioning fields.

The processor must atomically recheck ownership, card status, eligibility and
required step-up authentication; validate Apple's certificate trust chain, nonce
and signature; enforce freshness/replay protection; and generate the encrypted
payload through its approved network tokenization integration. This service does
not fabricate cryptographic values or assume access to an unspecified bank API.

The forwarded idempotency key is a SHA-256 digest scoped to customer and card.
The processor must durably deduplicate concurrent requests and bind keys to the
complete payload, returning 409 for conflicting reuse. This service does not
claim local replay protection or durable idempotency. Use authoritative processor
token events/status for bank-side status tracking; generating a payload does not
prove that Wallet successfully added the card.

## iOS integration

1. Obtain Apple's `com.apple.developer.payment-pass-provisioning` entitlement for
   the issuer app and enable it in the provisioning profile.
2. Sign in with the bank and fetch `/v1/cards`. Check device capability and existing
   Wallet passes locally using `primary_account_identifier`, including the target
   iPhone or Apple Watch.
3. Create `PKAddPaymentPassRequestConfiguration(encryptionScheme: .ECC_V2)` using
   the cardholder name, suffix, identifier and network, then present
   `PKAddPaymentPassViewController`.
4. In the delegate's `generateRequestWithCertificateChain` callback, Base64-encode
   the certificates, nonce and signature and POST them to this service.
5. Base64-decode the response into `PKAddPaymentPassRequest.activationData`,
   `.encryptedPassData` and `.ephemeralPublicKey`, then invoke the completion handler.
6. Handle failures/dismissal and use the delegate's `didFinishAdding` result for UI.

Apple references: [in-app provisioning guide](https://applepaydemo.apple.com/in-app-provisioning)
and [PKAddPaymentPassRequest](https://developer.apple.com/documentation/passkit/pkaddpaymentpassrequest).

## Deployment and verification

Tests use a mocked issuer and generated RSA keys. Real device provisioning needs
issuer credentials, an implemented processor adapter and Apple's entitlement.
Terminate HTTPS at ingress, enforce body/rate limits (a 128 KiB body limit covers
this API's maximum encoded challenge), and disable body logging in proxies and
observability agents. Rotate credentials and JWT public keys through deployment
configuration; automated JWKS rotation is not implemented. No provisioning data
is persisted by this service.

A Swift callback networking helper is provided in
[examples/WalletProvisioning.swift](examples/WalletProvisioning.swift). The host
app must invoke PassKit's completion handler on success and handle errors and UI
dismissal. The Swift helper is illustrative and has not been built in an iOS target.
