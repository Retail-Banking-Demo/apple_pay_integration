import base64
import binascii
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints


def validate_base64(value: str) -> str:
    try:
        if not base64.b64decode(value, validate=True):
            raise ValueError("Empty binary data")
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Expected nonempty standard Base64 data") from exc
    return value


Binary = Annotated[str, StringConstraints(min_length=4, max_length=16384), AfterValidator(validate_base64)]
Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,128}$")]


class Card(BaseModel):
    # Explicit response fields prevent issuer PANs or other extra data leaking out.
    id: Identifier
    cardholder_name: str = Field(min_length=1, max_length=200)
    primary_account_suffix: str = Field(pattern=r"^[0-9]{4}$")
    primary_account_identifier: str = Field(min_length=1, max_length=256)
    payment_network: Literal["visa", "mastercard", "amex", "discover", "interac", "eftpos", "maestro", "electron", "vpay"]
    eligible: bool


class Challenge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    certificates: list[Binary] = Field(min_length=2, max_length=5)
    nonce: Binary
    nonce_signature: Binary
    encryption_scheme: Literal["ECC_V2"] = "ECC_V2"


class ProvisioningData(BaseModel):
    activation_data: Binary
    encrypted_pass_data: Binary
    ephemeral_public_key: Binary
