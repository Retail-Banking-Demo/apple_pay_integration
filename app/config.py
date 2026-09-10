from pydantic import Field, HttpUrl, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    jwt_public_key: str
    jwt_issuer: str
    jwt_audience: str
    issuer_base_url: HttpUrl
    issuer_api_key: SecretStr = Field(min_length=1)

    @field_validator("issuer_base_url")
    @classmethod
    def require_https(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https" or value.username or value.password or value.query or value.fragment:
            raise ValueError("Issuer URL must be HTTPS without credentials, query or fragment")
        return value
