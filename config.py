from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode
from typing_extensions import Annotated


class Settings(BaseSettings):
    """All runtime configuration comes from environment variables (or backend/.env).

    See .env.example for the full list. Required values have no default, so the
    app fails fast at startup if they are missing.
    """

    # Database (required)
    DATABASE_URL: str

    # JWT (secret is required - never ship a default)
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_HOURS: int = 24

    # Login brute-force protection
    LOGIN_MAX_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # CORS - comma-separated list of allowed origins, e.g.
    # CORS_ORIGINS=http://localhost:8080,https://app.example.com
    CORS_ORIGINS: Annotated[list[str], NoDecode] = []

    # Swagger UI (/docs), ReDoc (/redoc) and /openapi.json. Keep false in production.
    ENABLE_API_DOCS: bool = False

    # Business details printed on invoices and reports
    BUSINESS_NAME: str = "Hisaab"
    BUSINESS_ADDRESS: str = ""
    BUSINESS_PHONE: str = ""

    # Groq AI (optional - AI summaries in exports are skipped when unset)
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "llama-3.1-8b-instant"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def split_origins(cls, value):
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
