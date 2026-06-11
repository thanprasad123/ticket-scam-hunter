"""Pydantic v2 schemas for Ticket Scam Hunter API and Agent Builder tools."""

from datetime import datetime
from enum import Enum
from typing import Annotated
from urllib.parse import unquote

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

URGENCY_PATTERNS = ("dm asap", "zelle", "venmo", "wire only", "cash app only")

# Fraud-signature patterns referenced in risk assessment prompts/logic
MAX_URL_LEN = 2048
MAX_QUERY_LEN = 500


class Verdict(str, Enum):
    SCAM = "SCAM"
    SUSPICIOUS = "SUSPICIOUS"
    LEGITIMATE = "LEGITIMATE"


class ScanUrlRequest(BaseModel):
    """Request to scan a ticket-sales URL."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: Annotated[AnyHttpUrl, Field(description="Ticket listing or sales page URL to analyze.")]
    persist: bool = Field(
        default=True,
        description="Store the result in Elasticsearch after analysis.",
    )
    force_refresh: bool = Field(
        default=False,
        description="Skip cache and run a fresh Gemini analysis.",
    )

    @field_validator("url", mode="before")
    @classmethod
    def sanitize_url(cls, value: object) -> object:
        if value is None:
            raise ValueError("url is required")
        if not isinstance(value, str):
            return value
        cleaned = unquote(value.strip())
        if not cleaned:
            raise ValueError("url cannot be empty")
        if len(cleaned) > MAX_URL_LEN:
            raise ValueError(f"url exceeds maximum length of {MAX_URL_LEN}")
        if any(ord(c) < 32 for c in cleaned):
            raise ValueError("url contains invalid control characters")
        return cleaned


class PageMeta(BaseModel):
    final_url: str | None = None
    status_code: int | None = None
    title: str | None = None
    content_length: int | None = None
    text_length: int | None = None


class ScanResultResponse(BaseModel):
    """Validated scan result returned to Agent Builder / clients."""

    model_config = ConfigDict(str_strip_whitespace=True)

    url: str
    verdict: Verdict
    score: Annotated[float, Field(ge=0.0, le=10.0)]
    reasons: list[str] = Field(min_length=1)
    red_flags: list[str] = Field(default_factory=list)
    trust_signals: list[str] = Field(default_factory=list)
    analyzed_at: datetime
    page: PageMeta | None = None
    document_id: str | None = Field(
        default=None, description="Elasticsearch document ID when persisted."
    )
    cached: bool = Field(
        default=False,
        description="True when served from a prior Elasticsearch scan.",
    )

    @field_validator("reasons", "red_flags", "trust_signals", mode="before")
    @classmethod
    def normalize_string_lists(cls, value: object) -> object:
        if value is None:
            return []
        if isinstance(value, str):
            items = [line.strip() for line in value.splitlines() if line.strip()]
            return items or [value.strip()] if value.strip() else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return value

class SearchScansRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    verdict: Verdict | None = Field(
        default=None, description="Filter by verdict (SCAM, SUSPICIOUS, LEGITIMATE)."
    )
    query: Annotated[
        str | None,
        Field(max_length=MAX_QUERY_LEN, description="Full-text search query."),
    ] = None

    @field_validator("query", mode="before")
    @classmethod
    def sanitize_query(cls, value: object) -> object:
        if value is None:
            return None
        if not isinstance(value, str):
            return value
        cleaned = value.strip()
        if not cleaned:
            return None
        if len(cleaned) > MAX_QUERY_LEN:
            raise ValueError(f"query exceeds maximum length of {MAX_QUERY_LEN}")
        return cleaned


class SearchScansResponse(BaseModel):
    total: int
    results: list[ScanResultResponse]


class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None


class ScanPipelineError(Exception):
    """Base exception for scan pipeline failures mapped to HTTP responses."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        status_code: int = 500,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code


class UrlFetchError(ScanPipelineError):
    """Target URL could not be fetched after retries."""

    def __init__(self, message: str, *, cause: Exception | None = None) -> None:
        super().__init__(message, error_code="url_fetch_failed", status_code=502)
        if cause is not None:
            self.__cause__ = cause


class AnalysisError(ScanPipelineError):
    """Gemini analysis or response parsing failed."""

    def __init__(self, message: str, *, cause: Exception | None = None) -> None:
        super().__init__(message, error_code="analysis_failed", status_code=502)
        if cause is not None:
            self.__cause__ = cause


class ScanResponseError(ScanPipelineError):
    """Scan completed but the result could not be validated."""

    def __init__(self, message: str, *, cause: Exception | None = None) -> None:
        super().__init__(message, error_code="invalid_scan_response", status_code=500)
        if cause is not None:
            self.__cause__ = cause
