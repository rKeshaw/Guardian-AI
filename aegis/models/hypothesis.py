from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


_ALLOWED_PARAM_TYPES = {"query", "form", "json", "header", "cookie", "graphql"}
_ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}
_VALID_OWASP_CATEGORIES = {
    "A01:2023", "A02:2023", "A03:2023", "A04:2023", "A05:2023",
    "A06:2023", "A07:2023", "A08:2023", "A09:2023", "A10:2023",
}


class InjectionPointSchema(BaseModel):
    url: str
    method: str
    param_name: str
    param_type: str
    context_hint: str = ""
    other_params: dict[str, str] = Field(default_factory=dict)

    @field_validator("method")
    @classmethod
    def _validate_method(cls, value: str) -> str:
        method = (value or "").upper().strip()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"method must be one of {sorted(_ALLOWED_METHODS)}")
        return method

    @field_validator("param_type")
    @classmethod
    def _validate_param_type(cls, value: str) -> str:
        param_type = (value or "").lower().strip()
        if param_type not in _ALLOWED_PARAM_TYPES:
            raise ValueError(f"param_type must be one of {sorted(_ALLOWED_PARAM_TYPES)}")
        return param_type


class HypothesisSchema(BaseModel):
    hypothesis: str
    owasp_category: str
    owasp_impact: int
    evidence_for: list[str]
    evidence_against: list[str]
    entry_probe: str
    expected_if_vulnerable: str
    expected_if_not_vulnerable: str
    confidence: int
    injection_point: InjectionPointSchema

    @field_validator("owasp_category")
    @classmethod
    def _validate_owasp_category(cls, value: str) -> str:
        category = (value or "").strip()
        if category not in _VALID_OWASP_CATEGORIES:
            raise ValueError(f"owasp_category must be one of {sorted(_VALID_OWASP_CATEGORIES)}")
        return category

    @field_validator("owasp_impact")
    @classmethod
    def _validate_owasp_impact(cls, value: int) -> int:
        if value < 1 or value > 10:
            raise ValueError("owasp_impact must be in range [1, 10]")
        return value

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, value: Any) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("confidence must be an integer") from exc
        return max(0, min(100, parsed))
