from __future__ import annotations
from typing import Optional, List, Any
from pydantic import BaseModel, HttpUrl, field_validator


class FeaturesInput(BaseModel):
    domain_length: int = 0
    redirect_count: int = 0
    has_password_input: bool = False
    has_card_keywords: bool = False
    suspicious_words_count: int = 0
    gambling_keywords_count: int = 0
    adult_keywords_count: int = 0
    drug_keywords_count: int = 0
    subdomain_count: int = 0
    has_punycode: bool = False
    hyphen_count: int = 0
    path_depth: int = 0
    is_https: bool = True


class MetaInput(BaseModel):
    user_agent: Optional[str] = None
    referrer: Optional[str] = None


class ScanRequest(BaseModel):
    url: str
    features: FeaturesInput = FeaturesInput()
    meta: MetaInput = MetaInput()

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        return v


class ScanResponse(BaseModel):
    trace_id: str
    verdict: str  # SAFE | SUSPICIOUS | SCAM
    risk_score: int  # 0..100
    reasons: List[str]
    model_version: str


class FeedbackRequest(BaseModel):
    trace_id: str
    user_label: str  # SAFE | SCAM

    @field_validator("user_label")
    @classmethod
    def label_valid(cls, v: str) -> str:
        if v not in ("SAFE", "SCAM"):
            raise ValueError("user_label must be SAFE or SCAM")
        return v

    comment: Optional[str] = None


class FeedbackResponse(BaseModel):
    status: str


class HealthResponse(BaseModel):
    status: str
    model_version: str
