"""
Scam Detector Backend – FastAPI application.
"""
from __future__ import annotations
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import (
    ScanRequest, ScanResponse,
    FeedbackRequest, FeedbackResponse,
    HealthResponse,
)
from app.scoring import (
    apply_rules, score_to_verdict,
    extract_from_url, merge_features,
    get_model, MODEL_VERSION,
)
from app.storage import init_db, get_db, Scan, Feedback
from app.security import check_rate_limit
from app.utils import make_trace_id, url_hash, extract_domain, truncate_features_json
from sqlalchemy.ext.asyncio import AsyncSession

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── CORS ─────────────────────────────────────────────────────────────────────
ALLOWED_ORIGINS: list[str] = os.getenv(
    "ALLOWED_ORIGINS", "*"
).split(",")

# ── App lifecycle ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    get_model()  # warm up (no-op for stub)
    logger.info("Scam Detector backend started | model=%s", MODEL_VERSION)
    yield

app = FastAPI(
    title="Scam Detector API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/v1/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", model_version=MODEL_VERSION)

@app.post(
    "/v1/scan",
    response_model=ScanResponse,
    dependencies=[Depends(check_rate_limit)],
)
async def scan(
    payload: ScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    trace_id = make_trace_id(payload.url)
    logger.info("trace_id=%s  scan request received", trace_id)

    url_feats = extract_from_url(payload.url)
    features = merge_features(url_feats, payload.features)

    rules_score, reasons = apply_rules(features)
    ml_score = get_model().predict(features)

    blended = int(rules_score * 0.8 + ml_score * 100 * 0.2)
    blended = max(0, min(100, blended))
    verdict = score_to_verdict(blended)

    if ml_score > 0.5:
        reasons.append("ML: classified as risky page")
    if not reasons:
        reasons = ["No significant risk signals detected"]

    scan_row = Scan(
        trace_id=trace_id,
        url_hash=url_hash(payload.url),
        domain=extract_domain(payload.url),
        score=blended,
        verdict=verdict,
        model_version=MODEL_VERSION,
        features_json=truncate_features_json(features),
    )
    db.add(scan_row)
    await db.commit()

    logger.info(
        "trace_id=%s  verdict=%s  score=%d  domain=%s",
        trace_id, verdict, blended, scan_row.domain,
    )

    return ScanResponse(
        trace_id=trace_id,
        verdict=verdict,
        risk_score=blended,
        reasons=reasons,
        model_version=MODEL_VERSION,
    )

@app.post("/v1/feedback", response_model=FeedbackResponse)
async def feedback(
    payload: FeedbackRequest,
    db: AsyncSession = Depends(get_db),
) -> FeedbackResponse:
    fb = Feedback(
        trace_id=payload.trace_id,
        user_label=payload.user_label,
        comment=payload.comment or "",
    )
    db.add(fb)
    await db.commit()
    logger.info("trace_id=%s  feedback=%s", payload.trace_id, payload.user_label)
    return FeedbackResponse(status="ok")
