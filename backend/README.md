# Scam Detector – Backend

FastAPI + SQLite backend that scores URLs for scam risk.

## Project structure

```
backend/
  app/
    main.py            # FastAPI app, endpoints
    schemas.py         # Pydantic models
    utils.py           # trace_id / url_hash helpers
    scoring/
      rules.py         # Heuristic rules engine
      model.py         # ML model stub (replace with real model)
      features.py      # Feature extraction from URL + client data
    storage/
      db.py            # SQLAlchemy async engine, session factory
      models.py        # ORM tables: scans, feedback
    security/
      rate_limit.py    # In-memory token bucket, 60 req/min per IP
  requirements.txt
```

## Installation

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive docs: http://localhost:8000/docs

## Setting the CORS origin for your extension

After loading the extension in Chrome (see extension/README.md), copy the extension ID
from `chrome://extensions` (e.g. `abcdefghijklmnopqrstuvwxyz123456`).

Then set the environment variable before starting the server:

```bash
export ALLOWED_ORIGINS="chrome-extension://abcdefghijklmnopqrstuvwxyz123456"
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Or edit the default directly in `app/main.py` line `ALLOWED_ORIGINS`.

For local testing without an extension you can temporarily set:
```bash
export ALLOWED_ORIGINS="http://localhost:3000,http://127.0.0.1:3000"
```

## Example curl requests

### Health check
```bash
curl http://localhost:8000/v1/health
```

### Scan a URL
```bash
curl -X POST http://localhost:8000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://paypal-secure-login.xn--vk1b.com/verify/account",
    "features": {
      "domain_length": 38,
      "redirect_count": 2,
      "has_password_input": true,
      "has_card_keywords": false,
      "suspicious_words_count": 3,
      "subdomain_count": 0,
      "has_punycode": true,
      "hyphen_count": 1,
      "path_depth": 2,
      "is_https": true
    },
    "meta": {}
  }'
```

### Submit feedback
```bash
curl -X POST http://localhost:8000/v1/feedback \
  -H "Content-Type: application/json" \
  -d '{"trace_id": "<trace_id from scan response>", "user_label": "SCAM", "comment": "Confirmed phishing"}'
```

## Privacy notice

- **The full URL is never stored.** Only a SHA-256 hash of the URL (`url_hash`) is persisted.
- The domain/hostname is stored in plain text (needed for aggregation/debugging).
- Feature vectors (aggregated counts, flags) are stored as a truncated JSON blob.
- No personal data or page content is ever transmitted to the backend.

## Rate limiting

60 requests per minute per client IP (sliding window). Configurable via `RATE_LIMIT_RPM` env var.

## Integrating a real ML model

1. Train your model and export it (e.g. as an ONNX file or a scikit-learn pickle).
2. Edit `app/scoring/model.py`:
   - In `_load_model()`: load your artifact.
   - In `predict(features)`: convert `features` dict to a numpy array / tensor and return a float in `[0, 1]`.
3. Update `MODEL_VERSION` string.
