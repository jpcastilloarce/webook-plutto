from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from datetime import datetime
import os
import json
import hashlib

app = FastAPI(title="Webhook Receiver", version="1.0.0")

LOG_DIR = "/tmp/webhook_logs"


def mask_token(token: str) -> str:
    if not token:
        return None
    if len(token) <= 12:
        return token[:2] + "..." + token[-2:]
    return token[:6] + "..." + token[-4:]


@app.post("/")
async def receive_webhook(request: Request):
    ts = datetime.utcnow().isoformat() + "Z"

    # Capture all headers as a dict (FastAPI gives case-insensitive headers)
    headers = {k: v for k, v in request.headers.items()}

    raw_body = await request.body()
    body_text = raw_body.decode("utf-8", errors="replace")

    # Try JSON, but don't fail if it's not JSON
    try:
        body_json = await request.json()
    except Exception:
        body_json = None

    auth = headers.get("authorization") or headers.get("Authorization")
    has_bearer = False
    bearer_token = None
    if auth and auth.lower().startswith("bearer "):
        has_bearer = True
        bearer_token = auth[7:].strip()

    # Build log record
    log_record = {
        "timestamp": ts,
        "path": str(request.url.path),
        "full_url": str(request.url),
        "query": dict(request.query_params),
        "client_ip": headers.get("x-forwarded-for"),
        "method": request.method,
        "has_bearer": has_bearer,
        "bearer_token_masked": mask_token(bearer_token),
        "headers": headers,
        "content_type": headers.get("content-type", ""),
        "body_json": body_json,
        "body_text": body_text if body_json is None else None,
        "body_sha256": hashlib.sha256(raw_body).hexdigest(),
    }

    # Ensure log directory exists (Vercel allows writing to /tmp only; ephemeral)
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, f"{datetime.utcnow().date()}.log")

    # Append one JSON line per request
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_record, ensure_ascii=False) + "\n")

    # Also print to stdout so you can see it in Vercel logs
    print(json.dumps(log_record, ensure_ascii=False))

    return JSONResponse(
        {
            "ok": True,
            "has_bearer": has_bearer,
            "bearer_token_masked": log_record["bearer_token_masked"],
            "logged_to": log_path,
        }
    )


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}
