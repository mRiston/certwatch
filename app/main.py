import json
import logging
import os
import threading
from pathlib import Path

import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .collector import collect
from .database import init_db, insert_scan, latest, history

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("certwatch")
CONFIG = Path(os.getenv("CERTWATCH_CONFIG", "/app/config/endpoints.yaml"))
TIMEOUT = max(1, min(60, int(os.getenv("CERTWATCH_TIMEOUT_SECONDS", "10"))))
INTERVAL = max(1, min(168, int(os.getenv("CERTWATCH_SCAN_INTERVAL_HOURS", "24"))))
app = FastAPI(title="CertWatch", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
lock = threading.Lock()
scheduler = BackgroundScheduler(timezone="UTC")


def endpoints():
    supplied = os.getenv("CERTWATCH_ENDPOINTS_JSON", "").strip()
    raw = json.loads(supplied) if supplied else (yaml.safe_load(CONFIG.read_text()) or {})
    if not isinstance(raw, dict) or not isinstance(raw.get("endpoints", []), list):
        raise ValueError("Expected an object with an endpoints list")
    result = []
    for entry in raw.get("endpoints", []):
        if not isinstance(entry, dict) or not entry.get("enabled", True):
            continue
        host = entry.get("host")
        if not isinstance(host, str) or not host.strip() or len(host) > 253:
            raise ValueError("Each enabled endpoint needs a valid hostname")
        port = int(entry.get("port", 443))
        if not 1 <= port <= 65535:
            raise ValueError("Endpoint port out of range")
        result.append({**entry, "host": host.strip(), "port": port})
    return result


def scan_all():
    if not lock.acquire(blocking=False):
        return
    try:
        try:
            targets = endpoints()
        except (ValueError, OSError, yaml.YAMLError, json.JSONDecodeError):
            logger.exception("Invalid endpoint configuration")
            return
        for entry in targets:
            try:
                insert_scan(collect(entry, TIMEOUT))
            except Exception:
                logger.exception("Failed to store scan result")
        logger.info("Scan completed for %d endpoints", len(targets))
    finally:
        lock.release()


@app.on_event("startup")
def startup():
    init_db()
    endpoints()  # Fail startup for invalid configuration.
    scheduler.add_job(scan_all, "interval", hours=INTERVAL, id="scan", max_instances=1, coalesce=True)
    scheduler.start()
    threading.Thread(target=scan_all, daemon=True).start()


@app.on_event("shutdown")
def shutdown():
    scheduler.shutdown(wait=False)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    rows = latest()
    statuses = ("healthy", "warning", "critical", "expired", "unreachable")
    counts = {status: sum(row["status"] == status for row in rows) for status in statuses}
    allowed = ("endpoint_key", "name", "host", "port", "environment", "service", "scanned_at", "issuer", "not_after", "days_remaining", "status", "fingerprint_sha256")
    safe = [{key: row.get(key) for key in allowed} for row in rows]
    return templates.TemplateResponse(request, "index.html", {"rows": safe, "counts": counts})


@app.get("/api/v1/certificates")
def api_certificates():
    allowed = ("endpoint_key", "name", "host", "port", "environment", "service", "scanned_at", "subject", "issuer", "not_after", "days_remaining", "status", "fingerprint_sha256")
    return [{key: row.get(key) for key in allowed} for row in latest()]


@app.get("/api/v1/history/{endpoint_key}")
def api_history(endpoint_key: str):
    if len(endpoint_key) > 300:
        raise HTTPException(400, "Invalid endpoint key")
    allowed = ("scanned_at", "success", "error_code", "not_after", "days_remaining", "status", "fingerprint_sha256")
    return [{key: row.get(key) for key in allowed} for row in history(endpoint_key)]


@app.post("/api/v1/scan", status_code=202)
def scan_now():
    if lock.locked():
        raise HTTPException(409, "Scan already in progress")
    threading.Thread(target=scan_all, daemon=True).start()
    return {"accepted": True}
