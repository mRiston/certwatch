from __future__ import annotations

import ipaddress
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .collector import Collector
from .database import DEFAULT_VARIABLES, Database
from .scheduler import ScanScheduler
from .security import validate_host, validate_variable

BASE_DIR = Path(__file__).resolve().parent
_DEFAULT_SEED = object()


class EndpointCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    environment: str = Field(default="unknown", min_length=1, max_length=64)
    service: str = Field(default="tls", min_length=1, max_length=64)
    enabled: bool = True

    @field_validator("name", "environment", "service")
    @classmethod
    def clean_label(cls, value: str) -> str:
        clean = " ".join(value.strip().split())
        if not clean:
            raise ValueError("Value cannot be blank")
        return clean

    @field_validator("host")
    @classmethod
    def clean_host(cls, value: str) -> str:
        return validate_host(value)


class EndpointUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    host: str | None = Field(default=None, min_length=1, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    environment: str | None = Field(default=None, min_length=1, max_length=64)
    service: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None

    @field_validator("name", "environment", "service")
    @classmethod
    def clean_optional_label(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = " ".join(value.strip().split())
        if not clean:
            raise ValueError("Value cannot be blank")
        return clean

    @field_validator("host")
    @classmethod
    def clean_optional_host(cls, value: str | None) -> str | None:
        return validate_host(value) if value is not None else None


class VariableCreate(BaseModel):
    key: str = Field(min_length=1, max_length=64)
    value: str = Field(default="", max_length=512)
    description: str = Field(default="", max_length=240)


class VariableUpdate(BaseModel):
    value: str = Field(default="", max_length=512)
    description: str = Field(default="", max_length=240)


def _clean_description(value: str) -> str:
    return " ".join(value.strip().split())


def _validate_effective_value(key: str, value: str) -> str:
    if key == "SCAN_INTERVAL_MINUTES":
        parsed = int(value)
        if not 1 <= parsed <= 525600:
            raise ValueError("SCAN_INTERVAL_MINUTES must be between 1 and 525600")
    elif key == "CONNECT_TIMEOUT_SECONDS":
        parsed = float(value)
        if not 1 <= parsed <= 60:
            raise ValueError("CONNECT_TIMEOUT_SECONDS must be between 1 and 60")
    elif key in {"WARNING_DAYS", "CRITICAL_DAYS"}:
        parsed = int(value)
        if not 0 <= parsed <= 3650:
            raise ValueError(f"{key} must be between 0 and 3650")
    elif key == "DNS_SERVERS":
        for item in [part.strip() for part in value.split(",") if part.strip()]:
            ipaddress.ip_address(item)
    elif key == "RUN_SCAN_ON_STARTUP" and value.lower() not in {"true", "false"}:
        raise ValueError("RUN_SCAN_ON_STARTUP must be true or false")
    return value


def create_app(
    db_path: str | None = None,
    seed_file: str | None | object = _DEFAULT_SEED,
    *,
    start_scheduler: bool = True,
) -> FastAPI:
    database = Database(db_path or os.getenv("CERTWATCH_DB_PATH", "/data/certwatch.db"))
    seed = (
        os.getenv("CERTWATCH_CONFIG_FILE", "/app/config/endpoints.yaml")
        if seed_file is _DEFAULT_SEED
        else seed_file
    )
    collector = Collector(database)
    scheduler = ScanScheduler(database, collector)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize(seed)  # type: ignore[arg-type]
        if not (database.get_variable("DNS_SERVERS", "") or "").strip():
            bootstrap_dns: list[str] = []
            for env_name in ("CERTWATCH_DNS_PRIMARY", "CERTWATCH_DNS_SECONDARY"):
                candidate = os.getenv(env_name, "").strip()
                if candidate:
                    try:
                        bootstrap_dns.append(str(ipaddress.ip_address(candidate)))
                    except ValueError:
                        pass
            if bootstrap_dns:
                dns_variable = next(
                    item for item in database.list_variables() if item["key"] == "DNS_SERVERS"
                )
                database.update_variable(
                    dns_variable["id"],
                    value=",".join(dict.fromkeys(bootstrap_dns)),
                    description=dns_variable["description"],
                )
        if start_scheduler:
            scheduler.start()
            if (database.get_variable("RUN_SCAN_ON_STARTUP", "true") or "true").lower() == "true":
                import threading
                threading.Thread(target=collector.scan_all, daemon=True, name="startup-scan").start()
        yield
        if start_scheduler:
            scheduler.shutdown()

    app = FastAPI(
        title="CertWatch",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.database = database
    app.state.collector = collector
    app.state.scheduler = scheduler
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard_page() -> FileResponse:
        return FileResponse(BASE_DIR / "templates" / "index.html")

    @app.get("/configuration", include_in_schema=False)
    def configuration_page() -> FileResponse:
        return FileResponse(BASE_DIR / "templates" / "configuration.html")

    @app.get("/health")
    def health() -> dict[str, str]:
        with database.connect() as conn:
            conn.execute("SELECT 1").fetchone()
        return {"status": "ok"}

    @app.get("/api/v1/certificates")
    def certificates() -> dict[str, Any]:
        records = database.dashboard_records()
        counts = {key: 0 for key in ("Healthy", "Warning", "Critical", "Expired", "Unreachable", "Pending", "Disabled")}
        for item in records:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        return {"items": records, "summary": counts, "scan_running": collector.scan_running}

    @app.post("/api/v1/scans", status_code=status.HTTP_202_ACCEPTED)
    def start_scan(background_tasks: BackgroundTasks) -> dict[str, str]:
        if collector.scan_running:
            raise HTTPException(status_code=409, detail="A scan is already running")
        background_tasks.add_task(collector.scan_all)
        return {"status": "accepted"}

    @app.get("/api/v1/config/endpoints")
    def list_endpoints() -> dict[str, Any]:
        return {"items": database.list_endpoints()}

    @app.post("/api/v1/config/endpoints", status_code=status.HTTP_201_CREATED)
    def create_endpoint(payload: EndpointCreate) -> dict[str, Any]:
        try:
            endpoint = database.create_endpoint(**payload.model_dump())
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="That host and port are already monitored") from exc
        return endpoint

    @app.patch("/api/v1/config/endpoints/{endpoint_id}")
    def update_endpoint(endpoint_id: int, payload: EndpointUpdate) -> dict[str, Any]:
        values = payload.model_dump(exclude_none=True)
        try:
            endpoint = database.update_endpoint(endpoint_id, values)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="That host and port are already monitored") from exc
        if not endpoint:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        return endpoint

    @app.delete("/api/v1/config/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_endpoint(endpoint_id: int) -> Response:
        if not database.delete_endpoint(endpoint_id):
            raise HTTPException(status_code=404, detail="Endpoint not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/v1/config/variables")
    def list_variables() -> dict[str, Any]:
        return {
            "items": database.list_variables(),
            "built_in_keys": sorted(DEFAULT_VARIABLES),
            "notice": "Only non-secret operational values are supported.",
        }

    @app.post("/api/v1/config/variables", status_code=status.HTTP_201_CREATED)
    def create_variable(payload: VariableCreate) -> dict[str, Any]:
        key, value = validate_variable(payload.key, payload.value)
        try:
            value = _validate_effective_value(key, value)
            variable = database.create_variable(
                key=key,
                value=value,
                description=_clean_description(payload.description),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="A variable with that name already exists") from exc
        if key == "SCAN_INTERVAL_MINUTES" and start_scheduler:
            scheduler.reschedule()
        return variable

    @app.put("/api/v1/config/variables/{variable_id}")
    def update_variable(variable_id: int, payload: VariableUpdate) -> dict[str, Any]:
        existing = next((item for item in database.list_variables() if item["id"] == variable_id), None)
        if not existing:
            raise HTTPException(status_code=404, detail="Variable not found")
        _, value = validate_variable(existing["key"], payload.value)
        try:
            value = _validate_effective_value(existing["key"], value)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        variable = database.update_variable(
            variable_id,
            value=value,
            description=_clean_description(payload.description),
        )
        if existing["key"] == "SCAN_INTERVAL_MINUTES" and start_scheduler:
            scheduler.reschedule()
        return variable  # type: ignore[return-value]

    @app.delete("/api/v1/config/variables/{variable_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_variable(variable_id: int) -> Response:
        try:
            deleted = database.delete_variable(variable_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if not deleted:
            raise HTTPException(status_code=404, detail="Variable not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return app


app = create_app()
