from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import yaml


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


DEFAULT_VARIABLES = {
    "SCAN_INTERVAL_MINUTES": ("1440", "Minutes between automatic scans"),
    "CONNECT_TIMEOUT_SECONDS": ("5", "TCP/TLS connection timeout in seconds"),
    "WARNING_DAYS": ("60", "Warning status begins at this many days remaining"),
    "CRITICAL_DAYS": ("14", "Critical status begins at this many days remaining"),
    "DNS_SERVERS": ("", "Optional comma-separated DNS server IP addresses"),
    "RUN_SCAN_ON_STARTUP": ("true", "Run a scan when CertWatch starts"),
}


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self, seed_file: str | Path | None = None) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS monitored_endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 443 CHECK(port BETWEEN 1 AND 65535),
                    environment TEXT NOT NULL DEFAULT 'unknown',
                    service TEXT NOT NULL DEFAULT 'tls',
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(host, port)
                );

                CREATE TABLE IF NOT EXISTS app_variables (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL UNIQUE,
                    value TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS certificate_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint_id INTEGER NOT NULL,
                    scanned_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_code TEXT,
                    expires_at TEXT,
                    days_remaining INTEGER,
                    subject TEXT,
                    issuer TEXT,
                    sans_json TEXT NOT NULL DEFAULT '[]',
                    fingerprint_sha256 TEXT,
                    not_before TEXT,
                    FOREIGN KEY(endpoint_id) REFERENCES monitored_endpoints(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER,
                    summary TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scans_endpoint_time
                    ON certificate_scans(endpoint_id, scanned_at DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_time
                    ON audit_log(occurred_at DESC);
                """
            )
            now = utc_now()
            for key, (value, description) in DEFAULT_VARIABLES.items():
                conn.execute(
                    """INSERT OR IGNORE INTO app_variables
                       (key, value, description, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (key, value, description, now, now),
                )

        if seed_file:
            self.seed_endpoints(seed_file)

    def seed_endpoints(self, seed_file: str | Path) -> None:
        seed_path = Path(seed_file)
        try:
            if not seed_path.exists():
                return
        except OSError:
            return
        with self.connect() as conn:
            if conn.execute("SELECT COUNT(*) FROM monitored_endpoints").fetchone()[0] > 0:
                return
        payload = yaml.safe_load(seed_path.read_text(encoding="utf-8")) or {}
        for item in payload.get("endpoints", []):
            try:
                self.create_endpoint(
                    name=str(item.get("name") or item["host"]),
                    host=str(item["host"]),
                    port=int(item.get("port", 443)),
                    environment=str(item.get("environment", "unknown")),
                    service=str(item.get("service", "tls")),
                    enabled=bool(item.get("enabled", True)),
                    audit=False,
                )
            except (KeyError, ValueError, sqlite3.IntegrityError):
                continue

    def list_endpoints(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        where = "WHERE enabled = 1" if enabled_only else ""
        with self.connect() as conn:
            rows = conn.execute(
                f"""SELECT id, name, host, port, environment, service, enabled,
                           created_at, updated_at
                    FROM monitored_endpoints {where}
                    ORDER BY name COLLATE NOCASE, host COLLATE NOCASE, port"""
            ).fetchall()
        return [{**dict(row), "enabled": bool(row["enabled"])} for row in rows]

    def get_endpoint(self, endpoint_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT id, name, host, port, environment, service, enabled,
                          created_at, updated_at
                   FROM monitored_endpoints WHERE id = ?""",
                (endpoint_id,),
            ).fetchone()
        return ({**dict(row), "enabled": bool(row["enabled"])} if row else None)

    def create_endpoint(
        self,
        *,
        name: str,
        host: str,
        port: int,
        environment: str,
        service: str,
        enabled: bool,
        audit: bool = True,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO monitored_endpoints
                   (name, host, port, environment, service, enabled, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, host, port, environment, service, int(enabled), now, now),
            )
            endpoint_id = int(cursor.lastrowid)
            if audit:
                self._audit_conn(
                    conn, "create", "endpoint", endpoint_id,
                    f"Added monitored endpoint {host}:{port}",
                )
        return self.get_endpoint(endpoint_id)  # type: ignore[return-value]

    def update_endpoint(self, endpoint_id: int, values: dict[str, Any]) -> dict[str, Any] | None:
        if not values:
            return self.get_endpoint(endpoint_id)
        allowed = {"name", "host", "port", "environment", "service", "enabled"}
        values = {key: value for key, value in values.items() if key in allowed}
        if not values:
            return self.get_endpoint(endpoint_id)
        values["updated_at"] = utc_now()
        columns = ", ".join(f"{key} = ?" for key in values)
        params = [int(value) if key == "enabled" else value for key, value in values.items()]
        params.append(endpoint_id)
        with self.connect() as conn:
            cursor = conn.execute(
                f"UPDATE monitored_endpoints SET {columns} WHERE id = ?", params
            )
            if cursor.rowcount == 0:
                return None
            self._audit_conn(conn, "update", "endpoint", endpoint_id, "Updated monitored endpoint")
        return self.get_endpoint(endpoint_id)

    def delete_endpoint(self, endpoint_id: int) -> bool:
        with self.connect() as conn:
            endpoint = conn.execute(
                "SELECT host, port FROM monitored_endpoints WHERE id = ?", (endpoint_id,)
            ).fetchone()
            if not endpoint:
                return False
            conn.execute("DELETE FROM monitored_endpoints WHERE id = ?", (endpoint_id,))
            self._audit_conn(
                conn, "delete", "endpoint", endpoint_id,
                f"Removed monitored endpoint {endpoint['host']}:{endpoint['port']}",
            )
        return True

    def list_variables(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT id, key, value, description, created_at, updated_at
                   FROM app_variables ORDER BY key COLLATE NOCASE"""
            ).fetchall()
        return [dict(row) for row in rows]

    def get_variable(self, key: str, default: str | None = None) -> str | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT value FROM app_variables WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def create_variable(self, *, key: str, value: str, description: str) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO app_variables
                   (key, value, description, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (key, value, description, now, now),
            )
            variable_id = int(cursor.lastrowid)
            self._audit_conn(conn, "create", "variable", variable_id, f"Added variable {key}")
        return next(item for item in self.list_variables() if item["id"] == variable_id)

    def update_variable(self, variable_id: int, *, value: str, description: str) -> dict[str, Any] | None:
        now = utc_now()
        with self.connect() as conn:
            row = conn.execute("SELECT key FROM app_variables WHERE id = ?", (variable_id,)).fetchone()
            if not row:
                return None
            conn.execute(
                """UPDATE app_variables SET value = ?, description = ?, updated_at = ?
                   WHERE id = ?""",
                (value, description, now, variable_id),
            )
            self._audit_conn(conn, "update", "variable", variable_id, f"Updated variable {row['key']}")
        return next(item for item in self.list_variables() if item["id"] == variable_id)

    def delete_variable(self, variable_id: int) -> bool:
        with self.connect() as conn:
            row = conn.execute("SELECT key FROM app_variables WHERE id = ?", (variable_id,)).fetchone()
            if not row:
                return False
            if row["key"] in DEFAULT_VARIABLES:
                raise ValueError("Built-in variables cannot be deleted")
            conn.execute("DELETE FROM app_variables WHERE id = ?", (variable_id,))
            self._audit_conn(conn, "delete", "variable", variable_id, f"Removed variable {row['key']}")
        return True

    def record_scan(self, endpoint_id: int, result: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO certificate_scans
                   (endpoint_id, scanned_at, status, error_code, expires_at, days_remaining,
                    subject, issuer, sans_json, fingerprint_sha256, not_before)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    endpoint_id,
                    result["scanned_at"],
                    result["status"],
                    result.get("error_code"),
                    result.get("expires_at"),
                    result.get("days_remaining"),
                    result.get("subject"),
                    result.get("issuer"),
                    json.dumps(result.get("sans", [])),
                    result.get("fingerprint_sha256"),
                    result.get("not_before"),
                ),
            )

    def dashboard_records(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT e.id, e.name, e.host, e.port, e.environment, e.service, e.enabled,
                       s.scanned_at, s.status, s.error_code, s.expires_at, s.days_remaining,
                       s.subject, s.issuer, s.sans_json, s.fingerprint_sha256, s.not_before
                FROM monitored_endpoints e
                LEFT JOIN certificate_scans s ON s.id = (
                    SELECT cs.id FROM certificate_scans cs
                    WHERE cs.endpoint_id = e.id
                    ORDER BY cs.scanned_at DESC, cs.id DESC LIMIT 1
                )
                ORDER BY e.name COLLATE NOCASE, e.host COLLATE NOCASE, e.port
                """
            ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["enabled"] = bool(item["enabled"])
            item["sans"] = json.loads(item.pop("sans_json") or "[]")
            if not item["status"]:
                item["status"] = "Pending" if item["enabled"] else "Disabled"
            records.append(item)
        return records

    @staticmethod
    def _audit_conn(
        conn: sqlite3.Connection,
        action: str,
        entity_type: str,
        entity_id: int | None,
        summary: str,
    ) -> None:
        conn.execute(
            """INSERT INTO audit_log (occurred_at, action, entity_type, entity_id, summary)
               VALUES (?, ?, ?, ?, ?)""",
            (utc_now(), action, entity_type, entity_id, summary[:240]),
        )
