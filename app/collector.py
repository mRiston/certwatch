from __future__ import annotations

import hashlib
import ipaddress
import logging
import socket
import ssl
from datetime import datetime, timezone
from threading import Lock
from typing import Any

import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .database import Database, utc_now

logger = logging.getLogger("certwatch.collector")


class Collector:
    def __init__(self, database: Database):
        self.database = database
        self._scan_lock = Lock()

    @property
    def scan_running(self) -> bool:
        return self._scan_lock.locked()

    def scan_all(self) -> bool:
        if not self._scan_lock.acquire(blocking=False):
            return False
        try:
            endpoints = self.database.list_endpoints(enabled_only=True)
            for endpoint in endpoints:
                result = self._scan_endpoint(endpoint)
                self.database.record_scan(endpoint["id"], result)
            return True
        finally:
            self._scan_lock.release()

    def _scan_endpoint(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        timeout = self._float_variable("CONNECT_TIMEOUT_SECONDS", 5.0, 1.0, 60.0)
        try:
            addresses = self._resolve(endpoint["host"])
        except Exception:
            logger.info("DNS resolution failed for endpoint_id=%s", endpoint["id"])
            return self._failure("DNS_RESOLUTION_FAILED")

        last_code = "NETWORK_ERROR"
        for address in addresses:
            try:
                der_cert = self._fetch_certificate(
                    address=address,
                    host=endpoint["host"],
                    port=endpoint["port"],
                    timeout=timeout,
                )
                return self._parse_certificate(der_cert)
            except TimeoutError:
                last_code = "CONNECTION_TIMEOUT"
            except ConnectionRefusedError:
                last_code = "CONNECTION_REFUSED"
            except ssl.SSLError:
                last_code = "TLS_HANDSHAKE_FAILED"
            except (OSError, socket.error):
                last_code = "NETWORK_ERROR"
            except ValueError:
                last_code = "CERTIFICATE_PARSE_FAILED"
            except Exception:
                logger.exception("Unexpected scan failure for endpoint_id=%s", endpoint["id"])
                last_code = "INTERNAL_ERROR"
        return self._failure(last_code)

    def _resolve(self, host: str) -> list[str]:
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass

        configured = self.database.get_variable("DNS_SERVERS", "") or ""
        nameservers = [part.strip() for part in configured.split(",") if part.strip()]
        addresses: list[str] = []
        if nameservers:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [str(ipaddress.ip_address(item)) for item in nameservers]
            resolver.timeout = self._float_variable("CONNECT_TIMEOUT_SECONDS", 5.0, 1.0, 60.0)
            resolver.lifetime = resolver.timeout
            for record_type in ("A", "AAAA"):
                try:
                    answers = resolver.resolve(host, record_type, search=False)
                    addresses.extend(str(answer) for answer in answers)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                    continue
        else:
            results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            addresses.extend(result[4][0] for result in results)

        unique = list(dict.fromkeys(addresses))
        if not unique:
            raise socket.gaierror(f"No addresses for {host}")
        return unique

    @staticmethod
    def _fetch_certificate(*, address: str, host: str, port: int, timeout: float) -> bytes:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((address, port), timeout=timeout) as tcp_socket:
            tcp_socket.settimeout(timeout)
            with context.wrap_socket(tcp_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert(binary_form=True)
                if not certificate:
                    raise ValueError("Peer did not provide a certificate")
                return certificate

    def _parse_certificate(self, der_cert: bytes) -> dict[str, Any]:
        certificate = x509.load_der_x509_certificate(der_cert)
        now = datetime.now(timezone.utc)
        not_after = certificate.not_valid_after_utc
        not_before = certificate.not_valid_before_utc
        days_remaining = (not_after - now).days
        warning_days = self._int_variable("WARNING_DAYS", 60, 1, 3650)
        critical_days = self._int_variable("CRITICAL_DAYS", 14, 0, warning_days)
        if days_remaining < 0:
            status = "Expired"
        elif days_remaining <= critical_days:
            status = "Critical"
        elif days_remaining <= warning_days:
            status = "Warning"
        else:
            status = "Healthy"

        try:
            san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        fingerprint = hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest().upper()
        return {
            "scanned_at": utc_now(),
            "status": status,
            "error_code": None,
            "expires_at": not_after.isoformat(),
            "days_remaining": days_remaining,
            "subject": certificate.subject.rfc4514_string(),
            "issuer": certificate.issuer.rfc4514_string(),
            "sans": sans,
            "fingerprint_sha256": fingerprint,
            "not_before": not_before.isoformat(),
        }

    @staticmethod
    def _failure(code: str) -> dict[str, Any]:
        return {
            "scanned_at": utc_now(),
            "status": "Unreachable",
            "error_code": code,
            "sans": [],
        }

    def _int_variable(self, key: str, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(self.database.get_variable(key, str(default)) or default)
            return min(max(value, minimum), maximum)
        except (TypeError, ValueError):
            return default

    def _float_variable(self, key: str, default: float, minimum: float, maximum: float) -> float:
        try:
            value = float(self.database.get_variable(key, str(default)) or default)
            return min(max(value, minimum), maximum)
        except (TypeError, ValueError):
            return default
