# CertWatch

CertWatch is a Portainer-ready, read-only TLS certificate inventory with a FastAPI dashboard, scheduled scanning, and persistent SQLite configuration.

## V0.2 highlights

- New **Configuration** page at `/configuration`
- Add, enable/disable, and remove monitored hosts without editing YAML
- Add and update non-secret runtime variables
- Persistent endpoint, variable, scan, and audit data in `/data/certwatch.db`
- Optional application-level DNS servers for internal zones
- Categorized DNS, TCP, TLS, and parsing failures
- Explicit response allowlists; no environment dump or raw config routes
- Secret-like variable names and common key/token formats are rejected

## Portainer deployment

1. In Portainer, create or update a standalone Docker Compose stack from this repository.
2. Use `compose.yaml`.
3. Keep the named volume `certwatch-data` when updating or recreating the stack.
4. Deploy and open `http://PORTAINER-HOST:8080`.
5. Open **Configuration** to add monitored hosts and runtime settings.

The Compose-managed `certwatch-data` volume persists `/data/certwatch.db` across container restarts and stack redeployments. Keep this volume when updating the stack. Deleting the volume deletes the configuration and scan history.

## Upgrade behavior

`config/endpoints.yaml` is now a seed file. It is imported only when the persistent endpoint table is empty. Existing hosts can remain in the file for the first V0.2 startup; after import, manage them through the UI.

If an earlier deployment already used a volume mounted at `/data`, retain that same volume and the same Portainer stack name. If it used a bind mount, change the Compose volume declaration to point at the existing data path before deploying. If you intentionally remove and recreate the stack, select or declare the existing volume rather than creating a new one.

## Built-in runtime variables

| Variable | Default | Purpose |
|---|---:|---|
| `SCAN_INTERVAL_MINUTES` | `1440` | Automatic scan cadence |
| `CONNECT_TIMEOUT_SECONDS` | `5` | DNS/TCP/TLS timeout |
| `WARNING_DAYS` | `60` | Warning threshold |
| `CRITICAL_DAYS` | `14` | Critical threshold |
| `DNS_SERVERS` | blank | Comma-separated DNS server IPs, e.g. `10.0.0.10,10.0.0.11` |
| `RUN_SCAN_ON_STARTUP` | `true` | Run a scan after application startup |

When `DNS_SERVERS` is populated, CertWatch resolves A/AAAA records against those servers and still uses the configured hostname for TLS SNI. This allows internal DNS to be changed from the UI without recreating the container.

For upgrade compatibility, `compose.yaml` maps the existing Portainer `DNS_PRIMARY` and `DNS_SECONDARY` stack variables into a one-time `DNS_SERVERS` seed. They are copied only while the persisted `DNS_SERVERS` value is blank; later UI changes remain authoritative.

Custom non-secret variables are also persisted for future integrations, but have no application behavior until code explicitly consumes them.

## Local development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
CERTWATCH_DB_PATH=./certwatch.db \
CERTWATCH_CONFIG_FILE=./config/endpoints.yaml \
uvicorn app.main:app --reload --port 8080
```

Run tests:

```bash
pytest -q
```

## API routes

- `GET /api/v1/certificates`
- `POST /api/v1/scans`
- `GET|POST /api/v1/config/endpoints`
- `PATCH|DELETE /api/v1/config/endpoints/{id}`
- `GET|POST /api/v1/config/variables`
- `PUT|DELETE /api/v1/config/variables/{id}`
- `GET /health`

The API intentionally does not expose raw environment variables, raw YAML, or audit-log contents.

## Security

There is no built-in authentication. Keep the service on a trusted management network and read [SECURITY.md](SECURITY.md). Internal hostnames, certificate subjects, SANs, issuers, and fingerprints are infrastructure metadata even though they are not credentials.
