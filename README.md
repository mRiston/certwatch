# CertWatch

A lightweight, read-only TLS leaf-certificate inventory and dashboard. FastAPI + SQLite, packaged for Docker and Portainer.

## Features

- TLS/SNI leaf certificate inventory for configured TCP endpoints
- Expiry dashboard and JSON API, with SQLite scan history
- Scheduled scans and manual scan button
- Runs as a non-root user with a read-only root filesystem
- Certificate verification is **intentionally disabled** to inventory expired and private-CA certificates. **This is not a TLS trust validation tool.**

## Deploy with GitHub + Portainer

1. Create a GitHub repository and push these files to its `main` branch. The included GitHub Actions workflow builds and publishes `ghcr.io/OWNER/REPO:latest` on each push.
2. In GitHub, check **Actions** for a successful build. Make the GHCR package public, or configure registry credentials in Portainer for a private image.
3. In Portainer, **Stacks → Add stack → Repository**. Provide the repository URL, branch `main`, and Compose path `compose.yaml`.
4. In the stack environment, set `CERTWATCH_IMAGE` to your actual image path (e.g. `ghcr.io/OWNER/REPO:latest`). Set `CERTWATCH_ENDPOINTS_JSON` to a JSON object containing an `endpoints` array. Optionally set bind address, port, timeout, and interval; see `.env.example`.
5. Deploy the stack. By default it binds to `127.0.0.1:8080` **on the Docker host**, not your laptop. To reach it remotely, use a trusted host interface IP and restrict access with firewall/reverse-proxy authentication.
6. To update, push to `main`, wait for the image build, then pull/redeploy the Portainer stack. Git polling alone does not guarantee an updated image is pulled; use Portainer's image pull/redeploy option or a pinned SHA tag.

### Endpoint configuration

Set `CERTWATCH_ENDPOINTS_JSON` in the **Portainer stack environment** (not in a public Git repository):

```json
{"endpoints":[{"name":"Example HTTPS","host":"example.com","port":443,"environment":"test","service":"web","enabled":true}]}
```

For standalone Docker, omit the environment variable to use the bundled `config/endpoints.yaml`, or mount a private YAML file at `/app/config/endpoints.yaml` read-only. Environment JSON takes precedence over YAML.

### Local build

```bash
docker build -t certwatch:local .
docker run --rm -p 127.0.0.1:8080:8080 -e CERTWATCH_ENDPOINTS_JSON='{"endpoints":[{"host":"example.com"}]}' -v certwatch-data:/data certwatch:local
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/api/v1/certificates
```

### Security notes

There is **no application authentication**. Restrict dashboard and API access, including `POST /api/v1/scan`, to a trusted network or authenticated reverse proxy. Hostnames, certificate subjects, and scan history can be sensitive. Do not put passwords, private keys, or tokens in endpoint configuration. Only scan hosts you are authorized to reach. Scans are sequential; for large inventories, consider a queue and per-host concurrency limits.

### Known limitations

- Only the presented leaf certificate is collected; chain trust and hostname matching are not evaluated.
- Certificate status is based on expiry (expired, critical ≤14 days, warning ≤60 days, healthy) or reachability.
- Existing records for removed endpoints remain visible until manually pruned from the database.
- One app process is expected. Multiple workers or replicas can duplicate scheduled jobs.
- No built-in alerting or authentication.
- JSON endpoints configured through Portainer are environment configuration, not encrypted secrets.

### API

- `GET /health`
- `GET /api/v1/certificates`
- `GET /api/v1/history/{host:port}`
- `POST /api/v1/scan` (202 accepted, 409 if scan is in progress)
