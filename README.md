# MCCoE Cyber Dashboard

Streamlit-based training dashboard for MCCoE cybersecurity education. Includes threat feed aggregation, log parsing, log analysis, basic vulnerability checks, and automated PDF threat reporting.

**Contact:** support@mccoe.org

Starts **empty by default** — no sample IOCs, logs, or vulnerability findings until you import data, upload files, enter records manually, or click **Load Demo Data**. Runs fully offline in **local-only mode** (`LOCAL_ONLY=true` by default), ideal for classrooms, air-gapped labs, and Docker deployment without internet access.

## Features

- **Threat Feed Aggregator** — OTX, URLhaus (online mode), plus CSV/JSON import and manual IOC entry
- **Log Parser** — Apache combined log parsing with brute-force, injection, and scan heuristics
- **Log Analyzer** — Risk scoring, timelines, top IPs, and IOC correlation
- **Vuln Checker** — Allowlist-only scanning with NVD CVE lookup (online mode) or manual entry
- **Threat Reporter** — MCCoE-branded PDF (with charts) and Markdown exports
- **Local-only mode** — No external API calls; portable and air-gap friendly
- **Optional demo data** — One-click **Load Demo Data** in the sidebar for training labs
- **Docker support** — One-command deployment via Docker Compose
- **FastAPI backend** — REST API with Swagger docs, API key / Basic auth, Streamlit integration

---

## Prerequisites

Choose one setup path:

| Method | Requirements |
|--------|--------------|
| **Docker** (recommended) | [Docker Desktop](https://www.docker.com/products/docker-desktop/) or Docker Engine + Compose |
| **Local Python** | Python 3.12+ |

---

## Option 1: Docker Deployment (Recommended)

Best for instructors who want a consistent, portable environment across machines.

### Quick start

```bash
git clone <your-repo-url> cyber-dashboard
cd cyber-dashboard
docker compose up --build
```

Open **http://localhost:8501** (Streamlit UI) and **http://localhost:8000/docs** (API Swagger UI).

Docker runs with `LOCAL_ONLY=true` and `AUTO_LOAD_DEMO=false` by default — the dashboard starts empty with no external API keys or internet required. Use the sidebar **Load Demo Data** button for a guided training walkthrough.

The FastAPI backend and Streamlit frontend share the same SQLite database via Docker volumes.

### Stop / restart

```bash
docker compose down          # stop
docker compose up -d         # start in background
docker compose up --build    # rebuild after code changes
```

### Persist data across restarts

`docker-compose.yml` uses named volumes for `data/` (reports, cache) and `db/` (SQLite). Reports and parsed logs survive container restarts.

To reset all data:

```bash
docker compose down -v
```

### Custom configuration

Create a `.env` file in the project root (optional — Compose reads it automatically):

```env
LOCAL_ONLY=true
AUTO_LOAD_DEMO=false
INSTRUCTOR_MODE=false
ALLOWED_TARGETS=127.0.0.1,localhost
AUTO_REPORT_ON_UPLOAD=true
```

To enable live threat feeds inside Docker, set:

```env
LOCAL_ONLY=false
OTX_API_KEY=your_key_here
```

Then restart: `docker compose up --build`

### Build image only (without Compose)

```bash
docker build -t cyber-training-dashboard .
docker run -p 8501:8501 -e LOCAL_ONLY=true -e AUTO_LOAD_DEMO=false cyber-training-dashboard
```

---

## Option 2: Local Python Setup

### 1. Clone and enter the project

```bash
cd cyber-dashboard
```

### 2. Create a virtual environment

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment

```bash
copy .env.example .env        # Windows
cp .env.example .env        # macOS / Linux
```

For portable offline use, keep the defaults:

```env
LOCAL_ONLY=true
AUTO_LOAD_DEMO=false
```

### 4. Run the dashboard

```bash
streamlit run app.py
```

Open **http://localhost:8501**

### 5. Run with FastAPI backend (optional)

Start the API server (terminal 1):

```powershell
.\run_api.bat
# or: .\.venv\Scripts\python.exe -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Enable API mode in `.env`:

```env
USE_API_BACKEND=true
API_BASE_URL=http://127.0.0.1:8000
API_KEY=mccoe-training-key
API_BASIC_USER=mccoe
API_BASIC_PASSWORD=training
```

Start Streamlit (terminal 2):

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Swagger UI: **http://localhost:8000/docs**

---

## Getting Data Into the Dashboard

The dashboard starts with zero IOCs, log alerts, and vulnerability findings. Populate it using any of these methods:

| Method | Where | What it loads |
|--------|-------|---------------|
| **Import IOCs** | Threat Feeds → Data Import | CSV or JSON IOC files, or manual IOC entry |
| **Upload logs** | Log Parser | Apache combined log files |
| **Vuln scan / manual entry** | Vuln Checker | Allowlist scan (online) or manual findings |
| **Load Demo Data** | Sidebar | Bundled demo IOCs, attack log, and vuln scan from `data/demo/` |
| **Live feeds** | Threat Feeds (online only) | URLhaus + OTX when `LOCAL_ONLY=false` |

Use **Clear All Data** in the sidebar to reset the database to empty.

---

## FastAPI REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check (no auth required) |
| `/api/threats` | GET | List IOCs with filters (`severity`, `ioc_type`, `source`, `search`, `refresh`) |
| `/api/threats/import` | POST | Import IOCs from JSON body |
| `/api/threats/import/upload` | POST | Import IOCs from CSV/JSON file upload |
| `/api/logs/analyze` | POST | Analyze log content (JSON body) |
| `/api/logs/analyze/upload` | POST | Analyze uploaded log file (multipart) |
| `/api/vulnerabilities` | GET | List vulnerability scan findings |
| `/api/vulnerabilities` | POST | Add a vulnerability scan result |
| `/api/reports/generate` | POST | Generate PDF, Markdown, or both |
| `/api/reports/download/{filename}` | GET | Download a generated report |
| `/api/demo/load` | POST | Load bundled demo data |
| `/api/data` | DELETE | Clear all dashboard data |

### Authentication

When `API_AUTH_ENABLED=true` (default), provide **either**:

- Header: `X-API-Key: mccoe-training-key`
- HTTP Basic auth: `mccoe` / `training`

Set `API_AUTH_ENABLED=false` for local development only.

### API usage examples

**Health check:**

```bash
curl http://localhost:8000/api/health
```

**List high-severity IOCs:**

```bash
curl -H "X-API-Key: mccoe-training-key" \
  "http://localhost:8000/api/threats?severity=high&limit=10"
```

**Import IOCs (JSON):**

```bash
curl -X POST http://localhost:8000/api/threats/import \
  -H "X-API-Key: mccoe-training-key" \
  -H "Content-Type: application/json" \
  -d "{\"iocs\":[{\"ioc_type\":\"ip\",\"value\":\"10.0.0.1\",\"severity\":\"medium\",\"source\":\"manual\"}]}"
```

**Refresh feeds and list IOCs (online mode only):**

```bash
curl -H "X-API-Key: mccoe-training-key" \
  "http://localhost:8000/api/threats?refresh=true"
```

**Analyze log data (JSON):**

```bash
curl -X POST http://localhost:8000/api/logs/analyze \
  -H "X-API-Key: mccoe-training-key" \
  -H "Content-Type: application/json" \
  -d "{\"filename\":\"attack.log\",\"content\":\"198.51.100.42 - - [10/Jun/2026:08:01:01 +0000] \\\"POST /login HTTP/1.1\\\" 403 512 \\\"-\\\" \\\"bot\\\"\"}"
```

**Analyze log file (upload):**

```bash
curl -X POST http://localhost:8000/api/logs/analyze/upload \
  -H "X-API-Key: mccoe-training-key" \
  -F "file=@data/demo/demo_attack.log"
```

**Load demo data:**

```bash
curl -X POST http://localhost:8000/api/demo/load \
  -H "X-API-Key: mccoe-training-key"
```

**Clear all data:**

```bash
curl -X DELETE http://localhost:8000/api/data \
  -H "X-API-Key: mccoe-training-key"
```

**Get vulnerability findings:**

```bash
curl -H "X-API-Key: mccoe-training-key" \
  http://localhost:8000/api/vulnerabilities
```

**Generate PDF report:**

```bash
curl -X POST http://localhost:8000/api/reports/generate \
  -H "X-API-Key: mccoe-training-key" \
  -H "Content-Type: application/json" \
  -d "{\"format\":\"pdf\",\"auto\":false}"
```

**Using HTTP Basic auth instead:**

```bash
curl -u mccoe:training http://localhost:8000/api/threats
```

**PowerShell example:**

```powershell
$headers = @{ "X-API-Key" = "mccoe-training-key" }
Invoke-RestMethod -Uri "http://localhost:8000/api/threats?severity=critical" -Headers $headers
```

---

## Local-Only Mode

`LOCAL_ONLY=true` is the default in `.env`, `config.py`, and Docker.

| Component | Online mode (`LOCAL_ONLY=false`) | Local-only mode (`LOCAL_ONLY=true`) |
|-----------|----------------------------------|-------------------------------------|
| Threat feeds | URLhaus + OTX (if keyed) | No auto-fetch; import IOCs or load demo data |
| CVE lookup | NVD API | Returns empty; add findings manually |
| Vuln scan | Real port/header checks on allowlist | Real scan only; no fake bundled results |
| Log parser | Upload logs | Upload logs |
| PDF reports | Uses whatever data is in the database | Same |

Local-only mode makes the dashboard fully portable — copy the folder or Docker image to a USB drive, classroom laptop, or air-gapped VM and run without network access.

The sidebar shows a **Local-only mode** badge when active.

---

## Training Lab Flow

1. Click **Load Demo Data** in the sidebar (or import your own IOCs in **Threat Feeds**).
2. In **Log Parser**, upload `data/demo/demo_attack.log` (or your own log), then **Parse & Detect**.
3. Open **Log Analyzer** to review risk scores and IOC matches.
4. In **Vuln Checker**, scan `127.0.0.1` (allowlist enforced) or review demo vuln findings.
5. In **Threat Reporter**, generate PDF, Markdown, or both — reports include MCCoE branding, charts, training notes, and a risk scoring legend.

---

## Configuration Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `LOCAL_ONLY` | `true` | Disable all external API calls |
| `AUTO_LOAD_DEMO` | `false` | Auto-load demo data on startup (not recommended for production) |
| `OTX_API_KEY` | empty | AlienVault OTX pulses (online mode) |
| `NVD_API_KEY` | empty | Faster NVD API access (online mode) |
| `INSTRUCTOR_MODE` | `false` | Expands scan allowlist when `true` |
| `ALLOWED_TARGETS` | `127.0.0.1,localhost` | Comma-separated vuln scan targets |
| `AUTO_REPORT_ON_UPLOAD` | `true` | Auto-generate PDF after log parsing |
| `MAX_UPLOAD_MB` | `50` | Log upload size cap |
| `FEED_CACHE_TTL_MINUTES` | `15` | Threat feed cache lifetime |
| `API_BASE_URL` | `http://127.0.0.1:8000` | FastAPI backend URL for Streamlit |
| `USE_API_BACKEND` | `false` | Streamlit calls FastAPI when `true` |
| `API_AUTH_ENABLED` | `true` | Require API key or Basic auth |
| `API_KEY` | `mccoe-training-key` | Training API key |
| `API_BASIC_USER` / `API_BASIC_PASSWORD` | `mccoe` / `training` | HTTP Basic auth credentials |

---

## Project Structure

```
cyber-dashboard/
├── api/                    # FastAPI backend (main.py, routes, auth)
├── app.py                  # Streamlit entry point
├── Dockerfile              # Container image
├── docker-compose.yml      # One-command deployment
├── config.py               # Settings and paths
├── data/
│   ├── demo/               # Optional demo IOCs, logs, vuln scan (Load Demo Data)
│   ├── cache/              # API response cache (online mode)
│   └── reports/            # Generated PDF reports
├── db/                     # SQLite database
└── src/                    # Core modules and UI pages
```

---

## Safety Notes

- Vulnerability scanning is allowlist-only by default.
- Uploaded logs are capped at 50 MB.
- This is a training tool, not a production SIEM.
- Unauthorized scanning of networks you do not own may be illegal.

---

## Tests

```bash
# Local Python
pytest

# Inside Docker
docker compose run --rm dashboard pytest
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Port 8501 already in use | Change to `"8502:8501"` in `docker-compose.yml` |
| `python` not found (Windows) | Install Python 3.12+ and restart your terminal |
| Empty dashboard on first launch | Expected — import data or click **Load Demo Data** in the sidebar |
| Empty threat feeds in local-only mode | Import IOCs via **Threat Feeds → Data Import**, or load demo data |
| Docker build slow | First build downloads dependencies; subsequent builds use cache |
| Reports not persisting | Ensure Docker volumes are not removed (`docker compose down` without `-v`) |