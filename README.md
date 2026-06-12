# Cybersecurity Training Dashboard

Streamlit-based training dashboard for nonprofit cybersecurity education. Includes threat feed aggregation, log parsing, log analysis, basic vulnerability checks, and automated PDF threat reporting.

Works fully offline in **local-only mode** using bundled sample data — ideal for classrooms, air-gapped labs, and Docker deployment without internet access.

## Features

- **Threat Feed Aggregator** — OTX, URLhaus, and bundled sample IOCs
- **Log Parser** — Apache combined log parsing with brute-force, injection, and scan heuristics
- **Log Analyzer** — Risk scoring, timelines, top IPs, and IOC correlation
- **Vuln Checker** — Allowlist-only scanning with NVD CVE lookup (or sample results offline)
- **Threat Reporter** — MCCoE-branded PDF (with charts) and Markdown exports
- **Local-only mode** — No external API calls; portable with bundled samples
- **Docker support** — One-command deployment via Docker Compose

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

Open **http://localhost:8501**

Docker runs with `LOCAL_ONLY=true` by default — no API keys or internet required.

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
docker run -p 8501:8501 -e LOCAL_ONLY=true cyber-training-dashboard
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

For portable offline use, keep the default:

```env
LOCAL_ONLY=true
```

### 4. Run the dashboard

```bash
streamlit run app.py
```

Open **http://localhost:8501**

---

## Local-Only Mode

Set `LOCAL_ONLY=true` in `.env` or Docker environment variables.

| Component | Online mode | Local-only mode |
|-----------|-------------|-----------------|
| Threat feeds | URLhaus + OTX (if keyed) | `data/samples/sample_iocs.csv` |
| CVE lookup | NVD API | Bundled sample CVEs |
| Vuln scan | Real port/header checks | `data/samples/sample_vuln_scan.json` |
| Log parser | Unchanged | Unchanged (uses uploaded/sample logs) |
| PDF reports | Unchanged | Unchanged |

Local-only mode makes the dashboard fully portable — copy the folder or Docker image to a USB drive, classroom laptop, or air-gapped VM and run without network access.

The sidebar shows a **Local-only mode** badge when active.

---

## Training Lab Flow

1. Go to **Threat Feeds** and click **Fetch & Merge Feeds**.
2. In **Log Parser**, click **Load Sample Attack Log**, then **Parse & Detect**.
3. Open **Log Analyzer** to review risk scores and IOC matches.
4. In **Vuln Checker**, scan `127.0.0.1` (allowlist enforced).
5. In **Threat Reporter**, generate PDF, Markdown, or both — reports include MCCoE branding, charts, training notes, and a risk scoring legend.

---

## Configuration Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `LOCAL_ONLY` | `false` (Docker: `true`) | Disable all external API calls |
| `OTX_API_KEY` | empty | AlienVault OTX pulses (online mode) |
| `NVD_API_KEY` | empty | Faster NVD API access (online mode) |
| `INSTRUCTOR_MODE` | `false` | Expands scan allowlist when `true` |
| `ALLOWED_TARGETS` | `127.0.0.1,localhost` | Comma-separated vuln scan targets |
| `AUTO_REPORT_ON_UPLOAD` | `true` | Auto-generate PDF after log parsing |
| `MAX_UPLOAD_MB` | `50` | Log upload size cap |
| `FEED_CACHE_TTL_MINUTES` | `15` | Threat feed cache lifetime |

---

## Project Structure

```
cyber-dashboard/
├── app.py                  # Streamlit entry point
├── Dockerfile              # Container image
├── docker-compose.yml      # One-command deployment
├── config.py               # Settings and paths
├── data/
│   ├── samples/            # Offline IOCs, logs, vuln scan data
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
| Empty threat feeds | Click **Fetch & Merge Feeds**; in local-only mode, samples load automatically |
| Docker build slow | First build downloads dependencies; subsequent builds use cache |
| Reports not persisting | Ensure Docker volumes are not removed (`docker compose down` without `-v`) |