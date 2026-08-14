# MCCoE — Missouri Cybersecurity Center of Excellence

This repository contains two MCCoE projects:

1. **MCCoE Student Learning Platform** — Web-based student portal with gamification, quizzes, Firebase tracking, and 4 interactive pillars
2. **MCCoE Cyber Dashboard** — Streamlit-based threat intel and training dashboard

---

## MCCoE Student Learning Platform

Live at: **https://kingchrischris23-eng.github.io/mccoe-platform/**

- Student portal with registration, login, weekly objectives, and quiz submissions
- 4 Pillars: Student Platform, CyberSec Academy, Curriculum Projects, Ethical Hacking Lab
- Firebase Realtime Database for cross-device sync (registry, logins, XP, academy scores, pentest scores)
- Admin tracker with attendance, leaderboard, academy scores, and pentest lab progress
- 90-question SY0-701 quiz bank, XP system, badges, and streak tracking

**Contact:** cking@mccoe.org

---

## MCCoE Cyber Dashboard

Streamlit-based training dashboard for MCCoE cybersecurity education. Includes threat feed aggregation, log parsing, log analysis, basic vulnerability checks, and automated PDF threat reporting.

**Contact:** support@mccoe.org

Starts **empty by default** — no sample IOCs, logs, or vulnerability findings until you import data, upload files, enter records manually, or click **Load Demo Data**. Runs fully offline in **local-only mode** (`LOCAL_ONLY=true` by default), ideal for classrooms, air-gapped labs, and Docker deployment without internet access.

## Features

- **Threat Feed Aggregator** — URLhaus, OTX, NIST NVD, CISA KEV (online mode), plus CSV/JSON import and manual IOC entry
- **Log Parser** — Apache combined log parsing with brute-force, injection, and scan heuristics
- **Log Analyzer** — Risk scoring, timelines, top IPs, and IOC correlation
- **Vuln Checker** — Allowlist-only scanning with NVD CVE lookup (online mode) or manual entry
- **Network Scanner** — Safe basic Nmap scans (allowlist + permission checkbox) with JSON export
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

### 3b. NIST NVD API key (optional)

The NVD API key is **optional**. Without it, NVD requests use public rate limits (5 requests per 30 seconds). With a key, limits increase to 50 requests per 30 seconds.

**Option A — Settings page (recommended)**

1. Run the dashboard (step 4 below).
2. Open **Settings** in the sidebar.
3. Paste your NVD API key and click **Save to .env**.

The key is written only to your local `.env` file (gitignored). It is never stored in source code or committed to git.

**Option B — Edit `.env` manually**

1. Copy `.env.example` to `.env` if you have not already.
2. Replace the example placeholder with your own key:

```env
NVD_API_KEY=your-key-here
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

## Safety Notes

- Vulnerability scanning is allowlist-only by default.
- Uploaded logs are capped at 50 MB.
- This is a training tool, not a production SIEM.
- Unauthorized scanning of networks you do not own may be illegal.
