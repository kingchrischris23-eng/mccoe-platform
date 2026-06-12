from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import health, logs, reports, threats, vulnerabilities
from src.reports.branding import ORG_EMAIL, ORG_NAME, REPORT_VERSION
from src.storage.repository import init_db


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="MCCoE Cyber Dashboard API",
    description=(
        f"REST API for the {ORG_NAME} training dashboard. "
        f"Authenticate with `X-API-Key` header or HTTP Basic auth. "
        f"Contact: {ORG_EMAIL}"
    ),
    version=REPORT_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(threats.router)
app.include_router(logs.router)
app.include_router(vulnerabilities.router)
app.include_router(reports.router)