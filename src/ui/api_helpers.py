import streamlit as st

from config import settings
from src.api_client import DashboardAPI, DashboardAPIError, get_api_client


def api_status_badge() -> None:
    if not settings.use_api_backend:
        st.sidebar.caption("Backend: direct (local modules)")
        return

    client = get_api_client()
    if client and client.is_available():
        st.sidebar.success(f"API connected: `{settings.api_base_url}`")
    else:
        st.sidebar.warning(f"API unreachable: `{settings.api_base_url}` (using local fallback)")


def get_client() -> DashboardAPI | None:
    client = get_api_client()
    if client and client.is_available():
        return client
    return None