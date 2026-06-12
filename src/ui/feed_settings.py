import streamlit as st

from config import is_local_only, settings
from src.feeds.aggregator import can_refresh_live, get_feed_status


def _key_status(label: str, value: str) -> None:
    if value:
        st.success(f"{label}: configured (loaded from .env)")
    else:
        st.warning(f"{label}: not set — add to `.env` and restart Docker")


def render_feed_settings() -> None:
    with st.expander("Live Feed Settings", expanded=False):
        st.caption(
            "API keys and feed toggles are loaded from `.env` in the project root. "
            "Edit that file and run `docker compose up --build -d` to apply changes."
        )

        if is_local_only():
            st.warning("LOCAL_ONLY=true — live refresh disabled. Set LOCAL_ONLY=false in `.env` to enable.")
        elif settings.enable_live_feeds:
            st.info("Live feeds enabled via `.env`.")
        else:
            st.warning("ENABLE_LIVE_FEEDS=false in `.env` — live refresh is off.")

        col1, col2 = st.columns(2)
        with col1:
            st.checkbox("URLhaus", value=settings.enable_urlhaus, disabled=True)
            st.checkbox("NIST NVD", value=settings.enable_nvd_feed, disabled=True)
        with col2:
            st.checkbox("AlienVault OTX", value=settings.enable_otx, disabled=True)
            st.checkbox("CISA KEV", value=settings.enable_cisa_kev, disabled=True)

        st.markdown("**API keys (from `.env`)**")
        _key_status("abuse.ch Auth-Key (URLhaus)", settings.abuse_ch_auth_key)
        _key_status("NVD API Key", settings.nvd_api_key)
        _key_status("OTX API Key", settings.otx_api_key)

        _render_feed_status()


def _render_feed_status() -> None:
    st.markdown("**Feed cache status**")
    sources = get_feed_status()
    rows = []
    for source in sources:
        if source.error == "disabled":
            continue
        cached = source.cached_at.isoformat()[:19] if source.cached_at else "—"
        mode = "live" if source.live else ("cached" if source.count else "empty")
        if source.stale and source.count:
            mode = "cached (stale)"
        rows.append(
            {
                "Source": source.name,
                "IOCs": source.count,
                "Last refresh": cached,
                "Mode": mode,
                "Note": source.error or ("rate limited" if source.rate_limited else ""),
            }
        )
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.caption("No feed cache yet. Refresh live feeds when online.")

    if can_refresh_live():
        st.caption("Live refresh is available.")
    elif is_local_only():
        st.caption("Showing cached data only while LOCAL_ONLY=true.")