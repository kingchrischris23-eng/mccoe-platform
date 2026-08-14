import streamlit as st

from config import has_abusech_auth_key, has_nvd_api_key, has_otx_api_key, is_local_only, settings
from src.feeds.aggregator import can_refresh_live, get_feed_status
from src.feeds.attribution import attribution_lines


def _key_status(label: str, configured: bool) -> None:
    if configured:
        st.success(f"{label}: configured")
    else:
        st.warning(f"{label}: not set — add to `.env` or **Settings**")


def render_feed_settings() -> None:
    with st.expander("Live Feed Settings", expanded=False):
        st.caption(
            "Toggle sources for this session. API keys are saved in `.env` via **Settings** "
            "(or edit `.env` directly and restart / `docker compose up --build -d`)."
        )

        enable_live = st.toggle(
            "Enable live feed refresh",
            value=settings.enable_live_feeds,
            disabled=is_local_only(),
            help="Requires LOCAL_ONLY=false in .env",
        )
        if is_local_only():
            st.warning("LOCAL_ONLY=true — live refresh disabled. Cached feeds still load after first pull.")

        col1, col2, col3 = st.columns(3)
        with col1:
            enable_otx = st.checkbox("AlienVault OTX", value=settings.enable_otx)
            enable_urlhaus = st.checkbox("URLhaus (abuse.ch)", value=settings.enable_urlhaus)
        with col2:
            enable_threatfox = st.checkbox("ThreatFox (abuse.ch)", value=settings.enable_threatfox)
            enable_nvd = st.checkbox("NIST NVD", value=settings.enable_nvd_feed)
        with col3:
            enable_kev = st.checkbox("CISA KEV", value=settings.enable_cisa_kev)
            st.checkbox(
                "OpenPhish",
                value=settings.enable_openphish,
                disabled=True,
                help="Coming in a future update — toggle reserved.",
            )

        st.markdown("**API keys**")
        _key_status("abuse.ch Auth-Key (URLhaus / ThreatFox)", has_abusech_auth_key())
        _key_status("OTX API Key", has_otx_api_key())
        _key_status("NVD API Key", has_nvd_api_key())

        if not has_otx_api_key() and settings.enable_otx:
            st.caption("OTX: no API key — cached data only.")
        if not has_abusech_auth_key() and (settings.enable_threatfox or settings.enable_urlhaus):
            st.caption("abuse.ch: no Auth-Key — cached data only. Get one at auth.abuse.ch.")
        if not has_nvd_api_key():
            st.caption("NVD: no API key — using public rate limits.")

        if st.button("Apply Feed Settings"):
            settings.enable_live_feeds = enable_live
            settings.enable_otx = enable_otx
            settings.enable_urlhaus = enable_urlhaus
            settings.enable_threatfox = enable_threatfox
            settings.enable_nvd_feed = enable_nvd
            settings.enable_cisa_kev = enable_kev
            st.success("Feed settings updated for this session.")

        _render_feed_status()

    with st.expander("Threat Intelligence Attribution", expanded=False):
        for line in attribution_lines():
            st.markdown(line)


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
        note = source.status_message or source.error or ""
        if source.rate_limited and not note:
            note = "rate limited — serving cache"
        rows.append(
            {
                "Source": source.name,
                "IOCs": source.count,
                "Last refresh": cached,
                "Mode": mode,
                "Status": note,
            }
        )
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.caption("No feed cache yet. Refresh live feeds when online.")

    if can_refresh_live() or has_abusech_auth_key():
        st.caption("Live refresh is available when LOCAL_ONLY=false.")
    elif is_local_only():
        st.caption("Showing cached data only while LOCAL_ONLY=true.")