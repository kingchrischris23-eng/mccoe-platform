import streamlit as st

from config import is_local_only, settings
from src.feeds.aggregator import can_refresh_live, get_feed_status


def render_feed_settings() -> None:
    with st.expander("Live Feed Settings", expanded=False):
        st.caption("Toggle sources and provide an optional NVD API key for higher rate limits.")

        enable_live = st.toggle(
            "Enable live feed refresh",
            value=settings.enable_live_feeds,
            disabled=is_local_only(),
            help="Requires LOCAL_ONLY=false in .env",
        )
        if is_local_only():
            st.warning("LOCAL_ONLY=true — live refresh disabled. Cached feeds still load after first pull.")

        col1, col2 = st.columns(2)
        with col1:
            enable_urlhaus = st.checkbox("URLhaus", value=settings.enable_urlhaus)
            enable_nvd = st.checkbox("NIST NVD", value=settings.enable_nvd_feed)
        with col2:
            enable_otx = st.checkbox("AlienVault OTX", value=settings.enable_otx)
            enable_kev = st.checkbox("CISA KEV", value=settings.enable_cisa_kev)

        nvd_key = st.text_input(
            "NVD API Key (optional)",
            value=settings.nvd_api_key,
            type="password",
            help="Free key from https://nvd.nist.gov/developers/request-an-api-key",
        )
        otx_key = st.text_input(
            "OTX API Key (optional)",
            value=settings.otx_api_key,
            type="password",
        )

        if st.button("Apply Feed Settings"):
            settings.enable_live_feeds = enable_live
            settings.enable_urlhaus = enable_urlhaus
            settings.enable_otx = enable_otx
            settings.enable_nvd_feed = enable_nvd
            settings.enable_cisa_kev = enable_kev
            if nvd_key:
                settings.nvd_api_key = nvd_key
            if otx_key:
                settings.otx_api_key = otx_key
            st.success("Feed settings updated for this session.")

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