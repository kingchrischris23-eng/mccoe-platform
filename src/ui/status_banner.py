import streamlit as st

from src.monitoring.status import get_dashboard_status


def _health_style(label: str) -> str:
    return {
        "Healthy": "🟢",
        "Degraded": "🟡",
        "Offline": "🔴",
        "Disabled": "⚪",
    }.get(label, "⚪")


def render_status_banner() -> None:
    status = get_dashboard_status()
    icon = _health_style(status.feed_health)
    auto_note = ""
    if status.auto_refresh_enabled:
        auto_note = f" | Auto-refresh: {status.auto_refresh_hours}h ({status.next_auto_refresh or 'pending'})"

    banner = (
        f"{icon} **Live Feeds:** {status.feed_health} "
        f"| **Last Scan:** {status.last_network_scan} "
        f"| **Feeds Updated:** {status.last_feed_refresh}"
        f"{auto_note}"
    )

    if status.feed_health == "Healthy":
        st.success(banner)
    elif status.feed_health == "Degraded":
        st.warning(banner)
    elif status.feed_health == "Offline":
        st.error(banner)
    else:
        st.info(banner)

    st.caption(
        f"{status.feed_detail} · Last quick refresh: {status.last_quick_refresh}"
    )