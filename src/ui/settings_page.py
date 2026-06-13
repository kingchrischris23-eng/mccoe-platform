import streamlit as st

import config
from config import (
    get_auto_feed_refresh_hours,
    get_ioc_ui_page_size,
    get_max_iocs_report,
    get_nvd_key_debug_info,
    get_otx_api_key,
    get_abusech_auth_key,
    has_abusech_auth_key,
    has_nvd_api_key,
    has_otx_api_key,
    is_auto_feed_refresh_enabled,
    reload_settings,
)
from src.feeds.aggregator import can_refresh_live
from src.config.env_store import mask_secret, update_env_value
from src.feeds.nvd_probe import probe_nvd_api_connection
from src.feeds.otx_probe import probe_otx_api_connection
from src.feeds.rate_limit import nvd_interval_seconds
from src.ui.clear_data import render_clear_data_section


def render() -> None:
    st.title("Settings")
    st.write("Manage local configuration. Secrets are saved to your `.env` file and never committed to git.")

    _render_monitoring_section()
    _render_display_section()
    _render_otx_api_key_section()
    _render_abusech_auth_key_section()
    _render_nvd_api_key_section()
    st.markdown("---")
    render_clear_data_section()


def _render_monitoring_section() -> None:
    st.subheader("Feed Auto-Refresh")
    st.markdown(
        """
        Optionally refresh live threat feeds on a schedule using a lightweight background thread.
        Disabled by default — no extra work runs unless you turn this on.
        """
    )

    refresh_hours = get_auto_feed_refresh_hours()
    auto_enabled = is_auto_feed_refresh_enabled()
    auto_refresh = st.toggle(
        f"Enable auto-refresh every {refresh_hours} hours",
        value=auto_enabled,
        help="Requires online mode (`LOCAL_ONLY=false`) and `ENABLE_LIVE_FEEDS=true`.",
    )
    if auto_refresh != auto_enabled:
        update_env_value("ENABLE_AUTO_FEED_REFRESH", "true" if auto_refresh else "false")
        reload_settings()
        st.rerun()

    hours = st.number_input(
        "Refresh interval (hours)",
        min_value=1,
        max_value=168,
        value=refresh_hours,
        step=1,
        help="How often the background thread checks whether feeds need refreshing.",
    )
    if hours != refresh_hours:
        update_env_value("AUTO_FEED_REFRESH_HOURS", str(int(hours)))
        reload_settings()
        st.rerun()

    if auto_refresh and not can_refresh_live():
        st.warning("Auto-refresh is on, but live feeds are disabled. Enable online mode and live feeds to use it.")
    elif auto_refresh:
        st.success(f"Auto-refresh active — feeds will refresh about every {int(hours)} hour(s).")
    else:
        st.caption("Auto-refresh is off. Use **Quick Refresh All** on the Overview page when needed.")

    st.markdown("---")


def _render_display_section() -> None:
    st.subheader("Threat Intelligence Display")
    st.markdown(
        """
        **Threat Feeds** loads **all IOCs** with pagination (50 per page, no display cap).
        Reports include the newest subset up to the limit below.
        """
    )

    report_max = get_max_iocs_report()
    page_size = get_ioc_ui_page_size()

    new_report_max = st.number_input(
        "Max IOCs in Reports",
        min_value=100,
        max_value=50000,
        value=report_max,
        step=100,
        help="PDF/Markdown reports include the newest IOCs up to this limit (default 5000).",
    )
    if int(new_report_max) != report_max:
        update_env_value("MAX_IOCS_REPORT", str(int(new_report_max)))
        reload_settings()
        st.rerun()

    new_page_size = st.number_input(
        "IOCs per page (Threat Feeds)",
        min_value=10,
        max_value=200,
        value=page_size,
        step=10,
        help="Pagination size for the Threat Intelligence table.",
    )
    if int(new_page_size) != page_size:
        update_env_value("IOC_UI_PAGE_SIZE", str(int(new_page_size)))
        reload_settings()
        st.rerun()

    st.caption(
        f"Reports: **{report_max}** newest IOCs of total tracked. "
        f"UI: **{page_size}** IOCs per page with Previous/Next navigation."
    )
    st.markdown("---")


def _render_otx_api_key_section() -> None:
    st.subheader("AlienVault OTX API Key")
    st.markdown(
        """
        OTX requires a **free API key** for live pulse pulls.

        1. Sign up at [AlienVault OTX](https://otx.alienvault.com/).
        2. Copy your API key from your profile settings.
        3. Paste below and click **Save to .env**.
        """
    )

    resolved = get_otx_api_key()
    if has_otx_api_key():
        st.success(f"OTX API key detected ({len(resolved)} chars).")
    else:
        st.warning("No OTX API key — OTX feed will serve cache only or stay empty.")

    col_test, col_reload = st.columns(2)
    with col_test:
        if st.button("Test OTX Connection", key="test_otx"):
            with st.spinner("Calling AlienVault OTX API..."):
                st.session_state["otx_test_result"] = probe_otx_api_connection()
    with col_reload:
        if st.button("Reload OTX from .env", key="reload_otx"):
            reload_settings()
            st.success("Reloaded settings from .env.")
            st.rerun()

    test_result = st.session_state.get("otx_test_result")
    if test_result:
        if test_result["success"]:
            st.success(test_result["message"])
        else:
            st.error(test_result["message"])

    new_key = st.text_input(
        "OTX API Key",
        value="",
        type="password",
        placeholder="Paste your AlienVault OTX API key",
        key="otx_key_input",
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Save OTX Key to .env", type="primary", key="save_otx"):
            try:
                update_env_value("OTX_API_KEY", new_key.strip())
                reload_settings()
                st.session_state.pop("otx_test_result", None)
                st.success(f"Saved. Status: {mask_secret(get_otx_api_key())}")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not write .env: {exc}")
    with col2:
        if st.button("Clear OTX Key", key="clear_otx"):
            try:
                update_env_value("OTX_API_KEY", "")
                reload_settings()
                st.session_state.pop("otx_test_result", None)
                st.success("OTX API key removed.")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not write .env: {exc}")

    st.markdown("---")


def _render_abusech_auth_key_section() -> None:
    st.subheader("abuse.ch Auth-Key (ThreatFox)")
    st.markdown(
        """
        ThreatFox requires a free **Auth-Key** from the abuse.ch authentication portal.

        1. Register at [abuse.ch Authentication Portal](https://auth.abuse.ch/).
        2. Copy your Auth-Key.
        3. Paste below and click **Save to .env**.

        The same key works across abuse.ch community APIs (ThreatFox, etc.).
        """
    )

    resolved = get_abusech_auth_key()
    if has_abusech_auth_key():
        st.success(f"abuse.ch Auth-Key detected ({len(resolved)} chars).")
    else:
        st.warning("No Auth-Key — ThreatFox will serve cache only or stay empty.")

    if st.button("Reload abuse.ch key from .env", key="reload_abusech"):
        reload_settings()
        st.success("Reloaded settings from .env.")
        st.rerun()

    new_key = st.text_input(
        "abuse.ch Auth-Key",
        value="",
        type="password",
        placeholder="Paste your abuse.ch Auth-Key",
        key="abusech_key_input",
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Save Auth-Key to .env", type="primary", key="save_abusech"):
            try:
                update_env_value("ABUSECH_AUTH_KEY", new_key.strip())
                reload_settings()
                st.success(f"Saved. Status: {mask_secret(get_abusech_auth_key())}")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not write .env: {exc}")
    with col2:
        if st.button("Clear Auth-Key", key="clear_abusech"):
            try:
                update_env_value("ABUSECH_AUTH_KEY", "")
                reload_settings()
                st.success("abuse.ch Auth-Key removed.")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not write .env: {exc}")

    st.markdown("---")


def _render_nvd_api_key_section() -> None:
    st.subheader("NIST NVD API Key")
    st.markdown(
        """
        An NVD API key is **optional**. Without one, the dashboard uses NVD public limits
        (5 requests per 30 seconds). With a key, limits increase to 50 requests per 30 seconds.

        1. Request a free key at [NIST NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key).
        2. Paste it below and click **Save to .env**.
        3. The key is stored only in your local `.env` file (gitignored).
        """
    )

    debug = get_nvd_key_debug_info()
    resolved_key = config.get_nvd_api_key()

    st.info(f"**Key status:** {debug['resolved_key_masked']}")
    if debug["has_key"]:
        st.success(
            f"NVD API key detected ({debug['resolved_key_length']} chars). "
            f"Rate mode: **{debug['rate_mode']}** (~{nvd_interval_seconds():.1f}s between requests)."
        )
    else:
        st.warning(
            f"No NVD API key detected. Using **no-key mode** "
            f"(~{nvd_interval_seconds():.1f}s between requests)."
        )

    with st.expander("Debug: key detection details", expanded=not debug["has_key"]):
        st.markdown(
            f"""
            | Check | Value |
            |-------|-------|
            | `.env` file exists | `{debug['env_file_exists']}` |
            | `.env` path | `{debug['env_file_path']}` |
            | Key in `.env` file | `{debug['env_file_key_masked']}` (len={debug['env_file_key_length']}) |
            | Key in `os.environ` (dotenv) | length={debug['dotenv_key_length']} |
            | Key in `settings` object | length={debug['settings_key_length']} |
            | **Resolved key** | `{debug['resolved_key_masked']}` (len={debug['resolved_key_length']}) |
            | `has_nvd_api_key()` | `{debug['has_key']}` |
            | All sources in sync | `{debug['keys_in_sync']}` |
            """
        )
        if not debug["keys_in_sync"] and debug["has_key"]:
            st.caption("Sources differ — click **Reload from .env** or save again to sync.")

    col_test, col_reload = st.columns(2)
    with col_test:
        if st.button("Test NVD Connection", type="secondary"):
            with st.spinner("Calling NIST NVD API..."):
                result = probe_nvd_api_connection()
            st.session_state["nvd_test_result"] = result
    with col_reload:
        if st.button("Reload from .env"):
            reload_settings()
            st.success("Reloaded settings from .env.")
            st.rerun()

    test_result = st.session_state.get("nvd_test_result")
    if test_result:
        if test_result["success"]:
            st.success(
                f"{test_result['message']} "
                f"(mode: {test_result['rate_mode']}, key length: {test_result['key_length']})"
            )
        else:
            st.error(
                f"NVD connection failed: {test_result['message']} "
                f"(mode: {test_result['rate_mode']}, key length: {test_result['key_length']})"
            )

    st.markdown("---")

    new_key = st.text_input(
        "NVD API Key",
        value="",
        type="password",
        placeholder="Paste your NIST NVD API key",
        help="Value is written to .env on save. Field stays empty to avoid displaying secrets.",
    )

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Save to .env", type="primary"):
            try:
                update_env_value("NVD_API_KEY", new_key.strip())
                reload_settings()
                st.session_state.pop("nvd_test_result", None)
                st.success(f"Saved. Status: {mask_secret(config.get_nvd_api_key())}")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not write .env: {exc}")
    with col2:
        if st.button("Clear stored key"):
            try:
                update_env_value("NVD_API_KEY", "")
                reload_settings()
                st.session_state.pop("nvd_test_result", None)
                st.success("NVD API key removed. No-key mode active.")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not write .env: {exc}")

    st.caption("`.env` is listed in `.gitignore` and is not pushed to GitHub.")
    if config.settings.use_api_backend:
        st.warning("FastAPI backend mode is on — restart the API server after saving so it reloads `.env`.")