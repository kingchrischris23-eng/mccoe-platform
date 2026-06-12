import streamlit as st

import config
from config import get_nvd_key_debug_info, has_nvd_api_key, reload_settings
from src.config.env_store import mask_secret, update_env_value
from src.feeds.nvd_probe import probe_nvd_api_connection
from src.feeds.rate_limit import nvd_interval_seconds


def render() -> None:
    st.title("Settings")
    st.write("Manage local configuration. Secrets are saved to your `.env` file and never committed to git.")

    _render_nvd_api_key_section()


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