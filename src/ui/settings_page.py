import streamlit as st

from config import has_nvd_api_key, reload_settings, settings
from src.config.env_store import mask_secret, update_env_value
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

        Leave the field blank and save to remove a stored key and return to no-key mode.
        """
    )

    st.info(f"Current status: **{mask_secret(settings.nvd_api_key)}**")
    if has_nvd_api_key():
        st.caption(f"NVD request interval: ~{nvd_interval_seconds():.1f}s between calls (with key).")
    else:
        st.caption(f"NVD request interval: ~{nvd_interval_seconds():.1f}s between calls (no-key mode).")

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
                st.success("NVD API key saved to .env.")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not write .env: {exc}")
    with col2:
        if st.button("Clear stored key"):
            try:
                update_env_value("NVD_API_KEY", "")
                reload_settings()
                st.success("NVD API key removed. No-key mode active.")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not write .env: {exc}")

    st.caption("`.env` is listed in `.gitignore` and is not pushed to GitHub.")
    if settings.use_api_backend:
        st.warning("FastAPI backend mode is on — restart the API server after saving so it reloads `.env`.")