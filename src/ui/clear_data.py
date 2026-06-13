import streamlit as st

from src.storage.data_clear import (
    CLEAR_OPTIONS,
    PROTECTED_NOTICE,
    execute_clear,
    preview_clear,
)


def _selection_defaults() -> dict[str, bool]:
    return {option.key: False for option in CLEAR_OPTIONS}


def _get_selections() -> dict[str, bool]:
    stored = st.session_state.get("clear_data_selections")
    if not isinstance(stored, dict):
        stored = _selection_defaults()
        st.session_state["clear_data_selections"] = stored
    return stored


def _selected_keys(selections: dict[str, bool]) -> list[str]:
    return [key for key, enabled in selections.items() if enabled]


def _apply_quick_all_except_settings() -> None:
    st.session_state["clear_data_selections"] = {option.key: option.key == "all_user_data" for option in CLEAR_OPTIONS}


def _reset_ui_state() -> None:
    st.session_state.pop("clear_data_confirm", None)
    st.session_state["clear_data_selections"] = _selection_defaults()
    for key in (
        "selected_ioc_row",
        "selected_ioc_token",
        "mitigation_cache",
        "ioc_page",
        "active_session_id",
        "demo_loaded",
        "feed_refresh",
    ):
        st.session_state.pop(key, None)


def render_clear_data_section(*, compact: bool = False) -> None:
    selections = _get_selections()
    title = "#### Clear Data" if compact else "## Data Management"
    st.markdown(title)
    st.markdown(
        "Select what to remove from the dashboard. This is useful for resetting labs, "
        "clearing stale caches, or starting fresh without touching configuration."
    )
    st.info(PROTECTED_NOTICE)

    quick_col, _ = st.columns([1, 2])
    with quick_col:
        if st.button("Clear Everything Except Settings", type="secondary"):
            _apply_quick_all_except_settings()
            st.session_state["clear_data_confirm"] = True
            st.rerun()

    st.markdown("### Choose what to clear")
    for option in CLEAR_OPTIONS:
        if option.key == "all_user_data":
            st.markdown("---")
        selections[option.key] = st.checkbox(
            option.label,
            value=selections.get(option.key, False),
            help=option.description,
        )

    if selections.get("all_user_data"):
        for option in CLEAR_OPTIONS:
            if option.key != "all_user_data":
                selections[option.key] = False

    st.session_state["clear_data_selections"] = selections
    selected = _selected_keys(selections)
    preview = preview_clear(selected) if selected else None

    if preview and preview.summary_lines():
        st.markdown("### Preview")
        for line in preview.summary_lines():
            st.markdown(line)
        st.caption(f"Estimated deletions: {preview.total_items}")
    elif selected:
        st.success("Selected categories are already empty.")

    action_col1, action_col2 = st.columns(2)
    with action_col1:
        review_disabled = not selected or (preview is not None and preview.total_items == 0 and "all_user_data" not in selected)
        if st.button("Review & Confirm", type="primary", disabled=not selected):
            st.session_state["clear_data_confirm"] = True
            st.rerun()
    with action_col2:
        if st.button("Reset Selection"):
            _reset_ui_state()
            st.rerun()

    if st.session_state.get("clear_data_confirm") and selected:
        st.warning("Confirm permanent deletion")
        if preview:
            for line in preview.summary_lines():
                st.markdown(line)
        st.markdown("This cannot be undone. Settings, API keys, and demo catalog files will not be deleted.")
        confirm_col1, confirm_col2 = st.columns(2)
        with confirm_col1:
            if st.button("Yes, delete selected data", type="primary"):
                result = execute_clear(selected)
                _reset_ui_state()
                if result.summary_lines():
                    st.success("Selected data cleared.")
                    for line in result.summary_lines():
                        st.markdown(line)
                else:
                    st.success("Clear operation completed. Selected categories were already empty.")
                st.rerun()
        with confirm_col2:
            if st.button("Cancel"):
                st.session_state.pop("clear_data_confirm", None)
                st.rerun()


@st.dialog("Clear Data")
def show_clear_data_dialog() -> None:
    render_clear_data_section(compact=True)


def render_clear_data_sidebar_trigger() -> None:
    if st.sidebar.button("Clear Data…", help="Selectively clear caches, logs, IOCs, scans, and reports."):
        show_clear_data_dialog()