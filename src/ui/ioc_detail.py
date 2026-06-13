import streamlit as st

from src.feeds.ioc_display import format_last_seen, recency_label, severity_palette
from src.feeds.mitigation import MitigationBrief, build_mitigation_brief


def _cached_brief(row: dict) -> MitigationBrief:
    cache = st.session_state.setdefault("mitigation_cache", {})
    key = (
        row.get("value"),
        row.get("source"),
        row.get("first_seen"),
        row.get("description"),
    )
    if key not in cache:
        cache[key] = build_mitigation_brief(row)
    return cache[key]


def _severity_badge(severity: str) -> str:
    key = str(severity).lower()
    palette = severity_palette(key)
    text = palette["badge_text"]
    return (
        f"<span style='background:{palette['accent']};color:{text};"
        f"padding:6px 14px;border-radius:8px;font-weight:700;'>"
        f"{severity.upper()}</span>"
    )


def _patch_badge(status: str) -> str:
    lowered = status.lower()
    if lowered.startswith("yes"):
        color = "#2E7D32"
    elif lowered.startswith("likely"):
        color = "#F57C00"
    elif lowered.startswith("no"):
        color = "#C62828"
    else:
        color = "#546E7A"
    return (
        f"<span style='background:{color};color:#fff;padding:5px 12px;"
        f"border-radius:8px;font-weight:600;'>{status}</span>"
    )


def render_ioc_detail_content(row: dict, *, brief: MitigationBrief | None = None) -> None:
    brief = brief or _cached_brief(row)
    st.markdown(
        f"### {brief.value} &nbsp; {_severity_badge(brief.severity)}",
        unsafe_allow_html=True,
    )
    if brief.title and brief.title != brief.value:
        st.markdown(f"**{brief.title}**")

    meta1, meta2, meta3, meta4 = st.columns(4)
    meta1.metric("Type", brief.ioc_type.upper())
    meta2.metric("Source", brief.source)
    meta3.metric("Vendor", brief.vendor or "—")
    meta4.metric("Product", brief.product or "—")

    st.markdown("#### Overview")
    st.write(brief.summary)
    st.caption(
        f"Last seen: {format_last_seen(row)} | Recency: {recency_label(row)} | "
        f"Data: {', '.join(brief.data_sources) or brief.source}"
    )

    if brief.kev_due_date:
        st.warning(f"CISA KEV remediation due: **{brief.kev_due_date}**")

    st.markdown("#### Patch & Workarounds")
    st.markdown(_patch_badge(brief.patch_available), unsafe_allow_html=True)
    st.write(brief.patch_notes)
    if brief.kev_required_action:
        st.info(brief.kev_required_action)

    if brief.workarounds:
        st.markdown("**Workarounds**")
        for item in brief.workarounds:
            st.markdown(f"- {item}")

    st.markdown("#### Mitigation Steps")
    for index, step in enumerate(brief.steps, start=1):
        st.markdown(f"{index}. {step}")

    if brief.service_actions:
        with st.expander("Service / software actions", expanded=False):
            for item in brief.service_actions:
                st.markdown(f"- {item}")

    if brief.firewall_rules:
        with st.expander("Firewall & network controls", expanded=False):
            for item in brief.firewall_rules:
                st.markdown(f"- `{item}`")

    if brief.references:
        st.markdown("#### References")
        for ref in brief.references:
            label = ref.get("label", "Reference")
            st.markdown(f"- [{label}]({ref['url']})")


@st.dialog("Threat Intelligence Detail", width="large")
def show_ioc_detail_dialog(row: dict) -> None:
    render_ioc_detail_content(row)


def render_selected_ioc_panel(row: dict | None) -> None:
    if not row:
        st.caption("Select a row in the table above to view CVE/IOC details and mitigation steps.")
        return

    with st.expander(f"Details & mitigation — {row.get('value', 'IOC')}", expanded=True):
        render_ioc_detail_content(row)


def open_detail_for_row(row: dict) -> None:
    st.session_state["selected_ioc_row"] = row
    show_ioc_detail_dialog(row)