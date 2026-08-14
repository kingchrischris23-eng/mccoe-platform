from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

# MCCoE-aligned palette — distinct, professional, colorblind-friendly
ALERT_CHART_COLORS = [
    "#1F4E79",
    "#C62828",
    "#F57C00",
    "#2E7D32",
    "#6A1B9A",
    "#00838F",
    "#455A64",
    "#1976D2",
    "#AD1457",
    "#558B2F",
]


def alert_breakdown_pie(breakdown: dict[str, int], output_path: Path) -> Path | None:
    if not breakdown:
        return None

    labels = list(breakdown.keys())
    sizes = list(breakdown.values())
    total = sum(sizes)
    if total <= 0:
        return None

    colors = [ALERT_CHART_COLORS[i % len(ALERT_CHART_COLORS)] for i in range(len(labels))]
    legend_labels = [
        f"{_short_label(name)} — {count} ({100 * count / total:.0f}%)"
        for name, count in zip(labels, sizes)
    ]

    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    wedges, _texts, autotexts = ax.pie(
        sizes,
        labels=None,
        autopct=_autopct_formatter(min_pct=7.0),
        pctdistance=0.78,
        colors=colors,
        startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.42, "edgecolor": "#FFFFFF", "linewidth": 1.6},
    )
    for autotext in autotexts:
        if autotext.get_text():
            autotext.set_fontsize(9)
            autotext.set_fontweight("bold")
            autotext.set_color("#FFFFFF")

    ax.set_title("Log Alert Breakdown", fontsize=12, fontweight="bold", pad=14)
    ax.legend(
        wedges,
        legend_labels,
        title="Alert rules",
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        fontsize=8.5,
        title_fontsize=9,
        frameon=True,
        framealpha=0.96,
        edgecolor="#CCCCCC",
    )
    fig.subplots_adjust(left=0.04, right=0.58, top=0.9, bottom=0.08)
    fig.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return output_path


def vulnerability_risk_bar(vuln_scans: list[dict], output_path: Path) -> Path | None:
    if not vuln_scans:
        return None

    scans = vuln_scans[:6]
    targets = [_short_label(scan["target"], max_len=18) for scan in scans]
    scores = [float(scan.get("risk_score", 0)) for scan in scans]
    colors = [_risk_color(score) for score in scores]

    fig, ax = plt.subplots(figsize=(6.5, 3.6))
    bars = ax.barh(targets, scores, color=colors, edgecolor="#37474F", linewidth=0.5)
    ax.set_xlim(0, 100)
    ax.set_xlabel("Risk Score", fontsize=9)
    ax.set_title("Vulnerability Risk Scores", fontsize=11, fontweight="bold", pad=10)
    ax.axvline(25, color="#F0AD4E", linestyle="--", linewidth=0.9, alpha=0.75)
    ax.axvline(50, color="#D9534F", linestyle="--", linewidth=0.9, alpha=0.75)
    ax.axvline(75, color="#922B21", linestyle="--", linewidth=0.9, alpha=0.75)
    ax.tick_params(axis="both", labelsize=8)
    for bar, score in zip(bars, scores):
        ax.text(
            min(bar.get_width() + 1.5, 92),
            bar.get_y() + bar.get_height() / 2,
            f"{score:.0f}",
            va="center",
            fontsize=8,
            fontweight="bold",
            color="#212121",
        )
    fig.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return output_path


def _autopct_formatter(min_pct: float = 7.0):
    def _fmt(pct: float) -> str:
        return f"{pct:.0f}%" if pct >= min_pct else ""

    return _fmt


def _short_label(label: str, max_len: int = 28) -> str:
    text = str(label).strip()
    return text if len(text) <= max_len else f"{text[: max_len - 3]}..."


def _risk_color(score: float) -> str:
    if score >= 75:
        return "#922B21"
    if score >= 50:
        return "#D9534F"
    if score >= 25:
        return "#F0AD4E"
    return "#5CB85C"