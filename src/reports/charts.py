from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="whitegrid", font_scale=0.9)


def alert_breakdown_pie(breakdown: dict[str, int], output_path: Path) -> Path | None:
    if not breakdown:
        return None

    labels = list(breakdown.keys())
    sizes = list(breakdown.values())
    colors = sns.color_palette("muted", n_colors=len(labels))

    fig, ax = plt.subplots(figsize=(5.0, 3.2))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=[_short_label(label) for label in labels],
        autopct="%1.0f%%",
        colors=colors,
        startangle=140,
        textprops={"fontsize": 8},
    )
    for autotext in autotexts:
        autotext.set_fontsize(7)
    ax.set_title("Log Alert Breakdown", fontsize=10, fontweight="bold")
    fig.tight_layout()
    fig.savefig(output_path, dpi=130, bbox_inches="tight")
    plt.close(fig)
    return output_path


def vulnerability_risk_bar(vuln_scans: list[dict], output_path: Path) -> Path | None:
    if not vuln_scans:
        return None

    scans = vuln_scans[:6]
    targets = [scan["target"] for scan in scans]
    scores = [float(scan.get("risk_score", 0)) for scan in scans]
    colors = [_risk_color(score) for score in scores]

    fig, ax = plt.subplots(figsize=(5.0, 3.0))
    bars = ax.barh(targets, scores, color=colors, edgecolor="#333333", linewidth=0.4)
    ax.set_xlim(0, 100)
    ax.set_xlabel("Risk Score")
    ax.set_title("Vulnerability Risk Scores", fontsize=10, fontweight="bold")
    ax.axvline(25, color="#f0ad4e", linestyle="--", linewidth=0.8, alpha=0.7)
    ax.axvline(50, color="#d9534f", linestyle="--", linewidth=0.8, alpha=0.7)
    ax.axvline(75, color="#922b21", linestyle="--", linewidth=0.8, alpha=0.7)
    for bar, score in zip(bars, scores):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2, f"{score:.0f}", va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(output_path, dpi=130, bbox_inches="tight")
    plt.close(fig)
    return output_path


def _short_label(label: str, max_len: int = 22) -> str:
    return label if len(label) <= max_len else f"{label[:19]}..."


def _risk_color(score: float) -> str:
    if score >= 75:
        return "#922b21"
    if score >= 50:
        return "#d9534f"
    if score >= 25:
        return "#f0ad4e"
    return "#5cb85c"