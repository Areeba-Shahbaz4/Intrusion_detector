# ZERO TRUST AI INTRUSION DETECTION SYSTEM
# ANALYTICS MODULE
# Detection Visualization
import os
import matplotlib
# Use non-GUI backend for Flask/server environments
matplotlib.use("Agg")
import matplotlib.pyplot as plt
# CREATE DETECTION CHART
def create_detection_chart(normal_records, attack_records):
    # CHART DIRECTORY
    chart_directory = os.path.join(
        "static",
        "charts"
    )
    os.makedirs(
        chart_directory,
        exist_ok=True
    )
    # CHART PATH
    chart_path = os.path.join(
        chart_directory,
        "detection_analysis.png"
    )
    # CREATE FIGURE
    plt.figure(
        figsize=(9, 5)
    )
    # DATA
    labels = [
        "Normal Traffic",
        "Attack Traffic"
    ]
    values = [
        normal_records,
        attack_records
    ]
    # BAR CHART
    bars = plt.bar(
        labels,
        values
    )
    # TITLE
    plt.title(
        "AI Intrusion Detection Analysis",
        fontsize=16,
        fontweight="bold"
    )
    plt.ylabel(
        "Number of Records"
    )
    # VALUE LABELS
    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x()
            + bar.get_width() / 2,
            height,
            str(int(height)),
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold"
        )
    # GRID
    plt.grid(
        axis="y",
        linestyle="--",
        alpha=0.3
    )
    # LAYOUT
    plt.tight_layout()
    # SAVE CHART
    plt.savefig(
        chart_path,
        dpi=150,
        bbox_inches="tight"
    )
    # CLOSE FIGURE
    plt.close()
    # RETURN PATH
    return chart_path