#!/usr/bin/env python3
"""
Incident Statistics Chart Generator
====================================
Generates all 7 charts + Q1 heatmap table image for the incident-statistics skill.

Usage:
    python3 generate_charts.py <input_json> <output_dir> <lookback_label>

Input JSON format:
{
    "q1": [...],  // Incidents by Title (Rank, Title, Severity, Total, New, Active, Closed, Tactics, Techniques)
    "q2": [...],  // MITRE Tactics & Techniques (Tactic, Technique, IncidentCount)
    "q3": [...],  // MTTA (Period, AvgMTTA, MedianMTTA, P90_MTTA, P99_MTTA, TotalIncidents)
    "q4": [...],  // MTTR (Period, AvgMTTR, MedianMTTR, P90_MTTR, P99_MTTR, TotalIncidents)
    "q5": [...],  // By Assignee (Assignee, IncidentCount)
    "q6": [...],  // Top 5 Users (UserName, IncidentCount)
    "q7": [...],  // Top 5 Devices (DeviceName, IncidentCount)
}

Each value is the array of result objects from the KQL query (as returned by the MCP tool).
Empty arrays or missing keys mean no data for that query — the chart is skipped.
"""

import json
import sys
import os
import re
from datetime import datetime, timedelta, timezone

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


# ---------------------------------------------------------------------------
# Q1: Heatmap table image (PNG)
# ---------------------------------------------------------------------------

def _heatmap_rgba(value, max_val, base_rgb):
    """Return (r, g, b, 1.0) tuple blended from white toward base_rgb."""
    if max_val == 0 or value == 0:
        return (1.0, 1.0, 1.0, 1.0)
    ratio = min(value / max_val, 1.0)
    br, bg, bb = [c / 255.0 for c in base_rgb]
    # lerp white → base colour
    return (1.0 - ratio * (1.0 - br),
            1.0 - ratio * (1.0 - bg),
            1.0 - ratio * (1.0 - bb),
            1.0)


def _text_color_for_bg(rgba):
    """Return 'white' or '#2c3e50' depending on background luminance."""
    lum = 0.299 * rgba[0] + 0.587 * rgba[1] + 0.114 * rgba[2]
    return 'white' if lum < 0.55 else '#2c3e50'


def generate_q1_table_image(data, output_dir, lookback_label):
    """Render the Q1 incident overview as a PNG table with heatmap cells."""
    if not data:
        print("  Q1 table image: No data — skipped")
        return

    from textwrap import shorten

    # --- time window --------------------------------------------------
    now = datetime.now(timezone.utc)
    match = re.search(r'(\d+)', lookback_label)
    days = int(match.group(1)) if match else 90
    start = now - timedelta(days=days)

    # --- extract values -----------------------------------------------
    rows = []
    for i, r in enumerate(data):
        rows.append({
            "rank":    str(r.get("Rank", i + 1)),
            "title":   shorten(r.get("Title", "Unknown"), width=72, placeholder="..."),
            "sev":     r.get("Severity", ""),
            "total":   int(r.get("Total", 0)),
            "new":     int(r.get("New", 0)),
            "active":  int(r.get("Active", 0)),
            "closed":  int(r.get("Closed", 0)),
        })

    max_t  = max(r["total"]  for r in rows) or 1
    max_n  = max(r["new"]    for r in rows) or 1
    max_a  = max(r["active"] for r in rows) or 1
    max_c  = max(r["closed"] for r in rows) or 1
    grand  = sum(r["total"]  for r in rows)

    # severity summary
    sc = {}
    for r in rows:
        sc[r["sev"]] = sc.get(r["sev"], 0) + r["total"]
    sev_parts = [f"{s}: {sc[s]}" for s in ("High", "Medium", "Low", "Informational") if s in sc]

    # colour bases (RGB 0-255)
    COL_TOTAL  = (231, 76,  60)   # red
    COL_NEW    = (230, 126, 34)   # orange
    COL_ACTIVE = (52,  152, 219)  # blue
    COL_CLOSED = (39,  174, 96)   # green

    # --- build table data for matplotlib ------------------------------
    col_labels = ["Rank", "Incident Title", "Severity",
                  "Total", "New", "Active", "Closed"]
    cell_text  = []
    cell_colors = []
    HEADER_BG  = "#2c3e50"
    WHITE      = (1, 1, 1, 1)
    ZEBRA      = (0.97, 0.97, 0.97, 1)

    for i, r in enumerate(rows):
        bg = ZEBRA if i % 2 == 1 else WHITE
        cell_text.append([
            r["rank"], r["title"], r["sev"],
            str(r["total"]), str(r["new"]), str(r["active"]), str(r["closed"]),
        ])
        cell_colors.append([
            bg, bg, bg,
            _heatmap_rgba(r["total"],  max_t, COL_TOTAL),
            _heatmap_rgba(r["new"],    max_n, COL_NEW),
            _heatmap_rgba(r["active"], max_a, COL_ACTIVE),
            _heatmap_rgba(r["closed"], max_c, COL_CLOSED),
        ])

    nrows = len(rows)
    fig_h = max(4, 0.42 * nrows + 1.8)
    fig, ax = plt.subplots(figsize=(16, fig_h))
    ax.axis('off')

    # subtitle
    sub = (f"Time window: {start.strftime('%Y-%m-%dT%H:%M:%SZ')} to "
           f"{now.strftime('%Y-%m-%dT%H:%M:%SZ')} (UTC)  |  "
           f"Total: {grand}  |  {' | '.join(sev_parts)}")
    ax.set_title(
        f"Incidents by Title — Last {lookback_label}\n"
        f"{sub}",
        fontsize=12, fontweight='bold', loc='left', pad=12,
        color='#2c3e50')

    col_widths = [0.04, 0.44, 0.08, 0.06, 0.06, 0.06, 0.06]
    tbl = ax.table(
        cellText=cell_text,
        colLabels=col_labels,
        cellLoc='center',
        loc='center',
        colWidths=col_widths,
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8.5)
    tbl.scale(1.0, 1.45)

    # style header row
    for j in range(len(col_labels)):
        cell = tbl[0, j]
        cell.set_facecolor(HEADER_BG)
        cell.set_text_props(color='white', fontweight='bold', fontsize=9)
        cell.set_edgecolor('#bdc3c7')

    # style body cells
    for i in range(nrows):
        for j in range(len(col_labels)):
            cell = tbl[i + 1, j]
            rgba = cell_colors[i][j]
            cell.set_facecolor(rgba)
            cell.set_edgecolor('#dcdcdc')
            tc = _text_color_for_bg(rgba)
            fw = 'bold' if j >= 3 and rgba != WHITE and rgba != ZEBRA else 'normal'
            cell.set_text_props(color=tc, fontweight=fw)
            # left-align title column
            if j == 1:
                cell.set_text_props(ha='left')
                cell.PAD = 0.02

    plt.tight_layout()
    path = os.path.join(output_dir, '1_incidents_by_title_table.png')
    plt.savefig(path, dpi=170, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Q1 table image saved: {path}")


# ---------------------------------------------------------------------------
# Q1: 3-D pie chart
# ---------------------------------------------------------------------------

def chart_q1_pie(data, output_dir, lookback_label):
    """Chart 1: 3D Pie chart of incidents by title."""
    if not data:
        print("  Chart 1: No data — skipped")
        return

    title_counts = {}
    for row in data:
        title = row.get("Title", "Unknown")
        count = int(row.get("Total", row.get("IncidentCount", 0)))
        title_counts[title] = title_counts.get(title, 0) + count

    sorted_data = sorted(title_counts.items(), key=lambda x: x[1], reverse=True)

    top8 = list(sorted_data[:8])
    other_count = sum(d[1] for d in sorted_data[8:])
    if other_count > 0:
        top8.append(("Other", other_count))

    labels = [d[0] for d in top8]
    sizes = [d[1] for d in top8]
    total = sum(sizes)
    colors = ['#e74c3c', '#e67e22', '#f39c12', '#2ecc71',
              '#3498db', '#9b59b6', '#1abc9c', '#e84393', '#bdc3c7']
    explode = [0.05 if s == max(sizes) else 0 for s in sizes]

    fig, ax = plt.subplots(figsize=(14, 8))

    # 3D depth layers
    for i in range(18, 0, -1):
        shadow_colors = []
        for c in colors[:len(sizes)]:
            r = int(c[1:3], 16) / 255
            g = int(c[3:5], 16) / 255
            b = int(c[5:7], 16) / 255
            factor = 0.50 + 0.18 * (i / 18)
            shadow_colors.append((r * factor, g * factor, b * factor))
        ax.pie(sizes, center=(0, -i * 0.004), startangle=140,
               colors=shadow_colors, explode=explode,
               wedgeprops=dict(edgecolor='none', linewidth=0), radius=1.0)

    # Top face
    wedges, texts, autotexts = ax.pie(
        sizes, labels=None,
        autopct=lambda pct: f'{pct:.1f}%\n({int(round(pct * total / 100))})',
        startangle=140, colors=colors[:len(sizes)], explode=explode,
        pctdistance=0.72, wedgeprops=dict(edgecolor='white', linewidth=2.5),
        radius=1.0, textprops=dict(fontsize=10))

    for t in autotexts:
        t.set_fontsize(8.5)
        t.set_fontweight('bold')
        t.set_color('white')
        t.set_bbox(dict(boxstyle='round,pad=0.2', facecolor='black',
                        alpha=0.45, edgecolor='none'))

    ax.legend(wedges, labels, title="Incident Title", loc="center left",
              bbox_to_anchor=(1.0, 0, 0.5, 1), fontsize=8, title_fontsize=10,
              frameon=True, fancybox=True, shadow=True)
    ax.set_title(f'Incidents by Title — Last {lookback_label}',
                 fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    path = os.path.join(output_dir, '1_incidents_by_title.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Chart 1 saved: {path}")


# ---------------------------------------------------------------------------
# Q2: MITRE heatmap
# ---------------------------------------------------------------------------

def chart_q2_heatmap(data, output_dir, lookback_label):
    """Chart 2: MITRE ATT&CK Heatmap (Tactic x Technique)."""
    if not data:
        print("  Chart 2: No MITRE data (no TruePositive incidents) — skipped")
        return

    tech_names = {
        "T1543": "T1543\nCreate/Modify\nSystem Process",
        "T1110": "T1110\nBrute Force",
        "T1071": "T1071\nApp Layer\nProtocol",
        "T1550": "T1550\nAlternate Auth\nMaterial",
        "T1114": "T1114\nEmail\nCollection",
        "T1078": "T1078\nValid\nAccounts",
        "T1098": "T1098\nAccount\nManipulation",
        "T1562": "T1562\nImpair\nDefenses",
        "T1199": "T1199\nTrusted\nRelationship",
        "T1136": "T1136\nCreate\nAccount",
        "T1087": "T1087\nAccount\nDiscovery",
        "T1059": "T1059\nCommand &\nScripting",
        "T1053": "T1053\nScheduled\nTask/Job",
        "T1021": "T1021\nRemote\nServices",
    }

    parsed = [(row["Tactic"], row["Technique"], int(row["IncidentCount"]))
              for row in data]
    tactics = sorted(set(d[0] for d in parsed))
    technique_ids = sorted(set(d[1] for d in parsed))

    matrix = np.zeros((len(tactics), len(technique_ids)))
    for tactic, tech, count in parsed:
        matrix[tactics.index(tactic)][technique_ids.index(tech)] = count

    fig, ax = plt.subplots(figsize=(max(10, len(technique_ids) * 1.5),
                                    max(5, len(tactics) * 0.8)))
    im = ax.imshow(matrix, cmap=plt.cm.YlOrRd, aspect='auto', vmin=0)
    ax.set_xticks(range(len(technique_ids)))
    ax.set_xticklabels([tech_names.get(t, t) for t in technique_ids],
                       fontsize=8, ha='center')
    ax.set_yticks(range(len(tactics)))
    ax.set_yticklabels(tactics, fontsize=9)

    for i in range(len(tactics)):
        for j in range(len(technique_ids)):
            val = int(matrix[i][j])
            if val > 0:
                color = 'white' if val > 10 else 'black'
                ax.text(j, i, str(val), ha='center', va='center',
                        fontsize=10, fontweight='bold', color=color)

    cbar = plt.colorbar(im, ax=ax, shrink=0.8, pad=0.02)
    cbar.set_label('Number of Incidents', fontsize=10)
    ax.set_title(
        f'MITRE ATT&CK Tactics x Techniques — True Positive Incidents\n'
        f'(Last {lookback_label})',
        fontsize=13, fontweight='bold', pad=15)
    ax.set_xlabel('Technique', fontsize=11, fontweight='bold', labelpad=10)
    ax.set_ylabel('Tactic', fontsize=11, fontweight='bold')
    plt.tight_layout()
    path = os.path.join(output_dir, '2_mitre_heatmap.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Chart 2 saved: {path}")


# ---------------------------------------------------------------------------
# Q3 / Q4: MTTA / MTTR grouped bar
# ---------------------------------------------------------------------------

def chart_mtta_mttr(data, query_num, metric_prefix, title_prefix,
                    bar_color, sla_target, output_dir, lookback_label):
    """Charts 3 & 4: MTTA/MTTR grouped bar chart with SLA target."""
    if not data:
        label = "MTTA" if query_num == 3 else "MTTR"
        print(f"  Chart {query_num}: No {label} data — skipped")
        return

    current_row = next((r for r in data if r["Period"] == "Current"), None)
    previous_row = next((r for r in data if r["Period"] == "Previous"), None)

    if not current_row and not previous_row:
        print(f"  Chart {query_num}: No period data — skipped")
        return

    avg_key = f"Avg{metric_prefix}"
    med_key = f"Median{metric_prefix}"
    p90_key = f"P90_{metric_prefix}"
    p99_key = f"P99_{metric_prefix}"

    metrics = ['Average', 'Median (P50)', 'P90', 'P99']
    x = np.arange(len(metrics))

    if current_row and previous_row:
        current = [float(current_row[avg_key]), float(current_row[med_key]),
                   float(current_row[p90_key]), float(current_row[p99_key])]
        previous = [float(previous_row[avg_key]), float(previous_row[med_key]),
                    float(previous_row[p90_key]), float(previous_row[p99_key])]
        width = 0.32

        fig, ax = plt.subplots(figsize=(11, 6.5))
        ax.bar(x - width / 2, previous, width, label='Previous Period',
               color='#95a5a6', edgecolor='white', linewidth=1.5, zorder=3)
        ax.bar(x + width / 2, current, width, label='Current Period',
               color=bar_color, edgecolor='white', linewidth=1.5, zorder=3)
        ax.axhline(y=sla_target, color='#e67e22', linestyle='--',
                   linewidth=2.5, label=f'SLA Target ({sla_target}h)', zorder=2)

        for i, (c, p) in enumerate(zip(current, previous)):
            ax.text(x[i] - width / 2, p + 0.25, f'{p:.2f}h', ha='center',
                    va='bottom', fontsize=9, fontweight='bold', color='#555555')
            ax.text(x[i] + width / 2, c + 0.25, f'{c:.2f}h', ha='center',
                    va='bottom', fontsize=9, fontweight='bold', color='#2c3e50')
            if p > 0:
                delta_pct = ((c - p) / p) * 100
                arrow = '\u25bc' if delta_pct < 0 else '\u25b2'
                clr = '#27ae60' if delta_pct < 0 else '#e74c3c'
                ax.text(x[i] + width / 2, c + 1.0,
                        f'{arrow} {abs(delta_pct):.0f}%',
                        ha='center', va='bottom', fontsize=9,
                        fontweight='bold', color=clr)

        max_val = max(max(current), max(previous))
    else:
        row = current_row or previous_row
        period_label = "Current" if current_row else "Previous"
        values = [float(row[avg_key]), float(row[med_key]),
                  float(row[p90_key]), float(row[p99_key])]
        width = 0.4

        fig, ax = plt.subplots(figsize=(11, 6.5))
        ax.bar(x, values, width, label=f'{period_label} Period',
               color=bar_color, edgecolor='white', linewidth=1.5, zorder=3)
        ax.axhline(y=sla_target, color='#e67e22', linestyle='--',
                   linewidth=2.5, label=f'SLA Target ({sla_target}h)', zorder=2)

        for i, v in enumerate(values):
            ax.text(x[i], v + 0.15, f'{v:.2f}h', ha='center', va='bottom',
                    fontsize=11, fontweight='bold', color='#2c3e50')

        max_val = max(values)

    total_str = ""
    if current_row:
        total_str += f" | {current_row['TotalIncidents']} incidents (current)"
    if previous_row:
        total_str += f", {previous_row['TotalIncidents']} (previous)"

    ax.set_ylabel('Hours', fontsize=12, fontweight='bold')
    ax.set_title(
        f'{title_prefix}\nCurrent vs Previous Period ({lookback_label})'
        f'{total_str}',
        fontsize=14, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=11)
    ax.legend(fontsize=10, loc='upper left')
    ax.grid(axis='y', alpha=0.3, linestyle='--', zorder=0)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_ylim(0, max(max_val, sla_target) * 1.2)
    plt.tight_layout()
    suffix = "mtta" if query_num == 3 else "mttr"
    path = os.path.join(output_dir, f'{query_num}_{suffix}.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Chart {query_num} saved: {path}")


# ---------------------------------------------------------------------------
# Q5: Assignee horizontal bar
# ---------------------------------------------------------------------------

def chart_q5_assignee(data, output_dir, lookback_label):
    """Chart 5: Incidents by Assignee horizontal bar chart."""
    if not data:
        print("  Chart 5: No assignee data — skipped")
        return

    assignees = [row["Assignee"] for row in data]
    counts = [int(row["IncidentCount"]) for row in data]
    total = sum(counts)
    colors = ['#bdc3c7' if a == 'Unassigned' else '#3498db'
              for a in assignees]

    assignees_r = assignees[::-1]
    counts_r = counts[::-1]
    colors_r = colors[::-1]

    fig, ax = plt.subplots(figsize=(10, max(4, len(assignees) * 0.6 + 1)))
    bars = ax.barh(assignees_r, counts_r, color=colors_r,
                   edgecolor='white', height=0.5, zorder=3)

    for bar, count in zip(bars, counts_r):
        pct = count / total * 100
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                f'{count}  ({pct:.1f}%)', va='center', ha='left',
                fontsize=11, fontweight='bold')

    ax.set_xlabel('Number of Incidents', fontsize=12, fontweight='bold')
    ax.set_title(f'Incidents by Assignee — Last {lookback_label}',
                 fontsize=14, fontweight='bold', pad=15)
    ax.set_xlim(0, max(counts) * 1.25)
    ax.grid(axis='x', alpha=0.3, linestyle='--', zorder=0)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    path = os.path.join(output_dir, '5_incidents_by_assignee.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Chart 5 saved: {path}")


# ---------------------------------------------------------------------------
# Q6 / Q7: Top-5 horizontal bar (users / devices)
# ---------------------------------------------------------------------------

def chart_horizontal_bar(data, query_num, name_key, title,
                         output_dir, lookback_label):
    """Charts 6 & 7: Top 5 horizontal bar chart (users or devices)."""
    if not data:
        entity = "user" if query_num == 6 else "device"
        print(f"  Chart {query_num}: No affected {entity} data — skipped")
        return

    names = [row[name_key] for row in data]
    counts = [int(row["IncidentCount"]) for row in data]
    total = sum(counts)
    colors = ['#e74c3c', '#9b59b6', '#e67e22', '#2ecc71', '#3498db']

    names_r = names[::-1]
    counts_r = counts[::-1]
    colors_r = colors[:len(names)][::-1]

    fig, ax = plt.subplots(figsize=(12, 5.5))
    bars = ax.barh(names_r, counts_r, color=colors_r,
                   edgecolor='white', height=0.55, zorder=3)

    for bar, count in zip(bars, counts_r):
        pct = count / total * 100
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                f'{count}  ({pct:.1f}%)', va='center', ha='left',
                fontsize=10, fontweight='bold')

    ax.set_xlabel('Number of Incidents', fontsize=12, fontweight='bold')
    ax.set_title(f'{title} — Last {lookback_label}',
                 fontsize=14, fontweight='bold', pad=15)
    ax.set_xlim(0, max(counts) * 1.3)
    ax.grid(axis='x', alpha=0.3, linestyle='--', zorder=0)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    suffix = "top5_affected_users" if query_num == 6 else "top5_affected_devices"
    path = os.path.join(output_dir, f'{query_num}_{suffix}.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Chart {query_num} saved: {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input.json> <output_dir> <lookback_label>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2]
    lookback_label = sys.argv[3]

    with open(input_file, 'r') as f:
        results = json.load(f)

    os.makedirs(output_dir, exist_ok=True)

    print(f"Generating charts for: Last {lookback_label}")
    print(f"Output directory: {output_dir}")

    # Q1: Heatmap table image + 3D Pie chart
    generate_q1_table_image(results.get("q1", []), output_dir, lookback_label)
    chart_q1_pie(results.get("q1", []), output_dir, lookback_label)

    # Chart 2: MITRE ATT&CK Heatmap
    chart_q2_heatmap(results.get("q2", []), output_dir, lookback_label)

    # Chart 3: MTTA (Grouped Bar + SLA)
    chart_mtta_mttr(results.get("q3", []), 3, "MTTA",
                    "MTTA — Mean Time To Acknowledge",
                    '#3498db', 4.0, output_dir, lookback_label)

    # Chart 4: MTTR (Grouped Bar + SLA)
    chart_mtta_mttr(results.get("q4", []), 4, "MTTR",
                    "MTTR — Mean Time To Resolve",
                    '#9b59b6', 12.0, output_dir, lookback_label)

    # Chart 5: Incidents by Assignee (Horizontal Bar)
    chart_q5_assignee(results.get("q5", []), output_dir, lookback_label)

    # Chart 6: Top 5 Affected Users (Horizontal Bar)
    chart_horizontal_bar(results.get("q6", []), 6, "UserName",
                         "Top 5 Affected Users", output_dir, lookback_label)

    # Chart 7: Top 5 Affected Devices (Horizontal Bar)
    chart_horizontal_bar(results.get("q7", []), 7, "DeviceName",
                         "Top 5 Affected Devices", output_dir, lookback_label)

    print("\nAll charts and tables generated successfully!")


if __name__ == "__main__":
    main()
