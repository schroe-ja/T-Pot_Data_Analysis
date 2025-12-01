#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import pathlib
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")                 # head‑less backend – produces SVG without a display
import matplotlib.pyplot as plt


def read_counts(csv_path: pathlib.Path) -> dict:
    """
    Return a dict {protocol: summed count} for the given CSV.
    The first line (header) is ignored.
    """
    totals = defaultdict(int)

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)

        # ---- skip the header -------------------------------------------------
        try:
            header = next(reader)          # raises StopIteration if file empty
        except StopIteration:
            return totals                  # empty file → nothing to do

        # optional sanity‑check (you can remove it if you wish)
        expected = ["username:password", "protocol", "count"]
        if [h.strip().lower() for h in header] != expected:
            # Header differs – we still continue, but warn the user.
            sys.stderr.write(
                f"⚠️  Unexpected header in {csv_path.name}: {header}\n"
                f"   Expected (case‑insensitive): {expected}\n"
            )

        # ---- process the data rows -------------------------------------------
        for row in reader:
            if len(row) != 3:
                continue                    # malformed line → ignore
            _, protocol, cnt = row
            try:
                cnt = int(cnt)
            except ValueError:
                continue                    # non‑numeric count → ignore
            protocol = protocol.strip().lower()
            totals[protocol] += cnt

    return totals


def make_grouped_bar_chart(total_counts: dict,
                           success_counts: dict,
                           out_svg: pathlib.Path):
    """
    Draw a grouped bar chart:
        X‑axis : protocols (SSH, TELNET)
        Y‑axis : number of attempts
        Two bars per protocol → total vs successful
    """
    protocols = ["ssh", "telnet"]

    # Ensure every protocol appears (missing → 0)
    total_vals   = [total_counts.get(p, 0)   for p in protocols]
    success_vals = [success_counts.get(p, 0) for p in protocols]

    grand_total = sum(total_vals) + sum(success_vals)
    if grand_total == 0:
        sys.stderr.write("❌ No data to plot.\n")
        sys.exit(1)

    # ----------------------------------------------------------------------
    # Plotting
    # ----------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(6, 4))

    bar_width = 0.35
    idx = range(len(protocols))

    bars_total = ax.bar([i - bar_width/2 for i in idx],
                       total_vals,
                       width=bar_width,
                       label="Total attempts",
                       color="#1f77b4")
    bars_success = ax.bar([i + bar_width/2 for i in idx],
                         success_vals,
                         width=bar_width,
                         label="Successful attempts",
                         color="#ff7f0e")

    # X‑tick labels – protocol name + % of *all* attempts (rounded)
    xtick_labels = [
        f"{p.upper()}\n{(t+s)/grand_total*100:.1f}%"
        for p, t, s in zip(protocols, total_vals, success_vals)
    ]
    ax.set_xticks(idx)
    ax.set_xticklabels(xtick_labels)

    ax.set_ylabel("Number of attempts")
    ax.legend()

    ax.spines[['right', 'top']].set_visible(False)

    # Annotate each bar with its raw count (nice for papers)
    def _annotate(bars, values):
        for bar, val in zip(bars, values):
            h = bar.get_height()
            ax.annotate(
                f"{val:,}",
                xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=9,
                fontweight="bold",
            )
    _annotate(bars_total,   total_vals)
    _annotate(bars_success, success_vals)

    ax.grid(axis="y", linestyle="", alpha=0.6)
    plt.tight_layout()
    fig.savefig(out_svg, format="svg")
    plt.close(fig)


def main():
    # --------------------------------------------------------------
    # Adjust these filenames if your CSVs live elsewhere
    total_csv_path   = pathlib.Path("cowrie_login_attempts.csv")
    success_csv_path = pathlib.Path("cowrie_successful_logins.csv")
    out_svg_path     = pathlib.Path("cowrie_comparison.svg")
    # --------------------------------------------------------------

    if not total_csv_path.is_file():
        sys.stderr.write(f"❌ Missing file: {total_csv_path}\n")
        sys.exit(1)
    if not success_csv_path.is_file():
        sys.stderr.write(f"❌ Missing file: {success_csv_path}\n")
        sys.exit(1)

    total_counts   = read_counts(total_csv_path)
    success_counts = read_counts(success_csv_path)

    # Quick console summary (optional)
    print("=== Aggregated counts ===")
    for proto in ("ssh", "telnet"):
        tot = total_counts.get(proto, 0)
        suc = success_counts.get(proto, 0)
        print(f"{proto.upper():6} – total: {tot:,}, successful: {suc:,}")

    make_grouped_bar_chart(total_counts, success_counts, out_svg_path)


if __name__ == "__main__":
    main()
