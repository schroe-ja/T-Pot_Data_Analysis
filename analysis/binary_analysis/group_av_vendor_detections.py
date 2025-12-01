#!/usr/bin/env python3
import csv
import sys
import os
from collections import Counter

def group_vendor_detections(input_csv):
    sample_counts = Counter()

    with open(input_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            samples = int(row["Detected Samples"])
            sample_counts[samples] += 1

    output_path = os.path.join(
        os.path.dirname(input_csv),
        "av_vendor_detections_grouped.csv"
    )

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Number of Vendors", "Number of Samples"])
        for samples, vendors in sorted(sample_counts.items()):
            writer.writerow([vendors, samples])

    print(f"Gruppierte Übersicht gespeichert unter: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python group_av_vendor_detections.py <av_vendor_detections.csv>")
        sys.exit(1)

    input_csv = sys.argv[1]
    if not os.path.isfile(input_csv):
        print(f"Datei existiert nicht: {input_csv}")
        sys.exit(1)

    group_vendor_detections(input_csv)

