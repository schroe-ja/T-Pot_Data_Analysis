#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import Counter

def collect_vt_json_files(root_path):
    json_files = []
    for dirpath, _, filenames in os.walk(root_path):
        if os.path.basename(dirpath) == "virus_total":
            json_files += [os.path.join(dirpath, f) for f in filenames if f.endswith(".json")]
    return json_files

def process_vt_av_detections(folder_path):
    av_counters = Counter()
    total_files = 0

    json_files = collect_vt_json_files(folder_path)

    for file in json_files:
        try:
            with open(file, "r") as f:
                data = json.load(f)
            total_files += 1

            analysis = None
            if "data" in data and isinstance(data["data"], dict):
                analysis = data["data"].get("attributes", {}).get("last_analysis_results", {})
            elif "attributes" in data:
                analysis = data["attributes"].get("last_analysis_results", {})

            if analysis:
                for vendor, result in analysis.items():
                    if result.get("result") is not None:
                        av_counters[vendor] += 1

        except Exception as e:
            print(f"Fehler bei Datei {file}: {e}")

    output_file = os.path.join(folder_path, "av_vendor_detections.csv")
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["AV Vendor", "Detected Samples"])
        for vendor, count in av_counters.most_common():
            writer.writerow([vendor, count])

    print(f"Ausgewertete VT-Dateien: {total_files}")
    print(f"Ergebnis gespeichert unter: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_vt_av_detections.py <ordnerpfad>")
    else:
        process_vt_av_detections(sys.argv[1])

