#!/usr/bin/env python3
import os
import json
import csv
import sys

def collect_json_files(root_path):
    json_files = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        if os.path.basename(dirpath) == "virus_total":
            json_files += [os.path.join(dirpath, f) for f in filenames if f.endswith(".json")]
    return json_files

def process_last_analysis_stats(folder_path):
    stats_keys = ["malicious", "suspicious", "undetected", "harmless", "timeout",
                  "confirmed-timeout", "failure", "type-unsupported"]
    total_stats = dict.fromkeys(stats_keys, 0)
    missing_stats_count = 0
    total_files = 0
    engines_count = []

    json_files = collect_json_files(folder_path)

    for file in json_files:
        try:
            with open(file, "r") as f:
                data = json.load(f)

            total_files += 1
            stats = None
            if "data" in data and isinstance(data["data"], dict):
                attributes = data["data"].get("attributes", {})
                stats = attributes.get("last_analysis_stats") or attributes.get("stats")
            elif "attributes" in data:
                stats = data["attributes"].get("last_analysis_stats") or data["attributes"].get("stats")

            if stats:
                for key in stats_keys:
                    total_stats[key] += stats.get(key, 0)
                engines_count.append(sum([stats.get(k, 0) for k in stats_keys]))
            else:
                missing_stats_count += 1
        except Exception as e:
            print(f"Fehler bei Datei {file}: {e}")

    output_file = os.path.join(folder_path, "last_analysis_stats.csv")
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "count"])
        for key in stats_keys:
            writer.writerow([key, total_stats[key]])

    print(f"Ausgewertete Dateien: {total_files}")
    print(f"Dateien ohne 'last_analysis_stats' oder 'stats': {missing_stats_count}")
    if engines_count:
        avg_engines = sum(engines_count) / len(engines_count)
        print(f"Durchschnittlich bewertende Engines pro Datei: {avg_engines:.2f}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vt_json_to_csv_last_analysis_stats.py <ordnerpfad>")
    else:
        process_last_analysis_stats(sys.argv[1])

