#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import Counter

def collect_json_files(root_path):
    json_files = []
    for dirpath, _, filenames in os.walk(root_path):
        if os.path.basename(dirpath) == "virus_total":
            json_files += [os.path.join(dirpath, f) for f in filenames if f.endswith(".json")]
    return json_files

def process_popular_threat_name(folder_path):
    counter = Counter()
    missing_count = 0
    total_files = 0

    json_files = collect_json_files(folder_path)

    for file in json_files:
        try:
            with open(file, "r") as f:
                data = json.load(f)
            total_files += 1

            threat_info = None
            if "data" in data and isinstance(data["data"], dict):
                threat_info = data["data"].get("attributes", {}).get("popular_threat_classification", {})
            elif "attributes" in data:
                threat_info = data["attributes"].get("popular_threat_classification", {})

            names = threat_info.get("popular_threat_name")
            if names:
                for entry in names:
                    counter[entry["value"]] += entry["count"]
            else:
                missing_count += 1

        except Exception as e:
            print(f"Fehler bei Datei {file}: {e}")

    output_file = os.path.join(folder_path, "popular_threat_name.csv")
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["threat_name", "count"])
        for name, count in counter.items():
            writer.writerow([name, count])

    print(f"Ausgewertete Dateien: {total_files}")
    print(f"Dateien ohne 'popular_threat_name': {missing_count}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vt_json_to_csv_popular_threat_name.py <ordnerpfad>")
    else:
        process_popular_threat_name(sys.argv[1])

