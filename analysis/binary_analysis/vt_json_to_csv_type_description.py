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

def process_type_description(folder_path):
    type_counter = Counter()
    missing_count = 0
    total_files = 0

    json_files = collect_json_files(folder_path)

    for file in json_files:
        try:
            with open(file, "r") as f:
                data = json.load(f)
            total_files += 1

            desc = None
            if "data" in data and isinstance(data["data"], dict):
                desc = data["data"].get("attributes", {}).get("type_description")
            elif "attributes" in data:
                desc = data["attributes"].get("type_description")

            if desc:
                type_counter[desc] += 1
            else:
                missing_count += 1

        except Exception as e:
            print(f"Fehler bei Datei {file}: {e}")

    output_file = os.path.join(folder_path, "type_description.csv")
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["type_description", "count"])
        for desc, count in type_counter.items():
            writer.writerow([desc, count])

    print(f"Ausgewertete Dateien: {total_files}")
    print(f"Dateien ohne 'type_description': {missing_count}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vt_json_to_csv_type_description.py <ordnerpfad>")
    else:
        process_type_description(sys.argv[1])

