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

def process_tags(folder_path):
    tag_counter = Counter()
    total_files = 0
    missing_tags = 0

    json_files = collect_json_files(folder_path)

    for file in json_files:
        try:
            with open(file, "r") as f:
                data = json.load(f)
            total_files += 1

            tags = None
            if "data" in data and isinstance(data["data"], dict):
                tags = data["data"].get("attributes", {}).get("tags", [])
            elif "attributes" in data:
                tags = data["attributes"].get("tags", [])

            if tags:
                for tag in tags:
                    tag_counter[tag] += 1
            else:
                missing_tags += 1

        except Exception as e:
            print(f"Fehler bei Datei {file}: {e}")

    output_file = os.path.join(folder_path, "tags.csv")
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["tag", "count"])
        for tag, count in tag_counter.items():
            writer.writerow([tag, count])

    print(f"Ausgewertete Dateien: {total_files}")
    print(f"Dateien ohne 'tags': {missing_tags}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vt_json_to_csv_tags.py <ordnerpfad>")
    else:
        process_tags(sys.argv[1])

