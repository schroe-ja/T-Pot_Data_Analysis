#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import Counter, defaultdict

def collect_json_files(root_path):
    json_files = []
    for dirpath, _, filenames in os.walk(root_path):
        if os.path.basename(dirpath) == "virus_total":
            json_files += [os.path.join(dirpath, f) for f in filenames if f.endswith(".json")]
    return json_files

def process_sandbox_verdicts(folder_path):
    category_counter = Counter()
    sandbox_name_counter = Counter()
    classification_counter = Counter()
    malware_name_counter = Counter()
    total_files = 0
    missing_keys = 0

    json_files = collect_json_files(folder_path)

    for file in json_files:
        try:
            with open(file, "r") as f:
                data = json.load(f)
            total_files += 1

            verdicts = None
            if "data" in data and isinstance(data["data"], dict):
                verdicts = data["data"].get("attributes", {}).get("sandbox_verdicts", {})
            elif "attributes" in data:
                verdicts = data["attributes"].get("sandbox_verdicts", {})

            if not verdicts:
                missing_keys += 1
                continue

            for sandbox, result in verdicts.items():
                sandbox_name_counter[sandbox] += 1
                category_counter[result.get("category", "unknown")] += 1
                for c in result.get("malware_classification", []):
                    classification_counter[c] += 1
                for m in result.get("malware_names", []):
                    malware_name_counter[m] += 1

        except Exception as e:
            print(f"Fehler bei Datei {file}: {e}")

    # Save CSV files
    def save_csv(counter, filename, header):
        path = os.path.join(folder_path, filename)
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for key, count in counter.items():
                writer.writerow([key, count])

    save_csv(category_counter, "sandbox_category.csv", ["category", "count"])
    save_csv(sandbox_name_counter, "sandbox_name.csv", ["sandbox_name", "count"])
    save_csv(classification_counter, "sandbox_classification.csv", ["classification", "count"])
    save_csv(malware_name_counter, "sandbox_malware_name.csv", ["malware_name", "count"])

    print(f"Ausgewertete Dateien: {total_files}")
    print(f"Dateien ohne 'sandbox_verdicts': {missing_keys}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vt_json_to_csv_sandbox_verdicts.py <ordnerpfad>")
    else:
        process_sandbox_verdicts(sys.argv[1])

