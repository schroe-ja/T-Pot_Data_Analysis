#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import Counter
import re

def extract_http_hostnames(base_dir):
    hostname_counter = Counter()
    total_files = 0
    total_lines = 0
    invalid_files = 0

    # Nur relevante Dateien wie eve.json, eve.json.1, eve.json.30 etc.
    relevant_pattern = re.compile(r"^eve\.json(\.\d+)?$")

    for root, _, files in os.walk(base_dir):
        for fname in files:
            if not relevant_pattern.match(fname):
                continue

            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    total_files += 1
                    for line in f:
                        total_lines += 1
                        try:
                            entry = json.loads(line.strip())
                            hostname = entry.get("http", {}).get("hostname")
                            if hostname:
                                hostname_counter[hostname.strip()] += 1
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Fehler beim Lesen von {filepath}: {e}")
                invalid_files += 1

    output_file = os.path.join(base_dir, "suricata_http_hostnames.csv")
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["hostname", "count"])
        for hostname, count in hostname_counter.most_common():
            writer.writerow([hostname, count])

    print("Analyse abgeschlossen.")
    print(f"Verarbeitete Dateien: {total_files}")
    print(f"Gelesene Zeilen: {total_lines}")
    print(f"Ungültige Dateien: {invalid_files}")
    print(f"Ergebnisse gespeichert in: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_suricata_http_hostnames.py <Verzeichnis>")
        sys.exit(1)

    extract_http_hostnames(sys.argv[1])

