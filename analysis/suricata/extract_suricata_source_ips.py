#!/usr/bin/env python3
import os
import sys
import json
import csv
from collections import Counter

def extract_suricata_source_ips(base_dir):
    ip_counter = Counter()
    total_files = 0
    skipped_files = 0
    total_lines = 0

    for root, _, files in os.walk(base_dir):
        for fname in files:
            #if not fname.startswith("eve.json") or fname.endswith(".gz"):
            #    continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    total_files += 1
                    for line in f:
                        total_lines += 1
                        try:
                            data = json.loads(line.strip())
                            if "alert" in data and "src_ip" in data:
                                ip_counter[data["src_ip"]] += 1
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Fehler beim Lesen von {filepath}: {e}")
                skipped_files += 1

    # CSV-Ausgabe
    output_file = os.path.join(base_dir, "suricata_source_ips.csv")
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "count"])
        for ip, count in ip_counter.most_common():
            writer.writerow([ip, count])

    print("Analyse abgeschlossen.")
    print(f"Dateien verarbeitet: {total_files}")
    print(f"Übersprungene Dateien (Fehler): {skipped_files}")
    print(f"Insgesamt gelesene Zeilen: {total_lines}")
    print(f"Anzahl eindeutiger Angreifer-IPs: {len(ip_counter)}")
    print(f"Ergebnisse gespeichert in: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_suricata_source_ips.py <Verzeichnis>")
        sys.exit(1)
    extract_suricata_source_ips(sys.argv[1])

