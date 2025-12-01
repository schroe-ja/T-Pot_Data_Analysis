#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import Counter

def is_valid_json_file(fname):
    return (
        fname.startswith("attackers")
        #and not fname.endswith(".gz")
        #and not fname.endswith(".backup")
        #and not fname.endswith(".log")
    )

def extract_honeytrap_ips(base_dir):
    ip_counter = Counter()
    total_files = 0
    skipped_files = 0
    total_entries = 0

    for root, _, files in os.walk(base_dir):
        for fname in files:
            if not is_valid_json_file(fname):
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    total_files += 1
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            if '"remote_ip":' in line:
                                ip = line.split('"remote_ip":')[1].split('"')[1]
                                ip_counter[ip] += 1
                                total_entries += 1
                        except Exception:
                            continue
            except Exception as e:
                print(f"Fehler beim Lesen von {filepath}: {e}")
                skipped_files += 1

    # Schreibe CSV
    output_csv = os.path.join(base_dir, "honeytrap_attacker_ips.csv")
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "count"])
        for ip, count in ip_counter.most_common():
            writer.writerow([ip, count])

    print("Analyse abgeschlossen.")
    print(f"Verarbeitete Dateien: {total_files}")
    print(f"Übersprungene Dateien (Fehler): {skipped_files}")
    print(f"Gefundene IP-Adressen: {total_entries}")
    print(f"Ergebnisse gespeichert in:\n  - {output_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_honeytrap_top_ips.py <Verzeichnis>")
        sys.exit(1)
    extract_honeytrap_ips(sys.argv[1])

