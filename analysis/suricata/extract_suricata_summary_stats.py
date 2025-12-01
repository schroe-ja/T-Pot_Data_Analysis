#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import Counter

def extract_suricata_summary_stats(base_dir):
    signature_counter = Counter()
    category_counter = Counter()
    total_json_files = 0
    skipped_files = 0

    for root, _, files in os.walk(base_dir):
        for filename in files:
            if filename.endswith(".gz"):
                continue  # gzip-Dateien überspringen
            if filename.endswith(".json") or ".json." in filename:
                filepath = os.path.join(root, filename)
                total_json_files += 1

                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                if "alert" in data:
                                    alert = data["alert"]
                                    signature = alert.get("signature", "").strip()
                                    category = alert.get("category", "").strip()
                                    if signature:
                                        signature_counter[signature] += 1
                                    if category:
                                        category_counter[category] += 1
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    print(f"Fehler beim Lesen von {filepath}: {e}")
                    skipped_files += 1

    # Speichern: Signaturen
    sig_file = os.path.join(base_dir, "suricata_signature_summary.csv")
    with open(sig_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["signature", "count"])
        for sig, count in signature_counter.items():
            writer.writerow([sig, count])

    # Speichern: Kategorien
    cat_file = os.path.join(base_dir, "suricata_category_summary.csv")
    with open(cat_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["category", "count"])
        for cat, count in category_counter.items():
            writer.writerow([cat, count])

    print("Zusammenfassung abgeschlossen.")
    print(f"Verarbeitete JSON-Dateien: {total_json_files}")
    print(f"Übersprungene Dateien wegen Fehlern: {skipped_files}")
    print(f"Ergebnisse gespeichert in: {sig_file} und {cat_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_suricata_summary_stats.py <Pfad_zum_Verzeichnis>")
        sys.exit(1)

    extract_suricata_summary_stats(sys.argv[1])

