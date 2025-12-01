#!/usr/bin/env python3
import os
import sys
import csv
import json

def load_virustotal_hashes(base_dir):
    md5_to_sha256 = {}
    for root, _, files in os.walk(base_dir):
        if "results/virus_total" not in root.replace("\\", "/"):
            continue
        for fname in files:
            if not fname.endswith(".json"):
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    md5 = data.get("attributes", {}).get("md5", "").lower()
                    sha256 = data.get("attributes", {}).get("sha256", "")
                    if md5 and sha256:
                        md5_to_sha256[md5] = sha256
            except Exception as e:
                print(f"Fehler beim Lesen von {filepath}: {e}")
    print(f"VirusTotal-Hashes geladen: {len(md5_to_sha256)}")
    return md5_to_sha256

def enrich_csv_with_sha256(csv_path, hash_map):
    output_file = os.path.join(os.path.dirname(csv_path), "dionaea_all_downloads_summary_enriched.csv")
    total = 0
    matches = 0

    with open(csv_path, "r", encoding="utf-8") as infile, open(output_file, "w", newline="", encoding="utf-8") as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + ["sha256"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            total += 1
            md5 = row.get("download_md5_hash", "").lower()
            row["sha256"] = hash_map.get(md5, "")
            if row["sha256"]:
                matches += 1
            writer.writerow(row)

    print(f"CSV-Einträge verarbeitet: {total}")
    print(f"Übereinstimmungen gefunden: {matches}")
    print(f"Angereicherte Datei gespeichert unter: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python enrich_dionaea_downloads_with_sha256.py <pfad_zur_csv> <basisordner_mit_virus_total_jsons>")
        sys.exit(1)

    csv_input = sys.argv[1]
    vt_dir = sys.argv[2]

    hash_map = load_virustotal_hashes(vt_dir)
    enrich_csv_with_sha256(csv_input, hash_map)

