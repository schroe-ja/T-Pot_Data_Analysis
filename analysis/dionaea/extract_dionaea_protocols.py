#!/usr/bin/env python3
import os
import json
import csv
import sys

def extract_dionaea_protocols(input_folder):
    protocol_counts = {}

    for root, dirs, files in os.walk(input_folder):
        for file in files:
            if file.startswith("dionaea.json") and not file.endswith(".gz"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            conn = entry.get("connection", {})
                            protocol = conn.get("protocol", "").strip().lower()
                            if protocol:
                                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
                        except json.JSONDecodeError:
                            continue

    output_path = os.path.join(input_folder, "extracted_dionaea_protocols.csv")
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["protocol", "count"])
        for protocol, count in sorted(protocol_counts.items(), key=lambda x: x[0]):
            writer.writerow([protocol, count])

    print(f"Protokolle extrahiert: {len(protocol_counts)}")
    print(f"Ergebnis gespeichert unter: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_dionaea_protocols.py <input_folder>")
        sys.exit(1)

    input_folder = sys.argv[1]

    if not os.path.isdir(input_folder):
        print(f"Ordner existiert nicht: {input_folder}")
        sys.exit(1)

    extract_dionaea_protocols(input_folder)

