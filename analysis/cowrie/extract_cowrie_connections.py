#!/usr/bin/env python3
import os
import sys
import json
import csv
from collections import Counter, defaultdict

def extract_cowrie_connections(base_dir):
    summary_counter = Counter()
    connection_details = []

    total_files = 0
    total_lines = 0
    skipped_files = 0
    supported_protocols = {"ssh", "telnet"}

    for root, _, files in os.walk(base_dir):
        for fname in files:
            if not fname.startswith("cowrie.json") or fname.endswith(".gz"):
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    total_files += 1
                    for line in f:
                        total_lines += 1
                        try:
                            log = json.loads(line.strip())
                            if log.get("eventid") == "cowrie.session.connect":
                                proto = log.get("protocol", "").lower()
                                if proto not in supported_protocols:
                                    continue
                                ip = log.get("src_ip", "")
                                port = log.get("src_port", "")
                                timestamp = log.get("timestamp", "")
                                session = log.get("session", "")
                                summary_counter[(ip, port, proto)] += 1
                                connection_details.append({
                                    "timestamp": timestamp,
                                    "src_ip": ip,
                                    "src_port": port,
                                    "protocol": proto,
                                    "session": session
                                })
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Fehler beim Lesen von {filepath}: {e}")
                skipped_files += 1

    # CSV 1: aggregiert
    summary_csv = os.path.join(base_dir, "cowrie_connection_summary.csv")
    with open(summary_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "src_port", "protocol", "session_count"])
        for (ip, port, proto), count in summary_counter.most_common():
            writer.writerow([ip, port, proto, count])

    # CSV 2: Details
    detail_csv = os.path.join(base_dir, "cowrie_connection_details.csv")
    with open(detail_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "src_ip", "src_port", "protocol", "session"])
        writer.writeheader()
        for entry in connection_details:
            writer.writerow(entry)

    print("Analyse abgeschlossen.")
    print(f"Verarbeitete Dateien: {total_files}")
    print(f"Übersprungene Dateien (Fehler): {skipped_files}")
    print(f"Insgesamt gelesene Zeilen: {total_lines}")
    print(f"Ergebnisse gespeichert in:\n  - {summary_csv}\n  - {detail_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_cowrie_connections.py <Verzeichnis>")
        sys.exit(1)
    extract_cowrie_connections(sys.argv[1])

