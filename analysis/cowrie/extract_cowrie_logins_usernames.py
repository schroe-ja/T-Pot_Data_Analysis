#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import Counter

def extract_logins_from_cowrie(base_dir):
    success_counter = Counter()
    failed_counter = Counter()
    total_files = 0
    total_lines = 0
    skipped_files = 0

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
                            if log.get("eventid") == "cowrie.login.success":
                                user = log.get("username", "").strip()
                                if user:
                                    success_counter[user] += 1
                            elif log.get("eventid") == "cowrie.login.failed":
                                user = log.get("username", "").strip()
                                if user:
                                    failed_counter[user] += 1
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Fehler beim Lesen von {filepath}: {e}")
                skipped_files += 1

    # CSV: Erfolgreiche Logins
    success_csv = os.path.join(base_dir, "cowrie_login_success_usernames.csv")
    with open(success_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "count"])
        for user, count in success_counter.most_common():
            writer.writerow([user, count])

    # CSV: Fehlgeschlagene Logins
    failed_csv = os.path.join(base_dir, "cowrie_login_failed_usernames.csv")
    with open(failed_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "count"])
        for user, count in failed_counter.most_common():
            writer.writerow([user, count])

    print("Analyse abgeschlossen.")
    print(f"Dateien verarbeitet: {total_files}")
    print(f"Übersprungene Dateien (Fehler): {skipped_files}")
    print(f"Insgesamt gelesene Zeilen: {total_lines}")
    print(f"Ergebnisse gespeichert in:\n  - {success_csv}\n  - {failed_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_cowrie_logins.py <Verzeichnis>")
        sys.exit(1)

    extract_logins_from_cowrie(sys.argv[1])

