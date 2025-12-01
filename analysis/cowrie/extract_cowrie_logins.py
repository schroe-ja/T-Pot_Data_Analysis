#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import Counter

def extract_cowrie_logins(base_dir):
    attempt_counter = Counter()
    success_counter = Counter()
    session_protocol_map = {}
    total_files = 0
    skipped_files = 0
    total_lines = 0

    for root, _, files in os.walk(base_dir):
        for fname in files:
            #if not fname.startswith("cowrie.json") or fname.endswith(".gz"):
            #    continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    total_files += 1
                    for line in f:
                        total_lines += 1
                        try:
                            log = json.loads(line.strip())
                            eventid = log.get("eventid", "")
                            session = log.get("session", "")

                            if eventid == "cowrie.session.connect":
                                protocol = log.get("protocol", "").strip()
                                if session and protocol:
                                    session_protocol_map[session] = protocol

                            elif eventid in ("cowrie.login.failed", "cowrie.login.success"):
                                username = log.get("username", "").strip()
                                password = log.get("password", "").strip()
                                protocol = session_protocol_map.get(session, "unknown")
                                key = (f"{username}:{password}", protocol)

                                if eventid == "cowrie.login.failed":
                                    attempt_counter[key] += 1
                                elif eventid == "cowrie.login.success":
                                    success_counter[key] += 1
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Fehler beim Lesen von {filepath}: {e}")
                skipped_files += 1

    # Write login attempts
    attempts_csv = os.path.join(base_dir, "cowrie_login_attempts.csv")
    with open(attempts_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["username:password", "protocol", "count"])
        for (userpass, protocol), count in attempt_counter.most_common():
            writer.writerow([userpass, protocol, count])

    # Write successful logins
    success_csv = os.path.join(base_dir, "cowrie_successful_logins.csv")
    with open(success_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["username:password", "protocol", "count"])
        for (userpass, protocol), count in success_counter.most_common():
            writer.writerow([userpass, protocol, count])

    print(f"Analyse abgeschlossen.")
    print(f"Dateien verarbeitet: {total_files}")
    print(f"Übersprungene Dateien (Fehler): {skipped_files}")
    print(f"Insgesamt gelesene Zeilen: {total_lines}")
    print(f"Ergebnisse gespeichert in:\n  - {attempts_csv}\n  - {success_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_cowrie_logins.py <Verzeichnis>")
        sys.exit(1)
    extract_cowrie_logins(sys.argv[1])

