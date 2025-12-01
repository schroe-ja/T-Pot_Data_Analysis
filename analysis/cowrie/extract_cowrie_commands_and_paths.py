#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import Counter
from urllib.parse import urlparse

def extract_cowrie_commands_and_paths(base_dir):
    command_counter = Counter()
    protected_url_counter = Counter()
    clean_ip_counter = Counter()
    path_counter = Counter()
    total_files = 0
    skipped_files = 0
    total_lines = 0

    url_prefixes = ("http://", "https://", "ftp://", "tftp://", "scp://")
    path_prefixes = ("/", "./", "../")

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
                            if log.get("eventid") == "cowrie.command.input":
                                cmd = log.get("input", "").strip()
                                if cmd:
                                    command_counter[cmd] += 1
                                    for part in cmd.split():
                                        if part.startswith(url_prefixes):
                                            protected_url = part.replace("http://", "http[:]//").replace("https://", "https[:]//")
                                            protected_url = protected_url.replace(":", "[:]").replace(".", "[.]")
                                            protected_url_counter[protected_url] += 1

                                            parsed = urlparse(part)
                                            ip = parsed.netloc.split(":")[0]
                                            clean_ip_counter[ip] += 1
                                        elif part.startswith(path_prefixes):
                                            path_counter[part] += 1
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Fehler beim Lesen von {filepath}: {e}")
                skipped_files += 1

    # cowrie_commands_summary.csv
    cmd_csv = os.path.join(base_dir, "cowrie_commands_summary.csv")
    with open(cmd_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["command", "count"])
        for cmd, count in command_counter.most_common():
            writer.writerow([cmd, count])

    # cowrie_extracted_urls.csv (geschützt)
    url_csv = os.path.join(base_dir, "cowrie_extracted_urls.csv")
    with open(url_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "count"])
        for url, count in protected_url_counter.most_common():
            writer.writerow([url, count])

    # cowrie_extracted_urls_clean.csv (IP-basiert)
    clean_csv = os.path.join(base_dir, "cowrie_extracted_urls_clean.csv")
    with open(clean_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "count"])
        for ip, count in clean_ip_counter.most_common():
            writer.writerow([ip, count])

    # cowrie_command_paths_summary.csv (Pfade)
    path_csv = os.path.join(base_dir, "cowrie_command_paths_summary.csv")
    with open(path_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "count"])
        for path, count in path_counter.most_common():
            writer.writerow([path, count])

    print(f"Analyse abgeschlossen.")
    print(f"Dateien verarbeitet: {total_files}")
    print(f"Übersprungene Dateien (Fehler): {skipped_files}")
    print(f"Insgesamt gelesene Zeilen: {total_lines}")
    print(f"Ergebnisse gespeichert in:")
    print(f"  - {cmd_csv}")
    print(f"  - {url_csv}")
    print(f"  - {clean_csv}")
    print(f"  - {path_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_cowrie_commands_and_paths.py <Verzeichnis>")
        sys.exit(1)
    extract_cowrie_commands_and_paths(sys.argv[1])

