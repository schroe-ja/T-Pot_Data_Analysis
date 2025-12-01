#!/usr/bin/env python3
import sqlite3
import csv
import sys
import os
import fnmatch

def extract_entries(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        query = """
        SELECT 
            d.download_md5_hash,
            d.download_url,
            c.remote_host
        FROM 
            downloads d
        LEFT JOIN 
            connections c ON d.connection = c.connection
        """

        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        return rows

    except Exception as e:
        print(f"[!] Fehler bei {db_path}: {e}")
        return []

def is_valid_sqlite_file(fname):
    base = os.path.basename(fname)
    return (
        (fnmatch.fnmatch(base, "dionaea.sqlite") or fnmatch.fnmatch(base, "dionaea.sqlite.*"))
        and not base.endswith(".gz")
        and ".backup" not in base
    )

def process_directory(base_dir):
    all_entries = []
    db_count = 0

    for root, _, files in os.walk(base_dir):
        for fname in files:
            if is_valid_sqlite_file(fname):
                db_path = os.path.join(root, fname)
                entries = extract_entries(db_path)
                if entries:
                    db_count += 1
                    all_entries.extend(entries)
                    print(f"[+] {len(entries)} Einträge extrahiert aus: {db_path}")

    output_csv = os.path.join(base_dir, "dionaea_all_downloads_summary.csv")
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["download_md5_hash", "download_url", "remote_host"])
        writer.writerows(all_entries)

    print(f"\n[✓] Gesamt: {len(all_entries)} Einträge aus {db_count} Datenbanken")
    print(f"[→] Zusammengefasst in: {output_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_dionaea_downloads_summary.py <Verzeichnis>")
        sys.exit(1)

    base_dir = sys.argv[1]
    process_directory(base_dir)

