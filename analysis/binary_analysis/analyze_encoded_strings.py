#!/usr/bin/env python3
import os
import sys
import subprocess
import csv
import hashlib

def is_elf(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT)
        return b'ELF' in output
    except subprocess.CalledProcessError:
        return False

def extract_strings(filepath):
    try:
        output = subprocess.check_output(['strings', filepath], stderr=subprocess.STDOUT)
        lines = output.decode(errors='ignore').splitlines()
        return lines
    except subprocess.CalledProcessError:
        return []

def analyze_strings(strings_list):
    ascii_count = sum(1 for s in strings_list if all(32 <= ord(c) <= 126 for c in s))
    non_ascii_count = len(strings_list) - ascii_count
    total = len(strings_list)
    percent_readable = (ascii_count / total * 100) if total else 0
    return ascii_count, non_ascii_count, percent_readable

def get_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def read_labels_txt(labels_txt):
    family_map = {}
    with open(labels_txt, 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                h, fam = parts
                family_map[h] = fam.split(':')[-1] if 'SINGLETON' not in fam else fam
    return family_map

def main(scan_root, labels_txt):
    family_map = read_labels_txt(labels_txt)
    csv_rows = []
    dedup_rows = {}
    summary = {'Encoded': 0, 'Plaintext': 0}
    total_files = 0

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue
        for name in files:
            filepath = os.path.join(root, name)
            if not os.path.isfile(filepath) or not is_elf(filepath):
                continue

            total_files += 1
            strings_list = extract_strings(filepath)
            ascii_count, non_ascii_count, percent_readable = analyze_strings(strings_list)
            status = "Encoded" if percent_readable < 50 else "Plaintext"
            summary[status] += 1

            sha256 = get_hash(filepath, 'sha256')
            md5 = get_hash(filepath, 'md5')
            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            row = {
                'File': filepath,
                'SHA256': sha256,
                'MD5': md5,
                'Malware_Family': family,
                'Total Strings': len(strings_list),
                'ASCII Strings': ascii_count,
                'Non-ASCII Strings': non_ascii_count,
                '% Readable': f"{percent_readable:.2f}",
                'Status': status
            }

            csv_rows.append(row)
            if sha256 not in dedup_rows:
                dedup_rows[sha256] = row

    # CSV 1: Alle Dateien (auch Duplikate)
    out_all = os.path.join(scan_root, "encoded_strings_analysis_all.csv")
    with open(out_all, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
        writer.writeheader()
        writer.writerows(csv_rows)

    # CSV 2: Dedup
    out_dedup = os.path.join(scan_root, "encoded_strings_analysis_dedup.csv")
    with open(out_dedup, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
        writer.writeheader()
        writer.writerows(dedup_rows.values())

    # CSV 3: Zusammenfassung
    out_summary = os.path.join(scan_root, "encoded_strings_analysis_summary.csv")
    with open(out_summary, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(['Status', 'Count'])
        for k in ['Encoded', 'Plaintext']:
            writer.writerow([k, summary[k]])
        writer.writerow(['TOTAL ELF binaries scanned', total_files])

    # Konsole
    print(f"\nAnalyse abgeschlossen: {total_files} ELF-Binaries geprüft.")
    print(f"Verdächtig verschleiert: {summary['Encoded']}")
    print(f"Unverschleiert: {summary['Plaintext']}")
    print(f"CSV gespeichert unter:\n- {out_all}\n- {out_dedup}\n- {out_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_encoded_strings.py <Ordner> <labels.txt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

