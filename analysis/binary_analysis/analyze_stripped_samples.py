#!/usr/bin/env python3
import os
import subprocess
import sys
import hashlib
import csv
from collections import defaultdict

def is_binary(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT)
        output = output.decode('utf-8', errors='ignore').lower()
        return ('elf' in output) or ('pe32' in output)
    except subprocess.CalledProcessError:
        return False

def check_stripped(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT)
        output = output.decode('utf-8', errors='ignore').lower()
        is_stripped = 'not stripped' not in output and 'stripped' in output
        return output, is_stripped
    except subprocess.CalledProcessError:
        return '', False

def detect_type(file_output):
    if 'elf' in file_output:
        return 'ELF'
    elif 'pe32' in file_output:
        if 'dll' in file_output:
            return 'DLL'
        elif 'sys' in file_output:
            return 'SYS'
        else:
            return 'PE'
    else:
        return 'OTHER'

def get_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def read_labels_txt(labels_path):
    mapping = {}
    try:
        with open(labels_path, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    h, fam = parts
                    mapping[h] = fam.split(':')[-1] if 'SINGLETON' not in fam else fam
    except:
        pass
    return mapping

def main(scan_root, labels_txt):
    results = []
    unique = {}
    family_map = read_labels_txt(labels_txt)
    total_files = 0

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue
        for name in files:
            filepath = os.path.join(root, name)
            if not os.path.isfile(filepath) or not is_binary(filepath):
                continue

            total_files += 1
            file_output, is_stripped = check_stripped(filepath)
            bin_type = detect_type(file_output)
            sha256 = get_hash(filepath, 'sha256')
            md5 = get_hash(filepath, 'md5')
            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            row = {
                'File': filepath,
                'Type': bin_type,
                'Stripped': 'Yes' if is_stripped else 'No',
                'SHA256': sha256,
                'MD5': md5,
                'Malware_Family': family
            }

            results.append(row)
            if sha256 not in unique:
                unique[sha256] = row

    # CSV: all
    out_all = os.path.join(scan_root, 'analyze_stripped_samples.csv')
    with open(out_all, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # CSV: dedup
    out_dedup = os.path.join(scan_root, 'analyze_stripped_samples_dedup.csv')
    with open(out_dedup, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(unique.values())

    # CSV: summary
    summary = defaultdict(lambda: {'Stripped': 0, 'Not Stripped': 0})
    for row in unique.values():
        status = 'Stripped' if row['Stripped'] == 'Yes' else 'Not Stripped'
        summary[row['Type']][status] += 1

    out_summary = os.path.join(scan_root, 'analyze_stripped_samples_summary.csv')
    with open(out_summary, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Binary Type', 'Stripped', 'Not Stripped'])
        for btype, counts in summary.items():
            writer.writerow([btype, counts['Stripped'], counts['Not Stripped']])

    print("\nAnalyse abgeschlossen.")
    print(f"TOTAL scanned binaries: {total_files}")
    print(f"CSV gespeichert unter:\n - {out_all}\n - {out_dedup}\n - {out_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_stripped_samples.py <Ordner> <labels.txt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

