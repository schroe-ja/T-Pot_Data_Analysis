#!/usr/bin/env python3
import os
import subprocess
import sys
import hashlib
import platform
import csv
from collections import defaultdict

def is_binary(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT)
        output = output.decode('utf-8', errors='ignore').lower()
        return ('elf' in output) or ('pe32' in output)
    except subprocess.CalledProcessError:
        return False

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

def check_linkage(filepath):
    try:
        sys_type = platform.system()
        if sys_type == 'Darwin':  # macOS
            output = subprocess.check_output(['otool', '-L', filepath], stderr=subprocess.STDOUT)
            output = output.decode('utf-8', errors='ignore').lower()
            lines = output.strip().split('\n')
            is_dynamic = len(lines) > 1
            return output, is_dynamic
        else:  # Linux
            output = subprocess.check_output(['ldd', filepath], stderr=subprocess.STDOUT)
            output = output.decode('utf-8', errors='ignore').lower()
            is_dynamic = 'not a dynamic executable' not in output
            return output, is_dynamic
    except subprocess.CalledProcessError:
        return '', False

def get_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
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
    total_files = 0
    summary = defaultdict(lambda: {'total': 0, 'dynamic': 0, 'static': 0})
    results = []
    dedup = {}
    
    for root, _, files in os.walk(scan_root):
        if not any(part.startswith('binaries') or part.startswith('downloads') for part in root.split(os.sep)):
            continue
        for name in files:
            filepath = os.path.join(root, name)
            if not os.path.isfile(filepath) or not is_binary(filepath):
                continue

            total_files += 1
            file_output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore').lower()
            bin_type = detect_type(file_output)
            _, is_dynamic = check_linkage(filepath)

            sha256 = get_hash(filepath, 'sha256')
            md5 = get_hash(filepath, 'md5')
            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            linkage = 'Dynamic' if is_dynamic else 'Static'

            summary[bin_type]['total'] += 1
            summary[bin_type]['dynamic' if is_dynamic else 'static'] += 1

            row = {
                'File': filepath,
                'Type': bin_type,
                'Linking': linkage,
                'SHA256': sha256,
                'MD5': md5,
                'Malware_Family': family
            }
            results.append(row)
            if sha256 not in dedup:
                dedup[sha256] = row

    # CSV 1: All
    out_all = os.path.join(scan_root, 'analyze_linkage.csv')
    with open(out_all, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # CSV 2: Dedup
    out_dedup = os.path.join(scan_root, 'analyze_linkage_dedup.csv')
    with open(out_dedup, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(dedup.values())

    # CSV 3: Summary
    out_summary = os.path.join(scan_root, 'analyze_linkage_summary.csv')
    with open(out_summary, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Binary Type', 'Total', 'Static', 'Dynamic'])
        for bin_type, counts in summary.items():
            writer.writerow([bin_type, counts['total'], counts['static'], counts['dynamic']])
        writer.writerow(['TOTAL scanned binaries', total_files, '', ''])

    # Console
    print("\nAnalyse-Ergebnis (Statisch vs. Dynamisch):\n")
    for bin_type, counts in summary.items():
        print(f"{bin_type} Files: {counts['total']}")
        print(f"   - Statisch verlinkt: {counts['static']}")
        print(f"   - Dynamisch verlinkt: {counts['dynamic']}\n")
    print(f"TOTAL scanned binaries: {total_files}")
    print(f"CSV gespeichert unter:\n- {out_all}\n- {out_dedup}\n- {out_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_linkage.py <Ordner> <labels.txt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

