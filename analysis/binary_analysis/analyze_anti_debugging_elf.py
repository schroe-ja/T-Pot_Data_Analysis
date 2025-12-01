#!/usr/bin/env python3

import os
import sys
import subprocess
import csv
import hashlib
from collections import defaultdict

# Anti-Debugging-Indikatoren
INDICATORS = {
    'Process attaching to itself': ['ptrace', 'PTRACE_TRACEME'],
    'Reading /proc/self/status': ['/proc/self/status'],
}

def is_elf(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT).decode(errors='ignore').lower()
        return 'elf' in output
    except subprocess.CalledProcessError:
        return False

def get_file_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def check_indicators(strings_output):
    results = []
    for category, patterns in INDICATORS.items():
        if any(pat in strings_output for pat in patterns):
            results.append(category)
    return results if results else ['None']

def read_labels_txt(labels_txt):
    family_map = {}
    with open(labels_txt, 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                h, fam = parts
                family = fam.split(':')[-1] if 'SINGLETON' not in fam else fam
                family_map[h] = family
    return family_map

def main(scan_root, labels_txt):
    family_map = read_labels_txt(labels_txt)
    seen_hashes = set()
    total_elf = 0

    all_results = []
    dedup_results = {}
    summary_counts = defaultdict(int)

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue

        for filename in files:
            filepath = os.path.join(root, filename)
            if not os.path.isfile(filepath) or not is_elf(filepath):
                continue

            sha256 = get_file_hash(filepath, 'sha256')
            md5 = get_file_hash(filepath, 'md5')

            try:
                strings_out = subprocess.check_output(['strings', filepath], stderr=subprocess.STDOUT).decode(errors='ignore')
            except subprocess.CalledProcessError:
                continue

            found = check_indicators(strings_out)
            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            # Alle Dateien (auch doppelte Hashes) → all_results
            all_results.append({
                'Filepath': filepath,
                'SHA256': sha256,
                'MD5': md5,
                'Category': ', '.join(found),
                'Family': family
            })

            # Deduplikation nur für dedup + summary
            if sha256 in seen_hashes:
                continue
            seen_hashes.add(sha256)
            total_elf += 1

            dedup_results[sha256] = {
                'Filepath': filepath,
                'SHA256': sha256,
                'MD5': md5,
                'Category': ', '.join(found),
                'Family': family
            }

            for cat in found:
                summary_counts[cat] += 1

    # Speichern: ALL
    out_all = os.path.join(scan_root, 'anti_debugging_elf_all.csv')
    with open(out_all, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Filepath', 'SHA256', 'MD5', 'Category', 'Family'])
        writer.writeheader()
        writer.writerows(all_results)

    # Speichern: DEDUP
    out_dedup = os.path.join(scan_root, 'anti_debugging_elf_dedup.csv')
    with open(out_dedup, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Filepath', 'SHA256', 'MD5', 'Category', 'Family'])
        writer.writeheader()
        writer.writerows(dedup_results.values())

    # Speichern: SUMMARY
    out_summary = os.path.join(scan_root, 'anti_debugging_elf_summary.csv')
    with open(out_summary, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Count'])
        for category in INDICATORS:
            writer.writerow([category, summary_counts.get(category, 0)])
        writer.writerow(['None', summary_counts.get('None', 0)])
        writer.writerow(['TOTAL unique ELF binaries scanned', total_elf])

    print("\nAnalyse abgeschlossen.")
    print(f"All gespeichert: {out_all}")
    print(f"Dedup gespeichert: {out_dedup}")
    print(f"Summary gespeichert: {out_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_anti_debugging_elf.py <SCAN_ROOT> <LABELS_TXT>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

