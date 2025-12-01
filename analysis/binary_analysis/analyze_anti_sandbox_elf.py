#!/usr/bin/env python3

import os
import sys
import subprocess
import csv
import hashlib
from collections import defaultdict

# Anti-Sandbox-Indikatoren
INDICATORS = {
    'Reading /proc/ directory': ['/proc/'],
    'Process enumeration': ['ps', 'pstree', 'pgrep'],
    'Checked start-up services': ['chkconfig', 'systemctl', 'init.d'],
    'Checked scheduled jobs': ['cron', 'crontab', '/etc/cron.', '/etc/anacrontab'],
    'Reading /sys/devices/system/': ['/sys/devices/system/'],
    'QEMU aliases': ['QEMU', 'qemu', 'kvm'],
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

def extract_strings(filepath):
    try:
        output = subprocess.check_output(['strings', filepath], stderr=subprocess.STDOUT)
        return output.decode(errors='ignore').lower()
    except:
        return ""

def check_indicators(strings_output):
    results = []
    for category, indicators in INDICATORS.items():
        for ind in indicators:
            if ind in strings_output:
                results.append(category)
                break
    if not results:
        results.append('None')
    return results

def main(scan_root, labels_txt):
    family_map = read_labels_txt(labels_txt)
    counts = defaultdict(int)
    total_elf = 0
    seen_hashes = set()
    all_results = []
    dedup_results = []

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue

        for name in files:
            filepath = os.path.join(root, name)
            if not os.path.isfile(filepath):
                continue
            if not is_elf(filepath):
                continue

            sha256 = get_file_hash(filepath, 'sha256')
            md5 = get_file_hash(filepath, 'md5')
            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'
            strings_output = extract_strings(filepath)
            found = check_indicators(strings_output)

            for category in found:
                counts[category] += 1

            all_results.append({
                'Filepath': filepath,
                'SHA256': sha256,
                'MD5': md5,
                'Categories': ', '.join(found),
                'Family': family
            })

            if sha256 not in seen_hashes:
                seen_hashes.add(sha256)
                total_elf += 1
                dedup_results.append({
                    'Filepath': filepath,
                    'SHA256': sha256,
                    'MD5': md5,
                    'Categories': ', '.join(found),
                    'Family': family
                })

    # ALL
    csv_all = os.path.join(scan_root, "anti_sandbox_elf_all.csv")
    with open(csv_all, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Filepath', 'SHA256', 'MD5', 'Categories', 'Family'])
        writer.writeheader()
        writer.writerows(all_results)

    # DEDUP
    csv_dedup = os.path.join(scan_root, "anti_sandbox_elf_dedup.csv")
    with open(csv_dedup, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Filepath', 'SHA256', 'MD5', 'Categories', 'Family'])
        writer.writeheader()
        writer.writerows(dedup_results)

    # SUMMARY
    csv_summary = os.path.join(scan_root, "anti_sandbox_elf_summary.csv")
    with open(csv_summary, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Count'])
        for category in INDICATORS.keys():
            writer.writerow([category, counts.get(category, 0)])
        writer.writerow(['None (no indicators)', counts.get('None', 0)])
        writer.writerow(['TOTAL unique ELF binaries scanned', total_elf])

    print("\nAnalyse abgeschlossen.")
    print(f"All gespeichert: {csv_all}")
    print(f"Dedup gespeichert: {csv_dedup}")
    print(f"Summary gespeichert: {csv_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_anti_sandbox_elf.py <Ordner> <LABELS_TXT>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

