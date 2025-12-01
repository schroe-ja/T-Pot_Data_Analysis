#!/usr/bin/env python3
import os
import sys
import subprocess
import csv
import hashlib

# Muster für Persistenz-Techniken
INDICATORS = {
    'cronjob': [
        'cron', 'crontab', '/etc/cron', 'cron.daily', 'cron.hourly'
    ],
    'init_daemon': [
        '/etc/init.d/', '/etc/rc.conf', '/etc/rc.d/rc.local', 'init.d', 'init'
    ],
    'configuration_files': [
        '/etc/rc.local', '/etc/rc.conf', '/etc/sysconfig/', '/etc/xdg/autostart/',
        'config', 'conf'
    ]
}

def is_elf(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT)
        return 'elf' in output.decode(errors='ignore').lower()
    except:
        return False

def extract_strings(filepath):
    try:
        output = subprocess.check_output(['strings', filepath], stderr=subprocess.STDOUT)
        return output.decode(errors='ignore').lower()
    except:
        return ""

def get_file_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def read_labels_txt(labels_txt):
    family_map = {}
    with open(labels_txt, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                h, fam = parts
                family_map[h] = fam.split(':')[-1] if 'SINGLETON' not in fam else fam
    return family_map

def main(scan_root, labels_txt):
    counts = {key: 0 for key in INDICATORS.keys()}
    counts['none'] = 0
    total_elfs = 0

    details = []
    dedup_seen = set()
    dedup_details = {}

    family_map = read_labels_txt(labels_txt)

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue

        for f in files:
            filepath = os.path.join(root, f)
            if not os.path.isfile(filepath):
                continue
            if not is_elf(filepath):
                continue

            total_elfs += 1
            strings_out = extract_strings(filepath)
            matched_categories = []

            for category, patterns in INDICATORS.items():
                if any(pat in strings_out for pat in patterns):
                    matched_categories.append(category)
                    counts[category] += 1

            if not matched_categories:
                counts['none'] += 1
                matched_categories.append('none')

            sha256 = get_file_hash(filepath, 'sha256')
            md5 = get_file_hash(filepath, 'md5')
            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            entry = {
                'file': filepath,
                'categories': ', '.join(matched_categories),
                'sha256': sha256,
                'md5': md5,
                'malware_family': family
            }

            details.append(entry)

            if sha256 not in dedup_seen:
                dedup_seen.add(sha256)
                dedup_details[sha256] = entry

    # CSV 1: ALL
    all_path = os.path.join(scan_root, "persistence_elf_analysis.csv")
    with open(all_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(['Filename', 'Categories', 'SHA256', 'MD5', 'Malware_Family'])
        for entry in details:
            writer.writerow([entry['file'], entry['categories'], entry['sha256'], entry['md5'], entry['malware_family']])

    # CSV 2: DEDUP
    dedup_path = os.path.join(scan_root, "persistence_elf_analysis_dedup.csv")
    with open(dedup_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(['Filename', 'Categories', 'SHA256', 'MD5', 'Malware_Family'])
        for entry in dedup_details.values():
            writer.writerow([entry['file'], entry['categories'], entry['sha256'], entry['md5'], entry['malware_family']])

    # CSV 3: SUMMARY
    summary_path = os.path.join(scan_root, "persistence_elf_analysis_summary.csv")
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(['Persistence technique used', 'Number of samples'])
        for category, count in counts.items():
            writer.writerow([category, count])
        writer.writerow(['TOTAL ELF binaries scanned', total_elfs])

    print("\nAnalyse abgeschlossen.")
    print(f"TOTAL ELF binaries gescannt: {total_elfs}")
    print(f"CSV gespeichert:\n - {all_path}\n - {dedup_path}\n - {summary_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_persistence_elf.py <Ordner> <labels.txt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

