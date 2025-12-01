#!/usr/bin/env python3
import os
import sys
import subprocess
import csv
import hashlib

# Anti-Forensics-Indikatoren
INDICATORS = {
    'process_renaming': [
        'prctl', 'pr_set_name', 'setproctitle', 'pr_set', 'task_comm'
    ],
    'removing_binary_after_execution': [
        'rm ', '/bin/rm', 'unlink', 'remove', 'delete', 'shred', 'wipe'
    ],
    'removing_logs_configs_ssh': [
        '/var/log/', '/var/tmp/', '/tmp/', 'rm -rf', 'history',
        'ssh', 'resolvconf', 'netstat', 'klog', 'utmp', 'wtmp', 'lastlog'
    ],
    'firewall_changes': [
        'iptables', 'ufw', 'firewalld', 'nft', 'firewall', 'ip6tables'
    ]
}

def is_elf(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT)
        return 'elf' in output.decode(errors='ignore').lower()
    except:
        return False

def get_file_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def extract_strings(filepath):
    try:
        output = subprocess.check_output(['strings', filepath], stderr=subprocess.STDOUT)
        return output.decode(errors='ignore').lower()
    except:
        return ""

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
    counts = {key: 0 for key in INDICATORS.keys()}
    counts['none'] = 0
    total_elfs = 0
    all_results = []
    dedup_results = []
    seen_hashes = set()

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue

        for f in files:
            filepath = os.path.join(root, f)
            if not os.path.isfile(filepath):
                continue
            if not is_elf(filepath):
                continue

            sha256 = get_file_hash(filepath, 'sha256')
            md5 = get_file_hash(filepath, 'md5')
            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            strings_out = extract_strings(filepath)
            matched_categories = [cat for cat, pats in INDICATORS.items() if any(pat in strings_out for pat in pats)]
            if not matched_categories:
                matched_categories = ['none']
                counts['none'] += 1
            else:
                for cat in matched_categories:
                    counts[cat] += 1

            # All samples (auch Duplikate)
            all_results.append({
                'Filepath': filepath,
                'SHA256': sha256,
                'MD5': md5,
                'Categories': ', '.join(matched_categories),
                'Family': family
            })

            # Nur deduplizierte Samples (einzigartige SHA256)
            if sha256 not in seen_hashes:
                seen_hashes.add(sha256)
                total_elfs += 1
                dedup_results.append({
                    'Filepath': filepath,
                    'SHA256': sha256,
                    'MD5': md5,
                    'Categories': ', '.join(matched_categories),
                    'Family': family
                })

    # Speichern ALL
    csv_all = os.path.join(scan_root, "anti_forensics_elf_all.csv")
    with open(csv_all, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=['Filepath', 'SHA256', 'MD5', 'Categories', 'Family'])
        writer.writeheader()
        writer.writerows(all_results)

    # Speichern DEDUP
    csv_dedup = os.path.join(scan_root, "anti_forensics_elf_dedup.csv")
    with open(csv_dedup, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=['Filepath', 'SHA256', 'MD5', 'Categories', 'Family'])
        writer.writeheader()
        writer.writerows(dedup_results)

    # Speichern SUMMARY
    csv_summary = os.path.join(scan_root, "anti_forensics_elf_summary.csv")
    with open(csv_summary, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(['Anti-forensics technique used', 'Number of samples'])
        for category in INDICATORS.keys():
            writer.writerow([category.replace('_', ' ').capitalize(), counts.get(category, 0)])
        writer.writerow(['None (no indicators)', counts.get('none', 0)])
        writer.writerow(['TOTAL unique ELF binaries scanned', total_elfs])

    print("\nAnalyse abgeschlossen.")
    print(f"All gespeichert: {csv_all}")
    print(f"Dedup gespeichert: {csv_dedup}")
    print(f"Summary gespeichert: {csv_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_anti_forensics_elf.py <Ordner> <LABELS_TXT>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

