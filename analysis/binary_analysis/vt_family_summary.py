#!/usr/bin/env python3
import os
import subprocess
import sys
import hashlib
import json
import csv

def is_elf(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore').lower()
        return 'elf' in output
    except:
        return False

def get_file_hash(filepath, hash_type='sha256'):
    if hash_type == 'md5':
        h = hashlib.md5()
    else:
        h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def get_vt_detection_rate(vt_file):
    try:
        with open(vt_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if data.get('type') == 'file':
                results = data['attributes']['last_analysis_results']
            elif data.get('type') == 'analysis':
                results = data['attributes']['results']
            else:
                return None
            positives = sum(1 for r in results.values() if r['result'])
            total = len(results)
            return round((positives / total) * 100, 2) if total > 0 else 0.0
    except:
        return None

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
    all_results = []
    dedup_results = {}
    summary_data = {}

    total_elfs = matched = unmatched = 0

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue

        for file in files:
            filepath = os.path.join(root, file)
            if not os.path.isfile(filepath):
                continue
            if not is_elf(filepath):
                continue

            total_elfs += 1

            sha256 = get_file_hash(filepath, 'sha256')
            md5 = get_file_hash(filepath, 'md5')

            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            vt_folder = os.path.join(root, 'results', 'virus_total')
            vt_file_sha256 = os.path.join(vt_folder, f"{sha256}.json")
            vt_file_md5 = os.path.join(vt_folder, f"{md5}.json")

            vt_rate = None
            if os.path.isfile(vt_file_sha256):
                vt_rate = get_vt_detection_rate(vt_file_sha256)
                matched += 1
            elif os.path.isfile(vt_file_md5):
                vt_rate = get_vt_detection_rate(vt_file_md5)
                matched += 1
            else:
                unmatched += 1

            entry = {
                'File': filepath,
                'SHA256': sha256,
                'MD5': md5,
                'Family': family,
                'VT_Detection_Rate': vt_rate if vt_rate is not None else 'N/A'
            }

            all_results.append(entry)
            if sha256 not in dedup_results:
                dedup_results[sha256] = entry

            if family not in summary_data:
                summary_data[family] = {'count': 0, 'sum_vt': 0.0}

            if vt_rate is not None:
                summary_data[family]['count'] += 1
                summary_data[family]['sum_vt'] += vt_rate

    # Save all results
    csv_all = os.path.join(scan_root, 'vt_family_all.csv')
    with open(csv_all, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'SHA256', 'MD5', 'Family', 'VT_Detection_Rate'])
        writer.writeheader()
        writer.writerows(all_results)

    # Save deduplicated
    csv_dedup = os.path.join(scan_root, 'vt_family_dedup.csv')
    with open(csv_dedup, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'SHA256', 'MD5', 'Family', 'VT_Detection_Rate'])
        writer.writeheader()
        writer.writerows(dedup_results.values())

    # Save summary
    csv_summary = os.path.join(scan_root, 'vt_family_summary.csv')
    with open(csv_summary, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Family', 'Unique Samples', 'Avg VT Detection Rate'])
        for family, data in summary_data.items():
            avg = round(data['sum_vt'] / data['count'], 2) if data['count'] > 0 else 0.0
            writer.writerow([family, data['count'], avg])

    print("\nAnalyse abgeschlossen.")
    print(f"TOTAL ELF binaries: {total_elfs}")
    print(f"Mit VT Match: {matched}")
    print(f"Ohne VT Match: {unmatched}")
    print(f"Gespeichert: {csv_all}, {csv_dedup}, {csv_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 vt_family_summary.py <SCAN_ROOT> <LABELS_TXT>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

