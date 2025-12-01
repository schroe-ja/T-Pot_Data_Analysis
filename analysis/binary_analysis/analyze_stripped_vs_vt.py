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

def is_stripped(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore').lower()
        return 'not stripped' not in output and 'stripped' in output
    except:
        return False

def get_file_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def get_vt_detection_rate(vt_path):
    try:
        with open(vt_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if data['type'] == 'file':
                results = data['attributes']['last_analysis_results']
            elif data['type'] == 'analysis':
                results = data['attributes']['results']
            else:
                return None
            detected = sum(1 for r in results.values() if r['result'] is not None)
            total = len(results)
            return round((detected / total) * 100, 2) if total > 0 else 0.0
    except:
        return None

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
    total = matched = unmatched = 0
    family_map = read_labels_txt(labels_txt)

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue

        for file in files:
            filepath = os.path.join(root, file)
            if not os.path.isfile(filepath) or not is_elf(filepath):
                continue

            total += 1
            stripped = "Yes" if is_stripped(filepath) else "No"
            sha256 = get_file_hash(filepath, 'sha256')
            md5 = get_file_hash(filepath, 'md5')
            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            vt_folder = os.path.join(root, 'results', 'virus_total')
            vt_file = os.path.join(vt_folder, f"{sha256}.json")
            detection_rate = None

            if os.path.isfile(vt_file):
                detection_rate = get_vt_detection_rate(vt_file)
                matched += 1
            else:
                unmatched += 1

            row = {
                'File': filepath,
                'Stripped': stripped,
                'SHA256': sha256,
                'MD5': md5,
                'VT_Detection_Rate': detection_rate if detection_rate is not None else 'N/A',
                'Malware_Family': family
            }

            results.append(row)
            if sha256 not in unique:
                unique[sha256] = row

    # CSV: all
    output_file = os.path.join(scan_root, 'analyze_stripped_vs_vt.csv')
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # CSV: dedup
    dedup_file = os.path.join(scan_root, 'analyze_stripped_vs_vt_dedup.csv')
    with open(dedup_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(unique.values())

    # CSV: summary
    stripped_yes = [float(e['VT_Detection_Rate']) for e in unique.values() if e['Stripped'] == 'Yes' and e['VT_Detection_Rate'] != 'N/A']
    stripped_no = [float(e['VT_Detection_Rate']) for e in unique.values() if e['Stripped'] == 'No' and e['VT_Detection_Rate'] != 'N/A']

    summary = [
        {'Debugging symbols removed': 'Yes', 'Virustotal positives': round(sum(stripped_yes)/len(stripped_yes), 2) if stripped_yes else 0.0},
        {'Debugging symbols removed': 'No', 'Virustotal positives': round(sum(stripped_no)/len(stripped_no), 2) if stripped_no else 0.0}
    ]

    summary_file = os.path.join(scan_root, 'analyze_stripped_vs_vt_summary.csv')
    with open(summary_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Debugging symbols removed', 'Virustotal positives'])
        writer.writeheader()
        writer.writerows(summary)

    print("\nAnalyse abgeschlossen.")
    print(f"TOTAL ELF binaries gefunden: {total}")
    print(f"Mit VT-Match: {matched}")
    print(f"Ohne VT-Match: {unmatched}")
    print(f"CSV gespeichert unter:\n - {output_file}\n - {dedup_file}\n - {summary_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_stripped_vs_vt.py <Ordner> <labels.txt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

