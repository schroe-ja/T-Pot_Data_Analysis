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

def is_statically_linked(filepath):
    try:
        output = subprocess.check_output(['readelf', '-d', filepath], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore').lower()
        if 'no dynamic section' in output:
            return True
        for line in output.splitlines():
            if 'needed' in line:
                return False
        return True
    except:
        return False

def get_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def get_vt_detection_rate(vt_path):
    try:
        with open(vt_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            results = data['attributes']['last_analysis_results'] if data.get('type') == 'file' else data['attributes']['results']
            detected = sum(1 for r in results.values() if r['result'] is not None)
            total = len(results)
            return round((detected / total) * 100, 2) if total > 0 else 0.0
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
    results = []
    dedup_results = {}
    total = matched = unmatched = 0

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue
        for file in files:
            filepath = os.path.join(root, file)
            if not os.path.isfile(filepath) or not is_elf(filepath):
                continue

            total += 1
            linking = "Static" if is_statically_linked(filepath) else "Dynamic"
            sha256 = get_hash(filepath, 'sha256')
            md5 = get_hash(filepath, 'md5')
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
                'Linking': linking,
                'SHA256': sha256,
                'MD5': md5,
                'Malware_Family': family,
                'VT_Detection_Rate': detection_rate if detection_rate is not None else 'N/A'
            }

            results.append(row)
            if sha256 not in dedup_results:
                dedup_results[sha256] = row

    # CSV 1: Alle Dateien (ALL)
    output_file = os.path.join(scan_root, 'analyze_library_linking_vs_vt.csv')
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        writer.writeheader()
        writer.writerows(results)

    # CSV 2: Dedup
    dedup_file = os.path.join(scan_root, 'analyze_library_linking_vs_vt_dedup.csv')
    with open(dedup_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        writer.writeheader()
        writer.writerows(dedup_results.values())

    # CSV 3: Zusammenfassung
    static_rates = [float(e['VT_Detection_Rate']) for e in dedup_results.values()
                    if e['Linking'] == 'Static' and e['VT_Detection_Rate'] != 'N/A']
    dynamic_rates = [float(e['VT_Detection_Rate']) for e in dedup_results.values()
                     if e['Linking'] == 'Dynamic' and e['VT_Detection_Rate'] != 'N/A']

    summary = [
        {'Library linking': 'Static', 'Virustotal positives': round(sum(static_rates)/len(static_rates), 2) if static_rates else 0.0},
        {'Library linking': 'Dynamic', 'Virustotal positives': round(sum(dynamic_rates)/len(dynamic_rates), 2) if dynamic_rates else 0.0}
    ]

    summary_file = os.path.join(scan_root, 'analyze_library_linking_vs_vt_summary.csv')
    with open(summary_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Library linking', 'Virustotal positives'])
        writer.writeheader()
        writer.writerows(summary)

    # Konsole
    print("\nAnalyse abgeschlossen.")
    print(f"TOTAL ELF binaries gefunden: {total}")
    print(f"Mit VT-Match: {matched}")
    print(f"Ohne VT-Match: {unmatched}")
    print(f"CSV gespeichert unter:\n- {output_file}\n- {dedup_file}\n- {summary_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_library_linking_vs_vt.py <Ordner> <labels.txt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

