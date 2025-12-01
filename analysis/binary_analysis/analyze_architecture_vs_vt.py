#!/usr/bin/env python3
import os
import subprocess
import sys
import hashlib
import json
import csv

def is_elf(filepath):
    try:
        output = subprocess.check_output(
            ['file', filepath], stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore').lower()
        return 'elf' in output
    except:
        return False

def get_architecture(filepath):
    try:
        output = subprocess.check_output(
            ['readelf', '-h', filepath], stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore').lower()
        for line in output.splitlines():
            if 'machine:' in line:
                if 'arm' in line:
                    return 'ARM'
                elif 'mips' in line:
                    return 'MIPS'
                elif 'x86-64' in line or 'i386' in line:
                    return 'x86'
                else:
                    return line.split(':', 1)[1].strip().upper()
    except:
        return 'UNKNOWN'

def get_file_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def get_file_md5(filepath):
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def get_vt_detection_rate(vt_path):
    try:
        with open(vt_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if data.get('type') == 'file':
                results = data['attributes']['last_analysis_results']
            elif data.get('type') == 'analysis':
                results = data['attributes']['results']
            else:
                return None
            detected = sum(1 for r in results.values() if r['result'] is not None)
            total = len(results)
            return round((detected / total) * 100, 2) if total > 0 else 0.0
    except:
        return None

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
    family_map = read_labels_txt(labels_txt)
    all_results = []
    unique_results = {}
    summary = {}

    total_files = 0
    vt_matches = 0
    vt_unmatched = 0

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue

        for file in files:
            filepath = os.path.join(root, file)
            if not os.path.isfile(filepath):
                continue
            if not is_elf(filepath):
                continue

            total_files += 1
            sha256 = get_file_hash(filepath)
            md5 = get_file_md5(filepath)
            architecture = get_architecture(filepath)

            vt_folder = os.path.join(root, 'results', 'virus_total')
            vt_file = os.path.join(vt_folder, f"{sha256}.json")
            vt_rate = None

            if os.path.isfile(vt_file):
                vt_rate = get_vt_detection_rate(vt_file)
                vt_matches += 1
            else:
                vt_unmatched += 1

            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            entry = {
                'File': filepath,
                'SHA256': sha256,
                'Architecture': architecture,
                'VT_Detection_Rate': vt_rate if vt_rate is not None else 'N/A',
                'Family': family
            }

            all_results.append(entry)

            if sha256 not in unique_results:
                unique_results[sha256] = entry

    # Zusammenfassung pro Architektur (nur dedup)
    summary_data = {}
    for item in unique_results.values():
        arch = item['Architecture']
        vt_rate = item['VT_Detection_Rate']
        if vt_rate == 'N/A':
            continue
        if arch not in summary_data:
            summary_data[arch] = {'count': 0, 'sum_vt': 0.0}
        summary_data[arch]['count'] += 1
        summary_data[arch]['sum_vt'] += vt_rate

    # CSV: full
    csv_full = os.path.join(scan_root, 'analyze_architecture_vs_vt_full.csv')
    with open(csv_full, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'SHA256', 'Architecture', 'VT_Detection_Rate', 'Family'])
        writer.writeheader()
        writer.writerows(all_results)

    # CSV: dedup
    csv_dedup = os.path.join(scan_root, 'analyze_architecture_vs_vt_dedup.csv')
    with open(csv_dedup, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'SHA256', 'Architecture', 'VT_Detection_Rate', 'Family'])
        writer.writeheader()
        writer.writerows(unique_results.values())

    # CSV: summary (ohne Family)
    csv_summary = os.path.join(scan_root, 'analyze_architecture_vs_vt_summary.csv')
    with open(csv_summary, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Architecture', 'Unique Samples', 'Avg VT Detection Rate'])
        for arch, data in summary_data.items():
            avg_vt = round(data['sum_vt'] / data['count'], 2) if data['count'] > 0 else 0.0
            writer.writerow([arch, data['count'], avg_vt])

    print("\nAnalyse abgeschlossen.")
    print(f"TOTAL ELF binaries gefunden: {total_files}")
    print(f"Mit VT-Match: {vt_matches}")
    print(f"Ohne VT-Match: {vt_unmatched}")
    print(f"CSV gespeichert unter:\n- {csv_full}\n- {csv_dedup}\n- {csv_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_architecture_vs_vt.py <Ordner> <LABELS_TXT>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

