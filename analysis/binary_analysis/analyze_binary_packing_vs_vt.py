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

def detect_packer(filepath):
    # Erkennt Default UPX, Custom Packer oder None
    try:
        subprocess.check_output(['upx', '-t', filepath], stderr=subprocess.STDOUT)
        return 'Default UPX'
    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:
        print("UPX nicht installiert! Skipping.")
        pass

    try:
        output = subprocess.check_output(['binwalk', filepath], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore').lower()
        custom_signatures = [
            'upx', 'lzma', 'compressed', 'packer', 'packed',
            'obfusc', 'cryptor', 'aspack', 'mpress', 'themida',
            'petite', 'upack', 'fsg', 'mew', 'nspack'
        ]
        for sig in custom_signatures:
            if sig in output:
                return 'Custom Packer'
    except:
        pass

    return 'None'

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
            vt_type = data.get("type", "")
            if vt_type == "file":
                results = data['attributes']['last_analysis_results']
            elif vt_type == "analysis":
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
    unique_results = {}
    total = matched = unmatched = 0

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue

        for file in files:
            filepath = os.path.join(root, file)
            if not os.path.isfile(filepath) or not is_elf(filepath):
                continue

            total += 1
            packing = detect_packer(filepath)
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
                'Packing': packing,
                'SHA256': sha256,
                'Family': family,
                'VT_Detection_Rate': detection_rate if detection_rate is not None else 'N/A'
            }

            all_results.append(row)
            if sha256 not in unique_results:
                unique_results[sha256] = row

    # CSV 1: Alle Ergebnisse (inkl. Familien, nicht dedupliziert)
    csv1 = os.path.join(scan_root, 'analyze_packing_vs_vt.csv')
    with open(csv1, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'Packing', 'SHA256', 'Family', 'VT_Detection_Rate'])
        writer.writeheader()
        writer.writerows(all_results)

    # CSV 2: Deduplizierte Ergebnisse
    csv2 = os.path.join(scan_root, 'analyze_packing_vs_vt_dedup.csv')
    with open(csv2, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'Packing', 'SHA256', 'Family', 'VT_Detection_Rate'])
        writer.writeheader()
        writer.writerows(unique_results.values())

    # CSV 3: Zusammenfassung ohne Malware-Familien
    packing_groups = {'None': [], 'Default UPX': [], 'Custom Packer': []}
    for entry in unique_results.values():
        rate = entry['VT_Detection_Rate']
        if rate != 'N/A':
            packing_groups[entry['Packing']].append(float(rate))

    summary_csv = os.path.join(scan_root, 'analyze_packing_vs_vt_summary.csv')
    with open(summary_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Binary packing', 'Virustotal positives'])
        for k in ['None', 'Default UPX', 'Custom Packer']:
            values = packing_groups[k]
            avg = round(sum(values)/len(values), 2) if values else 0.0
            writer.writerow([k, avg])

    print("\nAnalyse abgeschlossen.")
    print(f"TOTAL ELF binaries gefunden: {total}")
    print(f"Mit VT-Match: {matched}")
    print(f"Ohne VT-Match: {unmatched}")
    print(f"CSV gespeichert unter:\n {csv1}\n {csv2}\n {summary_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_packing_vs_vt.py <Ordner> <labels.txt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

