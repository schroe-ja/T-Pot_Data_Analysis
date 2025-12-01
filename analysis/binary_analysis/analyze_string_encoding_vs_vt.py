#!/usr/bin/env python3
import os
import subprocess
import sys
import hashlib
import json
import csv

ENCODING_INDICATORS = [
    "base64_decode", "str_rot13", "decode", "hex", "xor"
]

def is_elf(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore').lower()
        return 'elf' in output
    except:
        return False

def has_string_encoding(filepath):
    try:
        output = subprocess.check_output(['strings', filepath], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore').lower()
        return any(indicator in output for indicator in ENCODING_INDICATORS)
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
    total, matched, unmatched = 0, 0, 0

    family_map = read_labels_txt(labels_txt)

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue

        for file in files:
            filepath = os.path.join(root, file)
            if not os.path.isfile(filepath) or not is_elf(filepath):
                continue

            total += 1
            encoding = "Yes" if has_string_encoding(filepath) else "No"
            sha256 = get_file_hash(filepath, 'sha256')
            md5 = get_file_hash(filepath, 'md5')

            vt_folder = os.path.join(root, 'results', 'virus_total')
            vt_file = os.path.join(vt_folder, f"{sha256}.json")
            detection_rate = None

            if os.path.isfile(vt_file):
                detection_rate = get_vt_detection_rate(vt_file)
                matched += 1
            else:
                unmatched += 1

            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            entry = {
                'File': filepath,
                'Encoding': encoding,
                'SHA256': sha256,
                'MD5': md5,
                'Malware_Family': family,
                'VT_Detection_Rate': detection_rate if detection_rate is not None else 'N/A'
            }

            results.append(entry)

            if sha256 not in unique:
                unique[sha256] = entry

    # Alle Ergebnisse
    output_all = os.path.join(scan_root, 'string_encoding_vs_vt.csv')
    with open(output_all, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'Encoding', 'SHA256', 'MD5', 'Malware_Family', 'VT_Detection_Rate'])
        writer.writeheader()
        writer.writerows(results)

    # Dedup
    output_dedup = os.path.join(scan_root, 'string_encoding_vs_vt_dedup.csv')
    with open(output_dedup, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'Encoding', 'SHA256', 'MD5', 'Malware_Family', 'VT_Detection_Rate'])
        writer.writeheader()
        writer.writerows(unique.values())

    # Zusammenfassung
    enc_rates = [float(r['VT_Detection_Rate']) for r in unique.values() if r['Encoding'] == 'Yes' and r['VT_Detection_Rate'] != 'N/A']
    noenc_rates = [float(r['VT_Detection_Rate']) for r in unique.values() if r['Encoding'] == 'No' and r['VT_Detection_Rate'] != 'N/A']
    avg_yes = round(sum(enc_rates) / len(enc_rates), 2) if enc_rates else 0.0
    avg_no = round(sum(noenc_rates) / len(noenc_rates), 2) if noenc_rates else 0.0

    output_summary = os.path.join(scan_root, 'string_encoding_vs_vt_summary.csv')
    with open(output_summary, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['String encoding', 'Virustotal positives'])
        writer.writerow(['Yes', avg_yes])
        writer.writerow(['No', avg_no])

    print("\nAnalyse abgeschlossen.")
    print(f"TOTAL ELF binaries gefunden: {total}")
    print(f"Mit VT-Match: {matched}")
    print(f"Ohne VT-Match: {unmatched}")
    print(f"CSV gespeichert unter:\n - {output_all}\n - {output_dedup}\n - {output_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_string_encoding_vs_vt.py <Ordner> <labels.txt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

