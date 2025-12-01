#!/usr/bin/env python3
import os
import subprocess
import sys
import csv
import hashlib

PORT_CATEGORIES = {
    '22 (SSH)': ['22'],
    '23 (Telnet)': ['23'],
    '2323 (Telnet)': ['2323'],
    '53 (DNS)': ['53'],
    '80 (HTTP)': ['80'],
    '81 (Alt HTTP)': ['81'],
    '443 (HTTPS)': ['443'],
    '8080 (Alt HTTP)': ['8080'],
    '666 (IRC)': ['666'],
    '6666/6667/6697 (IRC)': ['6666', '6667', '6697'],
    '31337 (Backdoor)': ['31337'],
    '5555 (ADB)': ['5555'],
    '7547 (TR-069)': ['7547'],
    '52869 (Huawei)': ['52869'],
    '37215 (Huawei RCE)': ['37215'],
    '1900 (SSDP)': ['1900'],
    '2048 (Crypto Mining)': ['2048'],
    '123 (NTP)': ['123'],
    '137/138/139/445 (SMB)': ['137', '138', '139', '445'],
    '9000 (Remote shells)': ['9000'],
    'UDP (P2P)': ['udp'],
}

def extract_strings(filepath):
    try:
        result = subprocess.check_output(['strings', filepath], stderr=subprocess.DEVNULL)
        return result.decode('utf-8', errors='ignore').lower()
    except subprocess.CalledProcessError:
        return ""

def get_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

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
    total_files = 0
    results = {k: {'colon': 0, 'port_word': 0, 'total': 0} for k in PORT_CATEGORIES}
    none_count = 0

    all_results = []
    unique_hashes = set()
    dedup_results = []

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue
        for name in files:
            filepath = os.path.join(root, name)
            if not os.path.isfile(filepath):
                continue

            try:
                output = subprocess.check_output(['file', filepath], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore').lower()
            except:
                continue
            if 'elf' not in output:
                continue

            total_files += 1
            content = extract_strings(filepath)
            sha256 = get_hash(filepath, 'sha256')
            md5 = get_hash(filepath, 'md5')
            family = family_map.get(sha256) or family_map.get(md5) or 'UNKNOWN'

            matched_ports = []
            found = False

            for category, port_list in PORT_CATEGORIES.items():
                colon_count = sum(content.count(f":{p}") for p in port_list)
                port_word_count = sum(content.count(f"port {p}") for p in port_list)
                category_total = colon_count + port_word_count
                if category_total > 0:
                    results[category]['colon'] += colon_count
                    results[category]['port_word'] += port_word_count
                    results[category]['total'] += 1
                    matched_ports.append(category)
                    found = True

            if not found:
                none_count += 1
                matched_ports.append('None')

            all_results.append({
                'File': filepath,
                'SHA256': sha256,
                'MD5': md5,
                'Malware_Family': family,
                'Matched_Ports': ', '.join(matched_ports)
            })

            if sha256 not in unique_hashes:
                unique_hashes.add(sha256)
                dedup_results.append(all_results[-1])

    # Ausgabe in Konsole
    print("\nAnalyse-Ergebnis (C2 Ports):\n")
    for category, counts in results.items():
        print(f"{category}:")
        print(f"  - Count (:PORT): {counts['colon']}")
        print(f"  - Count ('port PORT'): {counts['port_word']}")
        print(f"  - Total: {counts['total']}\n")

    print(f"None: {none_count}")
    print(f"TOTAL ELF binaries scanned: {total_files}")

    # CSV 1: all
    csv_all = os.path.join(scan_root, "analyze_c2_ports_all.csv")
    with open(csv_all, "w", newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'SHA256', 'MD5', 'Malware_Family', 'Matched_Ports'])
        writer.writeheader()
        writer.writerows(all_results)

    # CSV 2: dedup
    csv_dedup = os.path.join(scan_root, "analyze_c2_ports_dedup.csv")
    with open(csv_dedup, "w", newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['File', 'SHA256', 'MD5', 'Malware_Family', 'Matched_Ports'])
        writer.writeheader()
        writer.writerows(dedup_results)

    # CSV 3: summary
    csv_summary = os.path.join(scan_root, "analyze_c2_ports_summary.csv")
    with open(csv_summary, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Port', 'Count (:PORT)', "Count ('port PORT')", 'Total'])
        for category, counts in results.items():
            writer.writerow([category, counts['colon'], counts['port_word'], counts['total']])
        writer.writerow(['None', '', '', none_count])
        writer.writerow(['TOTAL ELF binaries scanned', '', '', total_files])

    print(f"\nErgebnisse gespeichert unter:\n- {csv_all}\n- {csv_dedup}\n- {csv_summary}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python3 analyze_c2_ports_from_binaries.py <Ordner> <labels.txt>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

