#!/usr/bin/env python3
import os
import subprocess
import sys
import math
import csv

def is_binary(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT)
        return ('elf' in output.decode(errors='ignore').lower()) or ('pe32' in output.decode(errors='ignore').lower())
    except:
        return False

def detect_type(file_output):
    output = file_output.lower()
    if 'elf' in output:
        return 'ELF'
    elif 'pe32' in output:
        if 'dll' in output:
            return 'DLL'
        elif 'sys' in output:
            return 'SYS'
        else:
            return 'PE'
    else:
        return 'OTHER'

def calc_entropy(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    if not data:
        return 0.0
    occur = [0] * 256
    for b in data:
        occur[b] += 1
    ent = 0.0
    for oc in occur:
        if oc == 0:
            continue
        p = oc / len(data)
        ent -= p * math.log2(p)
    return round(ent, 3)

def calc_strings(filepath):
    try:
        output = subprocess.check_output(['strings', filepath], stderr=subprocess.STDOUT)
        return len(output.decode(errors='ignore').splitlines())
    except:
        return 0

def main(scan_root):
    rows = []

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue
        for name in files:
            path = os.path.join(root, name)
            if not os.path.isfile(path) or not is_binary(path):
                continue

            file_output = subprocess.check_output(['file', path]).decode(errors='ignore')
            btype = detect_type(file_output)
            size = os.path.getsize(path)
            ent = calc_entropy(path)
            strings_count = calc_strings(path)
            density = round(strings_count / (size / 1024 + 0.1), 2) if size > 0 else 0

            rows.append({
                'File': path,
                'Type': btype,
                'Size(Bytes)': size,
                'Strings': strings_count,
                'Strings per kB': density,
                'Entropy': ent
            })

            print(f"Scanned: {path} | {btype} | Entropy: {ent} | Strings: {strings_count} | Density: {density}")

    # Ausgabe-Datei im gleichen Ordner wie der Parameter speichern
    outfile = os.path.join(scan_root, "obfuscation_analysis.csv")
    with open(outfile, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n{len(rows)} Einträge gespeichert in: {outfile}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python3 analyze_obfuscation.py <Ordner>")
        sys.exit(1)
    main(sys.argv[1])

