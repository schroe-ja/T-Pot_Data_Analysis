#!/usr/bin/env python3

import os
import sys
import subprocess
import hashlib
import json

def is_elf(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT).decode().lower()
        return 'elf' in output
    except:
        return False

def get_hash(filepath, algorithm='sha256'):
    if algorithm == 'md5':
        h = hashlib.md5()
    elif algorithm == 'sha1':
        h = hashlib.sha1()
    elif algorithm == 'sha256':
        h = hashlib.sha256()
    else:
        raise ValueError("Unsupported hash algorithm")

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_vt(vt_file):
    av_labels = []
    try:
        with open(vt_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if data.get("type") == "file":
                results = data["attributes"]["last_analysis_results"]
            elif data.get("type") == "analysis":
                results = data["attributes"]["results"]
            else:
                return []
            for vendor, details in results.items():
                if details.get("result"):
                    # Korrekt als Tupel speichern!
                    av_labels.append( (vendor, details['result']) )
    except Exception as e:
        print(f"Fehler beim Parsen von {vt_file}: {e}")
    return av_labels

def main(scan_root):
    total = matched = unmatched = 0
    out_path = os.path.join(scan_root, "avclass_input.jsonl")

    with open(out_path, 'w', encoding='utf-8') as out_f:
        for root, _, files in os.walk(scan_root):
            if '/downloads' not in root and '/binaries' not in root:
                continue
            for file in files:
                filepath = os.path.join(root, file)
                if not os.path.isfile(filepath):
                    continue
                if not is_elf(filepath):
                    continue

                total += 1
                md5 = get_hash(filepath, 'md5')
                sha1 = get_hash(filepath, 'sha1')
                sha256 = get_hash(filepath, 'sha256')

                vt_path = os.path.join(root, "results", "virus_total", f"{sha256}.json")
                if not os.path.isfile(vt_path):
                    unmatched += 1
                    continue

                av_labels = parse_vt(vt_path)
                if not av_labels:
                    unmatched += 1
                    continue

                matched += 1
                entry = {
                    "md5": md5,
                    "sha1": sha1,
                    "sha256": sha256,
                    "av_labels": av_labels
                }
                out_f.write(json.dumps(entry) + "\n")

    print(f"\nELF gefunden: {total}")
    print(f"Mit VT: {matched}")
    print(f"Ohne VT/keine Labels: {unmatched}")
    print(f"Gespeichert: {out_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Nutzung: python3 create_avclass_input.py <Ordner>")
        sys.exit(1)
    main(sys.argv[1])

