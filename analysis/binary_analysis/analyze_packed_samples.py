#!/usr/bin/env python3
import os
import subprocess
import sys
from collections import defaultdict

def is_binary(filepath):
    try:
        output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT)
        output = output.decode('utf-8', errors='ignore').lower()
        return ('elf' in output) or ('pe32' in output)
    except subprocess.CalledProcessError:
        return False

def detect_type(filepath):
    output = subprocess.check_output(['file', filepath], stderr=subprocess.STDOUT)
    output = output.decode('utf-8', errors='ignore').lower()
    if 'elf' in output:
        return 'ELF'
    elif 'pe32' in output:
        if 'dll' in output:
            return 'DLL'
        else:
            return 'PE'
    else:
        return 'OTHER'

def is_standard_upx(filepath):
    try:
        subprocess.check_output(['upx', '-t', filepath], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

def detect_packer_with_binwalk(filepath):
    try:
        output = subprocess.check_output(['binwalk', filepath], stderr=subprocess.STDOUT)
        decoded = output.decode('utf-8', errors='ignore').lower()
        if 'upx' in decoded:
            return 'Custom UPX'
        elif any(p in decoded for p in ['packer', 'aspack', 'themida', 'nsis', 'petite', 'fsg', 'pecompact']):
            return 'Other Packer'
        else:
            return 'Not Packed'
    except subprocess.CalledProcessError:
        return 'Not Packed'

def main(scan_root):
    summary = defaultdict(lambda: {'Standard UPX': 0, 'Custom UPX': 0, 'Other Packer': 0, 'Not Packed': 0})
    total_files = 0

    for root, _, files in os.walk(scan_root):
        if '/binaries' not in root and '/downloads' not in root:
            continue
        for name in files:
            filepath = os.path.join(root, name)
            if not os.path.isfile(filepath):
                continue
            if not is_binary(filepath):
                continue

            bin_type = detect_type(filepath)
            total_files += 1

            if is_standard_upx(filepath):
                summary[bin_type]['Standard UPX'] += 1
            else:
                packer_result = detect_packer_with_binwalk(filepath)
                summary[bin_type][packer_result] += 1

    print("\nAnalyse-Ergebnis (Packing):\n")
    for bin_type, counts in summary.items():
        total = sum(counts.values())
        print(f"{bin_type} Files: {total}")
        print(f"  - Standard UPX: {counts['Standard UPX']}")
        print(f"  - Custom UPX:   {counts['Custom UPX']}")
        print(f"  - Other Packer: {counts['Other Packer']}")
        print(f"  - Not Packed:   {counts['Not Packed']}\n")

    print(f"TOTAL scanned binaries: {total_files}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_packed_samples.py <scan_root>")
        sys.exit(1)
    main(sys.argv[1])

