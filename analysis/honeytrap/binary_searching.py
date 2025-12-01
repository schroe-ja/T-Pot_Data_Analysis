#!/usr/bin/env python3

import os
import sys
import magic

def find_files(base_dir):
    total_files = 0
    elf_files = 0
    magic_obj = magic.Magic()  # Detailed file type, not just MIME

    for root, _, files in os.walk(base_dir):
        if "attacks" in root:
            for fname in files:
                filepath = os.path.join(root, fname)
                try:
                    ftype = magic_obj.from_file(filepath)
                    total_files += 1
                    if ftype.startswith("ELF"):
                        print(f"[ELF] {filepath} | {ftype}")
                        elf_files += 1
                    else:
                        print(f"[Not ELF] {filepath} | {ftype}")
                except Exception as e:
                    print(f"Failed to read {filepath}: {e}")

    print("\nFinished scanning.")
    print(f"Total files scanned: {total_files}")
    print(f"Total ELF files: {elf_files}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <Directory>")
        sys.exit(1)
    find_files(sys.argv[1])

