#!/usr/bin/env python3

import os
import subprocess
import shutil
import sys

def sanitize_name(name):
    return name.replace(" ", "_")

def classify_and_move_files(folder_path):
    if not os.path.isdir(folder_path):
        print(f"Pfad ist kein Verzeichnis: {folder_path}")
        return

    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)

        if not os.path.isfile(filepath):
            continue  # Nur reguläre Dateien analysieren

        try:
            # Dateityp mit dem `file`-Befehl herausfinden
            result = subprocess.run(["file", "-b", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            filetype = result.stdout.strip()
        except Exception as e:
            print(f"Fehler bei Datei {filename}: {e}")
            continue

        folder_name = sanitize_name(filetype)
        target_dir = os.path.join(folder_path, folder_name)

        os.makedirs(target_dir, exist_ok=True)

        try:
            shutil.move(filepath, os.path.join(target_dir, filename))
        except Exception as e:
            print(f"Fehler beim Verschieben von {filename} nach {target_dir}: {e}")

    print("Dateien wurden gruppiert und verschoben.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python3 move_files_by_type.py <Pfad_zum_Verzeichnis>")
    else:
        classify_and_move_files(sys.argv[1])

