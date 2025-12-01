#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import vt
from tqdm import tqdm
import json

# Virus Total API-Key
VT_API_KEY = ""

# API-Limit für die Public API: 4 Anfragen/Minute
SLEEP_BETWEEN_REQUESTS = 15

# SHA-256 Hash berechnen
def get_file_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# Datei hochladen und Bericht speichern
def scan_file(client, filepath):
    filename = os.path.basename(filepath)
    file_hash = get_file_hash(filepath)

    # Ergebnisordner im selben Pfad wie die Datei
    results_dir = os.path.join(os.path.dirname(filepath), "results", "virus_total")
    os.makedirs(results_dir, exist_ok=True)

    report_path = os.path.join(results_dir, f"{file_hash}.json")

    # Überspringen, wenn schon gescannt
    if os.path.exists(report_path):
        print(f">> Bereits gescannt: {file_hash}")
        return True

    print(f"--> Sende Datei: {filename}")
    try:
        with open(filepath, "rb") as f:
            analysis = client.scan_file(f)
    except vt.error.APIError as e:
        if e.code == "ConflictError":
            print(f"! Datei bereits bei VirusTotal vorhanden. Lade Report: {file_hash}")
        else:
            print(f"!! Fehler beim Hochladen: {e}")
            return False
    except Exception as e:
        print(f"!! Fehler beim Hochladen: {e}")
        if "QuotaExceededError" in str(e):
            print("!! Maximum an Anfragen erreicht. Breche ab")
            sys.exit(1)
        return False

    print("... Warte auf Analyse oder lade existierenden Bericht...")
    try:
        # Status nur abfragen, wenn keine ConflictError auftrat
        if 'analysis' in locals():
            analysis_id = analysis.id
            while True:
                analysis_obj = client.get_object(f"/analyses/{analysis_id}")
                if analysis_obj.status == "completed":
                    break
                time.sleep(5)

        # Bericht abrufen und speichern
        report = client.get_object(f"/files/{file_hash}")
        with open(report_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"Bericht gespeichert: {report_path}")
        return True
    except Exception as e:
        print(f"!! Fehler bei Analyse: {e}")
        return False

# Hauptfunktion
def main():
    if len(sys.argv) != 2:
        print("Bitte gib eine Datei oder einen Ordner an.")
        print("Beispiel: python3 vt_scan.py /pfad/zur/datei_oder_ordner")
        sys.exit(1)

    input_path = sys.argv[1]
    if not os.path.exists(input_path):
        print(f"Pfad ungültig: {input_path}")
        sys.exit(1)

    client = vt.Client(VT_API_KEY)

    try:
        if os.path.isfile(input_path):
            scan_file(client, input_path)
        else:
            files = [
                os.path.join(root, f)
                for root, _, filenames in os.walk(input_path)
                for f in filenames
                if not f.startswith(".") and not f.endswith(".json")
                and "results" not in os.path.relpath(root, input_path).split(os.sep)
            ]
            for filepath in tqdm(files, desc="... Dateien werden verarbeitet"):
                scanned = scan_file(client, filepath)
                if not scanned:
                    time.sleep(SLEEP_BETWEEN_REQUESTS)
    finally:
        client.close()
        print("Scan abgeschlossen.")

if __name__ == "__main__":
    main()
