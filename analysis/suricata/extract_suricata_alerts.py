#!/usr/bin/env python3
import os
import json
import csv
import sys
import gzip

def extract_suricata_alerts(base_dir):
    alerts = []
    total_json_files = 0
    alerts_found = 0
    no_alert_count = 0

    for root, _, files in os.walk(base_dir):
        for filename in files:
            # Nur Dateien berücksichtigen, die mit ".json" enden oder ".json.<irgendwas>"
            if not filename.startswith("eve.json"):
                continue
            if not (filename.endswith(".json") or ".json." in filename):
                continue

            filepath = os.path.join(root, filename)
            total_json_files += 1

            open_func = gzip.open if filename.endswith(".gz") else open

            try:
                with open_func(filepath, "rt", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            if "alert" in data:
                                alert = data["alert"]
                                alerts.append({
                                    "timestamp": data.get("timestamp", ""),
                                    "src_ip": data.get("src_ip", ""),
                                    "src_port": data.get("src_port", ""),
                                    "dest_ip": data.get("dest_ip", ""),
                                    "dest_port": data.get("dest_port", ""),
                                    "proto": data.get("proto", ""),
                                    "signature": alert.get("signature", ""),
                                    "category": alert.get("category", ""),
                                    "severity": alert.get("severity", "")
                                })
                                alerts_found += 1
                            else:
                                no_alert_count += 1
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Fehler beim Lesen von {filepath}: {e}")

    # Ergebnis speichern
    output_file = os.path.join(base_dir, "suricata_alerts_summary.csv")
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "signature", "category", "severity"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert)

    print(f"Analyse abgeschlossen.")
    print(f"Insgesamt JSON-Dateien verarbeitet: {total_json_files}")
    print(f"Gefundene Alerts: {alerts_found}")
    print(f"JSON-Einträge ohne 'alert': {no_alert_count}")
    print(f"Ergebnisse gespeichert in: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python extract_suricata_alerts.py <Pfad_zum_Verzeichnis>")
        sys.exit(1)

    extract_suricata_alerts(sys.argv[1])

