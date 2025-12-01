#!/usr/bin/env python3
import sys
import json
import csv
import os
from urllib.parse import urlparse

def extract_ip_from_url(url):
    try:
        return urlparse(url).hostname
    except Exception:
        return None

#def protect_url(url):
    #return url.replace(":", "[:]") \
              #.replace(".", "[.]")

def load_urlhaus_json(json_path):
    url_ip_map = {}
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for entries in data.values():
        for entry in entries:
            url = entry.get("url", "")
            ip = extract_ip_from_url(url)
            if ip:
                tags_raw = entry.get("tags", [])
                if isinstance(tags_raw, list):
                    tags = ",".join(tags_raw)
                elif isinstance(tags_raw, str):
                    tags = tags_raw
                else:
                    tags = ""
                if ip not in url_ip_map:
                    url_ip_map[ip] = []
                url_ip_map[ip].append({
                    "url": url,
                    "threat": entry.get("threat", ""),
                    "tags": tags
                })
    return url_ip_map

def match_ips_with_urlhaus(urlhaus_json_path, csv_input_path):
    urlhaus_data = load_urlhaus_json(urlhaus_json_path)
    urlhaus_ips = set(urlhaus_data.keys())

    csv_ips = set()
    csv_rows = {}

    with open(csv_input_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip_raw = row.get("src_ip", "") or row.get("ip", "")
            ip = ip_raw.strip()
            count = row.get("count", "").strip()
            if ip:
                csv_ips.add(ip)
                csv_rows[ip] = count

    matches = []
    for ip in csv_ips:
        if ip in urlhaus_data:
            for match in urlhaus_data[ip]:
                matches.append({
                    "src_ip": ip,
                    "count": csv_rows[ip],
                    "url": match["url"],
                    "threat": match["threat"],
                    "tags": match["tags"]
                })

    output_path = os.path.join(os.path.dirname(csv_input_path), "urlhaus_matches.csv")
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["src_ip", "count", "url", "threat", "tags"])
        writer.writeheader()
        for row in matches:
            writer.writerow(row)

    # Konsolenausgabe
    print(f"Analyse abgeschlossen.")
    print(f"Datei 1 (URLhaus JSON): {os.path.basename(urlhaus_json_path)} → {len(urlhaus_ips)} eindeutige IPs")
    print(f"Datei 2 (CSV mit IPs):   {os.path.basename(csv_input_path)} → {len(csv_ips)} eindeutige IPs")
    print(f"Gefundene Übereinstimmungen: {len(matches)}")
    print(f"Ergebnis gespeichert unter: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Verwendung: python match_urlhaus_json_with_csv.py <urlhaus_json> <csv_input>")
        sys.exit(1)

    urlhaus_json = sys.argv[1]
    csv_input = sys.argv[2]

    match_ips_with_urlhaus(urlhaus_json, csv_input)

