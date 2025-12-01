#!/usr/bin/env python3
import os
import json
import csv
import sys

def extract_honeytrap_ips(base_dir):
    results = []
    total_files = 0
    total_lines = 0
    total_parsed = 0
    total_failed_lines = 0

    for root, _, files in os.walk(base_dir):
        if "log" not in root:
            continue

        for fname in files:
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, start=1):
                        total_lines += 1
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            log = json.loads(line)
                            attack = log.get("attack_connection", {}) or {}

                            protocol = attack.get("protocol")
                            remote_ip = attack.get("remote_ip")
                            #remote_port = attack.get("remote_port")

                            #payload = attack.get("payload", {}) or {}
                            #md5 = payload.get("md5_hash")
                            #sha512 = payload.get("sha512_hash")

                            results.append({
                                "RemoteIP": remote_ip,
                                #"RemotePort": remote_port,
                                #"MD5": md5,
                                #"SHA512": sha512,
                                #"Protocol": protocol
                            })
                            total_parsed += 1
                        except json.JSONDecodeError as e:
                            print(f"[JSON ERROR] File: {filepath}, Line {line_num}: {e}")
                            total_failed_lines += 1
                        except Exception as e:
                            print(f"[PARSE ERROR] File: {filepath}, Line {line_num}: {e}")
                            total_failed_lines += 1

                total_files += 1
            except Exception as e:
                print(f"[FILE ERROR] Failed to open file {filepath}: {e}")

    print(f"\nSummary:")
    print(f"  ✔️ Processed {total_files} files")
    print(f"  ✔️ {total_lines} lines scanned")
    print(f"  ✔️ {total_parsed} attack entries parsed")
    print(f"  ⚠️ {total_failed_lines} lines failed to parse\n")

    return results


if __name__ == "__main__":
	if len(sys.argv) != 2:
		print("Usage: python3 script.py <Directory>")
		sys.exit(1)
	results = extract_honeytrap_ips(sys.argv[1])
	with open("honeytrap_ips.csv", 'w', newline='', encoding='utf-8') as f:
		#writer = csv.DictWriter(f, fieldnames=['RemoteIP', 'RemotePort', 'MD5', 'SHA512', 'Protocol'])
		writer = csv.DictWriter(f, fieldnames=['RemoteIP'])
		writer.writeheader()
		writer.writerows(results)
	
