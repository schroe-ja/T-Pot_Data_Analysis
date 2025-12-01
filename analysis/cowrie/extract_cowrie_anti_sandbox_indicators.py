#!/usr/bin/env python3
import os
import csv
import sys
import json
from collections import defaultdict

# -------------------------
# 1) Alle Indikatoren & Kategorien
# -------------------------
ANTI_SANDBOX_INDICATORS = [
    {
        "category": "System Information",
        "indicators": ["uname", "whoami", "id", "ps", "top", "lscpu", "lsusb", "lspci", "lsmod", "df", "free"]
    },
    {
        "category": "/proc & /sys",
        "indicators": ["/proc/", "/sys/"]
    },
    {
        "category": "Virtualization Detection",
        "indicators": ["dmidecode", "dmesg", "systemd-detect-virt", "lshw", "qemu", "virtualbox", "vmware", "grep"]
    },
    {
        "category": "Cgroup / Container",
        "indicators": ["cgroup"]
    },
    {
        "category": "Mounts",
        "indicators": ["mount", "umount"]
    },
    {
        "category": "Time Manipulation",
        "indicators": ["sleep", "cron", "at"]
    },
    {
        "category": "Process Manipulation",
        "indicators": ["killall"]
    },
    {
        "category": "Evidence Cleanup",
        "indicators": ["history", "rm", "shred"]
    }
]

# -------------------------
# 2) Alle relevanten Cowrie-Logs suchen
# -------------------------
def find_cowrie_logs(root_folder):
    cowrie_logs = []
    for dirpath, _, filenames in os.walk(root_folder):
        for f in filenames:
            if f.endswith('.json') and 'cowrie' in f:
                cowrie_logs.append(os.path.join(dirpath, f))
    return cowrie_logs

# -------------------------
# 3) Indikatoren zählen
# -------------------------
def analyze_logs(log_files):
    details = defaultdict(int)

    for log_file in log_files:
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        cmd = ''
                        if 'input' in entry:
                            cmd = entry['input'].lower()
                        elif 'command' in entry:
                            cmd = entry['command'].lower()
                        else:
                            continue

                        for cat in ANTI_SANDBOX_INDICATORS:
                            category = cat['category']
                            for indicator in cat['indicators']:
                                if indicator in cmd:
                                    details[(category, indicator)] += 1

                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Fehler bei {log_file}: {e}")

    return details

# -------------------------
# 4) Zusammenfassung nach Kategorie
# -------------------------
def summarize_by_category(details):
    summary = defaultdict(int)
    for (category, _), count in details.items():
        summary[category] += count
    return summary

# -------------------------
# 5) CSVs speichern
# -------------------------
def save_details_csv(details, output_path):
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Category', 'Indicator', 'Count'])
        for (category, indicator), count in sorted(details.items()):
            writer.writerow([category, indicator, count])

def save_summary_csv(summary, output_path):
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Category', 'TotalCount'])
        for category, total in sorted(summary.items()):
            writer.writerow([category, total])

# -------------------------
# 6) MAIN
# -------------------------
def main():
    if len(sys.argv) != 2:
        print("Verwendung: python3 extract_cowrie_anti_sandbox_indicators.py <Ordner>")
        sys.exit(1)

    input_folder = sys.argv[1]
    details_csv = os.path.join(input_folder, "cowrie_anti_sandbox_indicators.csv")
    summary_csv = os.path.join(input_folder, "cowrie_anti_sandbox_summary.csv")

    log_files = find_cowrie_logs(input_folder)
    print(f"Gefundene Cowrie-Logs: {len(log_files)}")

    details = analyze_logs(log_files)
    summary = summarize_by_category(details)

    save_details_csv(details, details_csv)
    save_summary_csv(summary, summary_csv)

    print(f"Details gespeichert unter: {details_csv}")
    print(f"Zusammenfassung gespeichert unter: {summary_csv}")

if __name__ == "__main__":
    main()

