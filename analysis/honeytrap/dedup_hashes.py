import csv
from collections import defaultdict

input_file = 'honeytrap_infos.csv'         # your input CSV
output_file = 'deduplicated_sorted_infos.csv'    # output file

# Dictionary to count hash pairs
hash_counts = defaultdict(int)

# Read and count
with open(input_file, 'r', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        key = (row['RemoteIP'], row['RemotePort'], row['MD5'], row['SHA512'], row['Protocol'])
        hash_counts[key] += 1

# Sort by count descending
sorted_hashes = sorted(hash_counts.items(), key=lambda item: item[1], reverse=True)

# Write output CSV
with open(output_file, 'w', newline='', encoding='utf-8') as f:
    fieldnames = ['RemoteIP', 'RemotePort', 'MD5', 'SHA512', 'Protocol', 'Count']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()

    for (remote_ip, remote_port, md5, sha512, protocol), count in sorted_hashes:
        writer.writerow({'RemoteIP': remote_ip, 'RemotePort': remote_port, 'MD5': md5, 'SHA512': sha512, 'Protocol': protocol, 'Count': count})

print(f"✅ Done! Wrote {len(sorted_hashes)} unique sorted hashes to {output_file}")

