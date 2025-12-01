import csv
import json

# Input paths
json_file = 'urlhaus_full.json'     # your JSON file
csv_file = 'deduplicated_sorted_ips.csv'         # your CSV with RemoteIP and Count
output_file = 'urlhaus_matches.csv'  # new CSV with added columns

# Step 1: Load and flatten the JSON
ip_to_urlinfo = {}

with open(json_file, 'r', encoding='utf-8') as f:
    data = json.load(f)

    for entry_id, entries in data.items():
        for entry in entries:
            url = entry.get('url', '')
            tags = entry.get('tags', [])
            if url.startswith('http'):
                # extract IP from URL (assuming format like http://IP/...)
                try:
                    host_port = url.split('//')[1].split('/')[0]
                    ip = host_port.split(':')[0]

                    ip_to_urlinfo[ip] = {
                        'url': url,
                        'tags': tags
                    }
                except IndexError:
                    continue

# Step 2: Read the CSV and enrich with URL and tags
with open(csv_file, 'r', newline='', encoding='utf-8') as csv_in, \
     open(output_file, 'w', newline='', encoding='utf-8') as csv_out:

    reader = csv.DictReader(csv_in)
    fieldnames = reader.fieldnames + ['MatchedURL', 'Tags']
    writer = csv.DictWriter(csv_out, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        ip = row['RemoteIP']

        match = ip_to_urlinfo.get(ip)

        if match:
            row['MatchedURL'] = match['url']
            row['Tags'] = ','.join(match['tags'])
            writer.writerow(row)
        #else:
        #    row['MatchedURL'] = ''
        #    row['Tags'] = ''

        

print(f"✅ Done! Output written to {output_file}")

