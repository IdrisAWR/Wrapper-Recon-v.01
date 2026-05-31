import json, os

path = './test_output'
files = os.listdir(path)

json_file = [f for f in files if f.endswith('.json')][0]
with open(os.path.join(path, json_file), encoding='utf-8') as f:
    data = json.load(f)

s = data['statistics']
print("=== STATISTIK LAPORAN ===")
print("Target domain    :", data['meta']['target_domain'])
print("Scan timestamp   :", data['meta']['scan_timestamp'])
print("Total subdomain  :", s['total_subdomains'])
print("Resolved (DNS)   :", s['resolved_subdomains'])
print("Live (HTTP)      :", s['live_hosts'])
print("Dead             :", s['dead_hosts'])
print("Live rate        :", s['live_rate_percent'], "%")
print("Status codes     :", s['status_code_distribution'])
print("Servers (top5)   :", dict(list(s['server_distribution'].items())[:5]))
print("Interesting hosts:", len(s['interesting_hosts']))
print()
print("=== SAMPLE INTERESTING HOST ===")
if s['interesting_hosts']:
    print(json.dumps(s['interesting_hosts'][0], indent=2, ensure_ascii=False))
print()
print("=== SAMPLE SUBDOMAIN ENTRY ===")
if data['subdomains']:
    print(json.dumps(data['subdomains'][0], indent=2, ensure_ascii=False))
