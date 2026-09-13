import urllib.request
import json

try:
    r = urllib.request.urlopen('http://127.0.0.1:8000/api/scan', timeout=30)
    data = json.loads(r.read())
    s = data['summary']
    print(f"Scan OK: {s['total_scanned']} processes")
    print(f"Posture: {s['system_posture']}")
    print(f"Malicious: {s['malicious_count']}, Suspicious: {s['suspicious_count']}")
    procs = data['processes']
    top = sorted(procs, key=lambda x: x['threat_score'], reverse=True)[:5]
    print("\nTop 5:")
    for p in top:
        print(f"  {p['name']}: {p['threat_score']}% [{p['status']}]")
except Exception as e:
    print(f"ERROR: {e}")
