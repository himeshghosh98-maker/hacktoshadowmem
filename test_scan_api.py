import urllib.request
import json
import time

url = 'http://127.0.0.1:8000/api/scan'
t0 = time.time()
try:
    r = urllib.request.urlopen(url, timeout=45)
    data = json.loads(r.read())
    elapsed = time.time() - t0
    s = data['summary']
    print(f"Scan OK: {s['total_scanned']} processes in {elapsed:.1f}s")
    print(f"Posture: {s['system_posture']}")
    print(f"Malicious: {s['malicious_count']}, Suspicious: {s['suspicious_count']}")
    procs = data['processes']
    top = sorted(procs, key=lambda x: x['threat_score'], reverse=True)[:5]
    print("\nTop 5:")
    for p in top:
        print(f"  {p['name']}: {p['threat_score']}% [{p['status']}]")
except Exception as e:
    elapsed = time.time() - t0
    print(f"ERROR after {elapsed:.1f}s: {e}")
