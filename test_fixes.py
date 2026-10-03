import urllib.request
import json

# Test scan
print("=== Test Scan ===")
r = urllib.request.urlopen('http://127.0.0.1:8000/api/scan', timeout=60)
data = json.loads(r.read())
print(f"Scan: {data['summary']['total_scanned']} processes")

# Test isolate on a nonexistent PID (should fail gracefully, not crash)
print("\n=== Test Isolate (nonexistent PID 99999) ===")
try:
    req = urllib.request.Request('http://127.0.0.1:8000/api/isolate/99999', method='POST')
    r = urllib.request.urlopen(req, timeout=5)
    result = json.loads(r.read())
    print(f"Result: {result}")
except urllib.error.HTTPError as e:
    body = json.loads(e.read())
    print(f"HTTP {e.code}: {body.get('error', body)}")

# Test resume on nonexistent PID
print("\n=== Test Resume (nonexistent PID 99999) ===")
try:
    req = urllib.request.Request('http://127.0.0.1:8000/api/resume/99999', method='POST')
    r = urllib.request.urlopen(req, timeout=5)
    result = json.loads(r.read())
    print(f"Result: {result}")
except urllib.error.HTTPError as e:
    body = json.loads(e.read())
    print(f"HTTP {e.code}: {body.get('error', body)}")

# Test dashboard HTML loads
print("\n=== Test Dashboard ===")
r = urllib.request.urlopen('http://127.0.0.1:8000/', timeout=5)
html = r.read().decode()
# Check for the duplicate let isolatedPids issue
count = html.count('let isolatedPids')
print(f"Dashboard HTML: {len(html)} bytes, 'let isolatedPids' occurrences: {count}")
print(f"Has scanBtn handler: {'scanBtn.addEventListener' in html}")
