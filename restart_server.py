import subprocess, time, os, sys, urllib.request

def log(*a):
    print(*a, flush=True)

def listeners():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    pids = set()
    for line in out.splitlines():
        if ":8000" in line and "LISTENING" in line:
            parts = line.split()
            if parts:
                pids.add(parts[-1])
    return pids

log("step 1: listeners on 8000:", listeners())

# Kill whatever owns the port (it is by definition the stale server)
for pid in listeners():
    if pid != "0":
        k = subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, text=True)
        log("  kill", pid, "->", (k.stdout or k.stderr).strip())

time.sleep(2)
remaining = listeners()
log("step 2: listeners after kill:", remaining or "none")

# Start one fresh server
subprocess.Popen(
    ["python", "app.py"],
    creationflags=0x00000008,  # DETACHED_PROCESS
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    cwd=os.path.dirname(os.path.abspath(__file__)),
)
log("step 3: server spawned")

ok = False
body = ""
for _ in range(40):
    time.sleep(0.5)
    try:
        body = urllib.request.urlopen("http://127.0.0.1:8000/", timeout=2).read().decode("utf-8", "ignore")
        ok = True
        break
    except Exception:
        continue

log("step 4: server up:", ok)
if ok:
    checks = {
        "page bg #0A0E1A": "#0A0E1A" in body,
        "panel bg #151B2B": "#151B2B" in body,
        "border #252D42": "#252D42" in body,
        "primary text #F5F5F5": "#F5F5F5" in body,
        "muted text #8B93A8": "#8B93A8" in body,
        "lime kept #C6FF3D": "#C6FF3D" in body,
        "accent #4CAF50": "#4CAF50" in body,
        "red kept #DC2626": "#DC2626" in body,
        "amber kept #D97706": "#D97706" in body,
        "zebra #1C2438": "#1C2438" in body,
        "no light-mode palette": all(x not in body for x in ("#EFF2EF", "#F3F9F3", "#FDFEFD", "#1A1A1A")),
    }
    for k, v in checks.items():
        log(("PASS " if v else "FAIL ") + k)
    sys.exit(0 if all(checks.values()) else 2)
