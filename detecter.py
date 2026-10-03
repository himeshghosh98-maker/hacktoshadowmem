import os
import pickle
import numpy as np
import memoryscanner

from technique_docs import SUBCLASS_ORDER, NUM_CLASSES, MALICIOUS_OFFSET, TECHNIQUE_DOCS

MODEL_PATH = "shadowmem_model.pkl"

# Legitimate JIT engines allocating RWX / unbacked memory
JIT_ENGINE_ALLOWLIST = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "code.exe",
    "discord.exe",
    "antigravity.exe",
    "slack.exe",
    "teams.exe",
    "electron.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
}

JIT_SCORE_CAP = 25

# Managed .NET runtimes. Name AND path must both match: malware frequently
# renames itself powershell.exe/dotnet.exe, so only system-installed hosts
# (under C:\Windows) are suppressed. Everything else gets fully scored.
MANAGED_RUNTIME_NAMES = {"powershell.exe", "pwsh.exe", "dotnet.exe"}
MANAGED_RUNTIME_PATH_PREFIXES = ("c:\\windows\\",)


def is_benign_managed_runtime(name: str, exe_path: str) -> bool:
    """True only for system-installed .NET hosts (name + path must both match)."""
    if name.lower().strip() not in MANAGED_RUNTIME_NAMES:
        return False
    exe = (exe_path or "").lower().replace("/", "\\")
    return exe.startswith(MANAGED_RUNTIME_PATH_PREFIXES)

def load_threat_model():
    """Loads the pre-trained Scikit-Learn Pipeline."""
    if not os.path.exists(MODEL_PATH):
        print(f"[!] Error: Model '{MODEL_PATH}' not found. Run 'train_model.py' first.")
        return None
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)

def run_detection():
    model = load_threat_model()
    if model is None:
        return

    print("[*] Inspecting active system processes for memory injection artifacts...")
    processes = memoryscanner.scan_all_processes()
    
    if not processes:
        print("[!] No inspectable processes found. Try running VS Code as Administrator.")
        return

    print(f"[*] Analyzing {len(processes)} processes through ShadowMem {NUM_CLASSES}-class classifier...\n")
    print(f"{'PID':<8} {'PROCESS NAME':<25} {'RWX':<6} {'UNBACKED':<10} {'THREAT SCORE':<14} {'VERDICT'}")
    print("-" * 90)

    threat_count = 0

    for proc in processes:
        name = proc.get("name", "Unknown")
        pname = name.lower().strip()
        exe_path = proc.get("exe", "") or ""
        rwx = int(proc.get("rwx_count", 0) or 0)
        unbacked = int(proc.get("unbacked_exec_count", 0) or 0)
        rwx_bytes = int(proc.get("total_rwx_bytes", 0) or 0)
        threads = int(proc.get("num_threads", 0) or 0)
        thr_unbacked = int(proc.get("thread_unbacked_start", 0) or 0)
        vad_anomaly = int(proc.get("vad_protection_anomaly", 0) or 0)

        is_jit = 1.0 if (pname in JIT_ENGINE_ALLOWLIST
                         or is_benign_managed_runtime(name, exe_path)) else 0.0

        # Feature order matches train_model.py FEATURE_NAMES:
        # [rwx_count, unbacked_exec_count, total_rwx_bytes, num_threads,
        #  thread_unbacked_start, is_known_jit_parent, vad_protection_anomaly]
        feature_vector = np.array([[
            float(rwx),
            float(unbacked),
            float(rwx_bytes),
            float(threads),
            float(thr_unbacked),
            is_jit,
            float(vad_anomaly),
        ]])

        try:
            proba = model.predict_proba(feature_vector)[0]
            # Sum of malicious class probabilities (indices 5+)
            threat_score = int(sum(proba[MALICIOUS_OFFSET:]) * 100)
            # Top malicious technique
            top_mal_idx = int(np.argmax(proba[MALICIOUS_OFFSET:])) + MALICIOUS_OFFSET
            top_technique = SUBCLASS_ORDER[top_mal_idx]
        except Exception:
            threat_score = 0
            top_technique = None

        # Apply JIT allowlist suppression
        if is_jit:
            threat_score = min(threat_score, JIT_SCORE_CAP)
            verdict = "[~] LEGITIMATE JIT"
            top_technique = None
        elif threat_score >= 70:
            verdict = "[!] MALICIOUS"
            threat_count += 1
        elif threat_score >= 35:
            verdict = "[?] SUSPICIOUS"
            threat_count += 1
        else:
            verdict = "[OK] CLEAN"
            top_technique = None

        # Technique tag for display
        tech_tag = ""
        if top_technique and top_technique in TECHNIQUE_DOCS:
            tech_tag = f"  [{TECHNIQUE_DOCS[top_technique]['display_name']}]"

        # Display any non-clean or allowlisted JIT processes
        if threat_score >= 35 or is_jit:
            print(f"{proc['pid']:<8} {name[:24]:<25} {rwx:<6} {unbacked:<10} {threat_score}%{'':<10} {verdict}{tech_tag}")

    if threat_count == 0:
        print("\n[+] Scan complete: No active fileless injections detected.")
    else:
        print(f"\n[!] Completed: Detected {threat_count} anomalous process(es).")

if __name__ == "__main__":
    run_detection()