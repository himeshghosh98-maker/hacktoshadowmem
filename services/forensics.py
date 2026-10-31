"""
services/forensics.py
=====================
Forensic memory inspection, feature extraction, and ML threat evaluation service.
Encapsulates Win32 VirtualQueryEx memory scanning and scikit-learn model inference.
"""

import pickle
import threading
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
import numpy as np

from core.config import settings
from core.logging import logger
from technique_docs import (
    SUBCLASS_ORDER,
    NUM_CLASSES,
    MALICIOUS_OFFSET,
    TECHNIQUE_DOCS,
)

try:
    import memoryscanner
except ImportError:
    memoryscanner = None
    logger.warning(
        "memoryscanner module not found. Volatile memory scanning will be unavailable."
    )

# Cached scikit-learn model instance
_model = None

# Serialises full scans so manual requests and background ticker tasks do not conflict
_scan_lock = threading.Lock()

# Cached evaluated process telemetry from the most recent scan
_all_processes: List[Dict[str, Any]] = []


def get_cached_processes() -> List[Dict[str, Any]]:
    """Return the evaluated process list from the latest memory scan."""
    return _all_processes


def set_cached_processes(processes: List[Dict[str, Any]]) -> None:
    """Update the cached evaluated process list."""
    global _all_processes
    _all_processes = processes


def get_scan_lock() -> threading.Lock:
    """Return the global scan lock."""
    return _scan_lock


def load_model():
    """Lazily load and cache the scikit-learn model."""
    global _model
    if _model is not None:
        return _model

    model_path = Path(settings.model_path)
    if not model_path.exists():
        logger.warning("Model file '%s' not found. Predictions will use fallback heuristics.", model_path)
        return None

    try:
        with open(model_path, "rb") as f:
            _model = pickle.load(f)
        logger.info("Loaded ShadowMem model from %s", model_path)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load model from %s: %s", model_path, exc)
        _model = None
    return _model


def classify_score(score: float) -> str:
    """Convert numeric threat score (0-100) into a forensic status label."""
    if score >= settings.threshold_malicious:
        return "Malicious (Injected)"
    if score >= settings.threshold_suspicious:
        return "Suspicious"
    return "Clean"


def is_jit_engine(process_name: str) -> bool:
    """Check if process is in the known JIT engine allowlist."""
    return process_name.lower().strip() in settings.jit_engine_allowlist


def is_benign_managed_runtime(process_name: str, exe_path: str) -> bool:
    """True only for system-installed .NET hosts (name and path must both match)."""
    if process_name.lower().strip() not in settings.managed_runtime_names:
        return False
    exe = (exe_path or "").lower().replace("/", "\\")
    return exe.startswith(settings.managed_runtime_path_prefixes)


def evaluate_process(proc: Dict[str, Any], model: Any = None) -> Dict[str, Any]:
    """
    Evaluate a single process record and attach threat score + status.
    Uses 7-feature forensic alignment matching train_model.py.
    """
    name = str(proc.get("name", "unknown"))
    pid = proc.get("pid", -1)
    exe_path = str(proc.get("exe", "") or "")

    rwx_count = int(proc.get("rwx_count", 0) or 0)
    unbacked_exec_count = int(proc.get("unbacked_exec_count", 0) or 0)
    total_rwx_bytes = int(proc.get("total_rwx_bytes", 0) or 0)
    num_threads = int(proc.get("num_threads", 0) or 0)
    thread_unbacked_start = int(proc.get("thread_unbacked_start", 0) or 0)
    vad_anomaly = int(proc.get("vad_protection_anomaly", 0) or 0)

    jit_engine = is_jit_engine(name)
    managed_runtime = is_benign_managed_runtime(name, exe_path)
    is_jit_flag = 1.0 if (jit_engine or managed_runtime) else 0.0

    feature_vector = [[
        float(rwx_count),
        float(unbacked_exec_count),
        float(total_rwx_bytes),
        float(num_threads),
        float(thread_unbacked_start),
        is_jit_flag,
        float(vad_anomaly),
    ]]

    raw_score = 0.0
    model_available = model is not None

    top_technique: Optional[str] = None
    technique_doc: Optional[Dict[str, str]] = None

    if model_available:
        try:
            proba = model.predict_proba(feature_vector)[0]
            raw_score = float(sum(proba[MALICIOUS_OFFSET:])) * 100.0
            top_mal_idx = int(np.argmax(proba[MALICIOUS_OFFSET:])) + MALICIOUS_OFFSET
            top_technique = SUBCLASS_ORDER[top_mal_idx]
        except Exception as exc:  # noqa: BLE001
            logger.error("Model inference failed for pid=%s (%s): %s", pid, name, exc)
            raw_score = 0.0
            model_available = False
    else:
        heuristic = (
            (thread_unbacked_start * 35)
            + (vad_anomaly * 8)
            + (unbacked_exec_count * 3)
            + (total_rwx_bytes / (1024 * 1024))
        )
        raw_score = min(heuristic, 100.0)

    if jit_engine or managed_runtime:
        threat_score = min(raw_score, settings.jit_score_cap)
        status = "Legitimate JIT Engine"
    else:
        threat_score = max(0.0, min(raw_score, 100.0))
        status = classify_score(threat_score)
        if threat_score >= settings.threshold_suspicious and top_technique:
            technique_doc = TECHNIQUE_DOCS.get(top_technique)

    return {
        "pid": pid,
        "name": name,
        "exe": exe_path,
        "rwx_count": rwx_count,
        "unbacked_exec_count": unbacked_exec_count,
        "total_rwx_bytes": total_rwx_bytes,
        "allocated_kb": round(total_rwx_bytes / 1024.0, 2),
        "num_threads": num_threads,
        "thread_unbacked_start": thread_unbacked_start,
        "vad_protection_anomaly": vad_anomaly,
        "threat_score": round(threat_score, 2),
        "status": status,
        "jit_engine": jit_engine or managed_runtime,
        "model_used": model_available,
        "classification": technique_doc,
        "unbacked_regions": list(proc.get("unbacked_regions") or []),
    }


def execute_scan() -> List[Dict[str, Any]]:
    """Run one full memory scan across all processes, sorted by highest threat score."""
    if memoryscanner is None:
        raise RuntimeError("memoryscanner module is not available on this system.")
    raw_processes: List[Dict[str, Any]] = memoryscanner.scan_all_processes()
    model = load_model()
    evaluated = [evaluate_process(proc, model) for proc in raw_processes]
    evaluated.sort(key=lambda p: p["threat_score"], reverse=True)
    return evaluated


def process_key(proc: Dict[str, Any]) -> tuple:
    """Stable identity for diffing a process across scans (PIDs are reused)."""
    return (int(proc.get("pid") or -1), str(proc.get("name") or ""))


def diff_new_threats(
    previous: Dict[tuple, str],
    evaluated: List[Dict[str, Any]],
) -> List[Tuple[Dict[str, Any], Optional[str]]]:
    """Return (proc, previous_status) for processes newly in or transitioning threat states."""
    changes: List[Tuple[Dict[str, Any], Optional[str]]] = []
    for proc in evaluated:
        status = proc.get("status")
        if status not in settings.threat_statuses:
            continue
        prev_status = previous.get(process_key(proc))
        if prev_status != status:
            changes.append((proc, prev_status))
    return changes


def perform_scan_and_diff_locked() -> Tuple[List[Dict[str, Any]], List[Tuple[Dict[str, Any], Optional[str]]]]:
    """Inner scan and diff step. The caller MUST already hold the scan lock."""
    global _all_processes
    previous = {process_key(p): str(p.get("status") or "") for p in _all_processes}
    evaluated = execute_scan()
    _all_processes = evaluated
    changes = diff_new_threats(previous, evaluated)
    return evaluated, changes


def perform_scan_and_diff() -> Tuple[List[Dict[str, Any]], List[Tuple[Dict[str, Any], Optional[str]]]]:
    """Thread-safe scan and diff step."""
    with _scan_lock:
        return perform_scan_and_diff_locked()
