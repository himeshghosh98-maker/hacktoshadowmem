"""
train_model.py — ShadowMem Advanced Training Pipeline
--------------------------------------------------------------------
Production-grade training pipeline for the ShadowMem fileless-malware /
memory-injection classifier.

Forensic feature space (7 features, in fixed order):
    0. rwx_count               - count of PAGE_EXECUTE_READWRITE regions
    1. unbacked_exec_count     - MEM_PRIVATE executable regions w/ no backing file
    2. total_rwx_bytes         - aggregate byte size of RWX allocations
    3. num_threads             - total active threads in the process
    4. thread_unbacked_start   - # threads whose start address resolves into
                                  unbacked/private memory (shellcode / CreateRemoteThread)
    5. is_known_jit_parent     - 1 if process is a known JIT-capable runtime
                                  (browser/Electron/Node/JVM), else 0
    6. vad_protection_anomaly  - count of VAD regions observed transitioning
                                  RW -> RX/RWX (VirtualProtect hook pattern)

Run:
    python train_model.py

Produces:
    shadowmem_model.pkl   -- a single sklearn Pipeline (scaler + classifier)
                             callable directly as model.predict_proba(X)
"""

import warnings
import pickle
import sys

import numpy as np
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)
from sklearn.inspection import permutation_importance

from core.config import settings
from technique_docs import SUBCLASS_ORDER, NUM_CLASSES, MALICIOUS_OFFSET

warnings.filterwarnings("ignore", category=UserWarning)

RNG = np.random.default_rng(seed=42)

FEATURE_NAMES = [
    "rwx_count",
    "unbacked_exec_count",
    "total_rwx_bytes",
    "num_threads",
    "thread_unbacked_start",
    "is_known_jit_parent",
    "vad_protection_anomaly",
]

# ==========================================================================
# 1. SYNTHETIC FORENSIC DATA GENERATION
# ==========================================================================
#
# Rationale: real EDR telemetry is proprietary/sensitive and rarely labeled
# at scale, so we hand-craft class-conditional generative distributions that
# encode known forensic behavior patterns for each population. Every class
# below is deliberately given *overlapping* support with its neighbors
# (rather than clean separability) because that's what real memory forensics
# looks like: a heavily multi-threaded Electron app and a hollowed process
# both have elevated thread counts and non-zero RWX pages. The classifier
# has to learn the *joint* pattern, not a single threshold.


def _clip_nonneg(arr):
    return np.clip(arr, 0, None)


def gen_benign_daemon(n):
    """
    Class 0a: Ordinary background system daemons / services.
    Forensic rationale: These almost never allocate RWX memory. Any exec
    regions are backed by mapped disk binaries (DLLs/.so). Thread counts are
    low-to-moderate. Occasional noisy false trace of 1 RWX page can occur
    from legitimate use of JIT-adjacent libraries (e.g., regex JIT in some
    runtimes), so we don't force it to exactly zero.
    """
    rwx_count = RNG.poisson(0.15, n)                                   # near-zero
    unbacked_exec = RNG.poisson(0.05, n)                                # near-zero
    total_rwx_bytes = _clip_nonneg(RNG.normal(500, 800, n)) * rwx_count # scales w/ rwx
    num_threads = _clip_nonneg(RNG.normal(8, 4, n)).round()
    thread_unbacked_start = np.zeros(n)                                 # essentially never
    is_jit_parent = np.zeros(n)
    vad_anomaly = RNG.poisson(0.02, n)                                  # noise floor
    labels = np.zeros(n, dtype=int)
    return rwx_count, unbacked_exec, total_rwx_bytes, num_threads, \
        thread_unbacked_start, is_jit_parent, vad_anomaly, labels


def gen_benign_gui_multithreaded(n):
    """
    Class 0b: Legitimate multi-threaded GUI applications (office suites,
    IDEs without heavy JIT, media players).
    Forensic rationale: Higher thread counts (UI thread, render thread,
    worker pool, background autosave/telemetry threads) but still no
    meaningful RWX/unbacked-exec footprint. This class exists specifically
    to prevent the model from learning "high thread count == malicious".
    """
    rwx_count = RNG.poisson(0.3, n)
    unbacked_exec = RNG.poisson(0.1, n)
    total_rwx_bytes = _clip_nonneg(RNG.normal(1500, 2000, n)) * (rwx_count > 0)
    num_threads = _clip_nonneg(RNG.normal(28, 10, n)).round()
    thread_unbacked_start = np.zeros(n)
    is_jit_parent = RNG.binomial(1, 0.05, n)  # a few embed scripting engines
    vad_anomaly = RNG.poisson(0.05, n)
    labels = np.zeros(n, dtype=int)
    return rwx_count, unbacked_exec, total_rwx_bytes, num_threads, \
        thread_unbacked_start, is_jit_parent, vad_anomaly, labels


def gen_benign_jit_engine(n):
    """
    Class 0c: Legitimate JIT-compiling runtimes (Chromium/V8, Electron,
    Node.js, JVM, .NET RyuJIT hosts).
    Forensic rationale: This is THE classic false-positive source for naive
    RWX-based detectors. These processes legitimately hold a meaningful
    number of RWX pages (JIT code cache) and even some "unbacked" executable
    regions (JIT-emitted native code has no backing file by design). The key
    forensic distinguisher from real injection is that VAD protection
    *transitions* are typically RW->RX (write-then-seal per code page, done
    incrementally and in volume) rather than a small number of large,
    late-stage RW->RWX flips, and thread-start-in-unbacked-memory stays low
    because JIT code is invoked via call from managed frames, not via
    freshly spawned remote threads pointing directly at shellcode.
    """
    rwx_count = _clip_nonneg(RNG.normal(18, 8, n)).round()
    unbacked_exec = _clip_nonneg(RNG.normal(9, 5, n)).round()
    total_rwx_bytes = _clip_nonneg(RNG.normal(4_000_000, 2_500_000, n))  # several MB of JIT cache
    num_threads = _clip_nonneg(RNG.normal(35, 15, n)).round()
    # Small residual chance of a start pointer landing in unbacked memory
    # (e.g. a JIT trampoline) -- kept low but nonzero for realism.
    thread_unbacked_start = RNG.poisson(0.4, n)
    is_jit_parent = np.ones(n)
    vad_anomaly = _clip_nonneg(RNG.normal(3, 2, n)).round()  # frequent small RW->RX flips
    labels = np.zeros(n, dtype=int)
    return rwx_count, unbacked_exec, total_rwx_bytes, num_threads, \
        thread_unbacked_start, is_jit_parent, vad_anomaly, labels


def gen_benign_managed_runtime(n):
    """
    Class 0d: Managed .NET runtimes (powershell.exe, pwsh.exe, dotnet.exe).
    Forensic rationale: The .NET RyuJIT compiler produces a large private
    executable code heap that looks statistically like injection to any
    RWX/unbacked counter: live Windows hosts routinely show ~20-30 private
    executable regions per PowerShell process, many RW->RX flipped during
    tiered compilation. This class is modeled directly from observed live
    telemetry (23 RWX / 23 unbacked regions on a stock Windows 11 desktop)
    so the classifier stops saturating at ~99 on every .NET host.
    Key distinguishers from real injection remain: near-zero thread starts
    in unbacked memory (managed threads enter via runtime stubs in mapped
    images), and VAD flips are numerous but small and incremental.
    """
    rwx_count = _clip_nonneg(RNG.normal(10, 5, n)).round()
    unbacked_exec = _clip_nonneg(RNG.normal(25, 10, n)).round()
    total_rwx_bytes = _clip_nonneg(RNG.normal(2_000_000, 1_200_000, n))
    num_threads = _clip_nonneg(RNG.normal(20, 8, n)).round()
    thread_unbacked_start = RNG.poisson(0.2, n)
    is_jit_parent = np.ones(n)
    vad_anomaly = _clip_nonneg(RNG.normal(4, 2, n)).round()
    labels = np.zeros(n, dtype=int)
    return rwx_count, unbacked_exec, total_rwx_bytes, num_threads, \
        thread_unbacked_start, is_jit_parent, vad_anomaly, labels


def gen_benign_desktop_app(n):
    """
    Class 0e: Real-world desktop apps OUTSIDE the JIT allowlist (GPU vendor
    utilities, WebView2 hosts, scripting runtimes, Electron-adjacent tools,
    endpoint agents).
    Forensic rationale: modeled directly from live telemetry on a stock
    Windows 11 desktop, where the observed profiles are heavy-tailed:
      RadeonSoftware.exe   60 unbacked / 59 VAD flips / 69 threads
      bun-baseline.exe     12 RWX / 13 unbacked / 6.9 MB
      msedgewebview2.exe   up to 26 MB RWX, 1-7 unbacked
      python.exe / helpers 1-2 RWX, 1-2 threads, tiny footprint
    The one common benign signature: ZERO shellcode-style thread starts
    (thread_unbacked_start = 0 across every observed instance). VAD flips
    and unbacked regions co-occur in bulk for bursty apps because legit
    CFG/thunk pages are flipped in batches during startup - unlike the
    small late-stage flip counts of injection.
    Mixture: ~30% tiny utilities (1-3 regions, 4 KB-300 KB, few threads).
    Dense coverage here is critical because this zone statistically
    overlaps the quiet-beacon shellcode profile; the forensic tie-breaker
    is thread_unbacked_start, which is 0 on every observed benign process
    but ~1 for beacons. ~40% moderate / ~30% bursty capture the heavy tail.
    """
    roll = RNG.random(n)
    burst = roll >= 0.85
    tiny = (roll >= 0.45) & ~burst

    unbacked_tiny = _clip_nonneg(RNG.normal(1.5, 1.0, n)).round()
    unbacked_moderate = _clip_nonneg(RNG.normal(3, 2.5, n)).round()
    unbacked_burst = _clip_nonneg(RNG.normal(30, 15, n)).round()
    unbacked_exec = np.where(
        burst, unbacked_burst, np.where(tiny, unbacked_tiny, unbacked_moderate)
    )

    rwx_count = RNG.poisson(0.4 * unbacked_exec + 0.3)

    bytes_present = RNG.random(n) < 0.4
    # Tiny utilities legitimately carry just 4 KB .. ~300 KB of RWX
    # (AacAmbientLighting 4 KB, python.exe 135 KB) -- well below the
    # beacon-sized 45 KB+ range naive models treat as suspicious.
    bytes_tiny = _clip_nonneg(RNG.lognormal(mean=10.5, sigma=2.5, size=n))
    bytes_large = _clip_nonneg(RNG.lognormal(mean=13.5, sigma=2.2, size=n))
    total_rwx_bytes = np.where(
        bytes_present & (rwx_count > 0),
        np.where(tiny, bytes_tiny, bytes_large),
        0.0,
    )

    # Flat 1-10 spread: tiny utilities ship with as few as 1-2 threads
    # (python.exe observed at 2), which no unimodal distribution covers well.
    threads_tiny = RNG.integers(1, 11, n).astype(float)
    threads_general = _clip_nonneg(RNG.normal(20, 15, n)).round()
    num_threads = np.where(tiny, threads_tiny, threads_general)
    thread_unbacked_start = RNG.poisson(0.02, n)   # observed: zero everywhere
    is_jit_parent = np.zeros(n)                    # NOT allowlisted by design

    vad_moderate = RNG.poisson(1.0, n)
    vad_burst = _clip_nonneg(unbacked_exec * RNG.uniform(0.7, 1.0, n)).round()
    vad_anomaly = np.where(burst, vad_burst, vad_moderate)

    labels = np.zeros(n, dtype=int)
    return rwx_count, unbacked_exec, total_rwx_bytes, num_threads, \
        thread_unbacked_start, is_jit_parent, vad_anomaly, labels


def gen_malicious_reflective_dll(n):
    """
    Class 1a: Reflective DLL injection.
    Forensic rationale: A DLL image is manually mapped into memory without
    going through the loader, so its sections are MEM_PRIVATE rather than
    MEM_IMAGE, producing unbacked executable regions and typically one
    late-stage RW->RWX (or RW->RX) protection flip once the loader manually
    resolves imports and finalizes section protections. Thread counts stay
    close to the host process baseline (injected into an existing process),
    but a new thread is often created to invoke DllMain / the reflective
    loader stub, and its start address lands in unbacked memory.
    """
    rwx_count = _clip_nonneg(RNG.normal(3, 2, n)).round()
    unbacked_exec = _clip_nonneg(RNG.normal(4, 2, n)).round()
    total_rwx_bytes = _clip_nonneg(RNG.normal(180_000, 120_000, n))  # DLL-sized image
    num_threads = _clip_nonneg(RNG.normal(14, 6, n)).round()
    thread_unbacked_start = _clip_nonneg(RNG.normal(1.4, 0.8, n)).round()
    is_jit_parent = RNG.binomial(1, 0.03, n)  # rarely coincides w/ a JIT host
    vad_anomaly = _clip_nonneg(RNG.normal(1.8, 1.0, n)).round()
    labels = np.ones(n, dtype=int)
    return rwx_count, unbacked_exec, total_rwx_bytes, num_threads, \
        thread_unbacked_start, is_jit_parent, vad_anomaly, labels


def gen_malicious_process_hollowing(n):
    """
    Class 1b: Process hollowing (unmap legit image, write malicious payload,
    resume in hijacked context).
    Forensic rationale: The original image section gets unmapped and
    replaced, so the executable region backing a *named* process image is
    now MEM_PRIVATE — a strong unbacked-exec signal. Because the payload
    (unpacked PE) is written and protected in stages, we see a larger burst
    of RW->RX/RWX VAD transitions than reflective injection. RWX bytes are
    frequently large because the whole hollowed payload is unpacked in
    memory. Thread counts stay near-normal since it reuses the original
    process's primary thread (resumed, not newly spawned), so
    thread_unbacked_start is often modest despite heavy unbacked exec.
    """
    rwx_count = _clip_nonneg(RNG.normal(6, 3, n)).round()
    unbacked_exec = _clip_nonneg(RNG.normal(7, 3, n)).round()
    total_rwx_bytes = _clip_nonneg(RNG.normal(900_000, 500_000, n))  # full PE unpack
    num_threads = _clip_nonneg(RNG.normal(6, 3, n)).round()  # resumes primary thread
    thread_unbacked_start = _clip_nonneg(RNG.normal(0.8, 0.6, n)).round()
    is_jit_parent = np.zeros(n)
    vad_anomaly = _clip_nonneg(RNG.normal(5, 2.5, n)).round()  # multi-stage rewrite
    labels = np.ones(n, dtype=int)
    return rwx_count, unbacked_exec, total_rwx_bytes, num_threads, \
        thread_unbacked_start, is_jit_parent, vad_anomaly, labels


def gen_malicious_shellcode_beacon(n):
    """
    Class 1c: Basic shellcode / C2 beacon (e.g., dropped via a macro or
    exploit, staged directly in an anonymous RWX region).
    Forensic rationale: Small footprint by design — a beacon is often a few
    KB to low hundreds of KB. It's typically committed directly as RWX
    (no need to hide the transition since the loader is unsophisticated),
    so unbacked_exec and rwx_count are both small but strongly correlated,
    and a single new thread is created pointing directly at the shellcode
    buffer (thread_unbacked_start ~ 1). VAD anomaly count is low since there
    is often no RW->RX transition at all -- it's allocated RWX from the
    start (a distinguishable but not universal signal, hence noise below).
    """
    rwx_count = _clip_nonneg(RNG.normal(1.5, 1.0, n)).round()
    unbacked_exec = _clip_nonneg(RNG.normal(1.3, 0.9, n)).round()
    total_rwx_bytes = _clip_nonneg(RNG.normal(45_000, 40_000, n))  # small beacon stub
    num_threads = _clip_nonneg(RNG.normal(9, 5, n)).round()
    # The beacon's worker thread points directly at the shellcode buffer,
    # so >=1 unbacked thread start is inherent to the technique; rare
    # sampling dips to 0 would blur the quiet-utility overlap zone.
    thread_unbacked_start = np.maximum(
        1.0, _clip_nonneg(RNG.normal(1.1, 0.5, n)).round()
    )
    is_jit_parent = np.zeros(n)
    vad_anomaly = RNG.poisson(0.3, n)  # often none; sometimes one late flip
    labels = np.ones(n, dtype=int)
    return rwx_count, unbacked_exec, total_rwx_bytes, num_threads, \
        thread_unbacked_start, is_jit_parent, vad_anomaly, labels


def gen_malicious_thread_hijack(n):
    """
    Class 1d: Thread execution hijacking (SetThreadContext / APC injection
    into an *existing* thread rather than creating a new one).
    Forensic rationale: Because no new thread is created, thread_unbacked_start
    counted at new-thread-creation time can stay at 0 — this is the class most
    likely to evade a naive "new thread into shellcode" heuristic, which is
    exactly why it needs to be represented so the model leans on VAD
    protection anomalies and unbacked exec regions instead. RWX footprint is
    small (just enough for the hijacked gadget stub) and total thread count is
    unchanged from baseline.
    """
    rwx_count = _clip_nonneg(RNG.normal(1.1, 0.7, n)).round()
    unbacked_exec = _clip_nonneg(RNG.normal(1.4, 0.9, n)).round()
    total_rwx_bytes = _clip_nonneg(RNG.normal(20_000, 15_000, n))
    num_threads = _clip_nonneg(RNG.normal(11, 5, n)).round()
    thread_unbacked_start = RNG.poisson(0.2, n)  # low -- existing thread reused
    is_jit_parent = np.zeros(n)
    # ~3.2 VAD flips is this technique's dominant residual signal; keeping
    # it clearly above the quiet-utility noise floor (Poisson(1)) separates
    # hijack from the dense benign mass around 0-2 flips.
    vad_anomaly = _clip_nonneg(RNG.normal(3.2, 1.2, n)).round()  # the dominant signal here
    labels = np.ones(n, dtype=int)
    return rwx_count, unbacked_exec, total_rwx_bytes, num_threads, \
        thread_unbacked_start, is_jit_parent, vad_anomaly, labels


def build_synthetic_dataset(n_total=6000):
    """
    Assemble the full dataset from all class generators, with realistic
    class imbalance: injection techniques are rare events relative to the
    benign population on a real host, so we weight ~78% benign / ~22%
    malicious overall, split further across sub-classes. `class_weight`
    balancing at train time (not oversampling) is used to handle this,
    matching real-world SOC / EDR base rates.
    """
    proportions = {
        "benign_daemon": 0.26,
        "benign_gui": 0.17,
        "benign_jit": 0.15,
        "benign_managed": 0.10,
        "benign_desktop": 0.14,
        "mal_reflective": 0.06,
        "mal_hollow": 0.05,
        "mal_shellcode": 0.04,
        "mal_hijack": 0.03,
    }
    generators = {
        "benign_daemon": gen_benign_daemon,
        "benign_gui": gen_benign_gui_multithreaded,
        "benign_jit": gen_benign_jit_engine,
        "benign_managed": gen_benign_managed_runtime,
        "benign_desktop": gen_benign_desktop_app,
        "mal_reflective": gen_malicious_reflective_dll,
        "mal_hollow": gen_malicious_process_hollowing,
        "mal_shellcode": gen_malicious_shellcode_beacon,
        "mal_hijack": gen_malicious_thread_hijack,
    }

    rows = []
    class_labels = []
    for name, frac in proportions.items():
        n = int(round(n_total * frac))
        rwx, unbacked, total_bytes, threads, thr_unbacked, jit_flag, vad, labels = generators[name](n)
        block = np.column_stack([rwx, unbacked, total_bytes, threads, thr_unbacked, jit_flag, vad])
        rows.append(block)
        class_labels.append(np.full(n, name))

    X = np.vstack(rows)
    subclass = np.concatenate(class_labels)
    # Multi-class integer labels — SUBCLASS_ORDER defines the mapping.
    subclass_to_idx = {name: i for i, name in enumerate(SUBCLASS_ORDER)}
    y = np.array([subclass_to_idx[s] for s in subclass], dtype=int)

    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["subclass"] = subclass
    df["label"] = y
    # Real telemetry has measurement jitter (race conditions while walking
    # VADs, transient thread creation/teardown during the scan window).
    # Add small Gaussian jitter to continuous features and occasional
    # single-count flips to integer features so classes are NOT perfectly
    # separable -- this keeps evaluation metrics honest.
    noise_cols_continuous = ["total_rwx_bytes"]
    for col in noise_cols_continuous:
        jitter = RNG.normal(0, df[col].std() * 0.08, len(df))
        df[col] = _clip_nonneg(df[col] + jitter)

    noise_cols_count = ["rwx_count", "unbacked_exec_count", "num_threads",
                         "thread_unbacked_start", "vad_protection_anomaly"]
    for col in noise_cols_count:
        flip = RNG.binomial(1, 0.06, len(df)) * RNG.choice([-1, 1], len(df))
        df[col] = _clip_nonneg(df[col] + flip)

    # Occasional mislabeled-looking overlap cases: rare "aggressive JIT"
    # benign outliers that creep into the suspicious range, and rare
    # "quiet" malware samples that under-express their signal (e.g., a
    # beacon that hasn't triggered its second-stage yet at scan time).
    aggressive_jit_idx = df[df["subclass"] == "benign_jit"].sample(frac=0.05, random_state=1).index
    df.loc[aggressive_jit_idx, "vad_protection_anomaly"] += RNG.integers(3, 6, len(aggressive_jit_idx))
    df.loc[aggressive_jit_idx, "unbacked_exec_count"] += RNG.integers(5, 10, len(aggressive_jit_idx))

    quiet_malware_idx = df[df["label"] == 1].sample(frac=0.08, random_state=2).index
    df.loc[quiet_malware_idx, "rwx_count"] = _clip_nonneg(df.loc[quiet_malware_idx, "rwx_count"] * 0.3)
    df.loc[quiet_malware_idx, "unbacked_exec_count"] = _clip_nonneg(
        df.loc[quiet_malware_idx, "unbacked_exec_count"] * 0.3
    )

    df["is_known_jit_parent"] = df["is_known_jit_parent"].clip(0, 1)

    # Recompute label after all noise/augmentation passes
    df["label"] = df["subclass"].map(subclass_to_idx).astype(int)

    return df.sample(frac=1.0, random_state=7).reset_index(drop=True)  # shuffle


# ==========================================================================
# 2. PIPELINE CONSTRUCTION
# ==========================================================================

def build_pipeline(model_type="hgb"):
    """
    RobustScaler is used (rather than StandardScaler) because total_rwx_bytes
    and total byte counts are heavy-tailed with genuine extreme outliers
    (a hollowed process unpacking a multi-MB payload vs. a beacon at a few
    KB) -- RobustScaler's use of median/IQR keeps those outliers from
    dominating distance- and gradient-based learning the way a mean/std
    scaler would.
    """
    if model_type == "hgb":
        clf = HistGradientBoostingClassifier(
            max_iter=400,
            max_depth=6,
            learning_rate=0.06,
            l2_regularization=0.5,
            class_weight="balanced",
            random_state=42,
        )
    else:
        clf = RandomForestClassifier(
            n_estimators=600,
            max_depth=14,
            min_samples_leaf=3,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=42,
        )

    pipeline = Pipeline(steps=[
        ("scaler", RobustScaler()),
        ("classifier", clf),
    ])
    return pipeline


# ==========================================================================
# 3. TRAINING + CROSS-VALIDATION + EVALUATION
# ==========================================================================

def evaluate_cv(pipeline, X, y, n_splits=5):
    print(f"\n{'='*70}\nSTRATIFIED {n_splits}-FOLD CROSS-VALIDATION\n{'='*70}")
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    y_pred = cross_val_predict(pipeline, X, y, cv=skf, method="predict", n_jobs=-1)
    y_proba_all = cross_val_predict(pipeline, X, y, cv=skf, method="predict_proba", n_jobs=-1)

    acc = accuracy_score(y, y_pred)
    bal_acc = balanced_accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred, average="weighted")
    rec = recall_score(y, y_pred, average="weighted")
    f1 = f1_score(y, y_pred, average="weighted")
    auc = roc_auc_score(y, y_proba_all, multi_class="ovr", average="weighted")

    print(f"Accuracy           : {acc:.4f}")
    print(f"Balanced Accuracy  : {bal_acc:.4f}")
    print(f"Precision (wt)     : {prec:.4f}")
    print(f"Recall (wt)        : {rec:.4f}")
    print(f"F1 (wt)            : {f1:.4f}")
    print(f"ROC-AUC (ovr, wt)  : {auc:.4f}")

    cm = confusion_matrix(y, y_pred)
    print(f"\nConfusion Matrix ({NUM_CLASSES}x{NUM_CLASSES}, rows=actual, cols=predicted):")
    print(cm)

    # Binary aggregate metrics (benign vs all-malicious) for continuity
    y_bin = (y >= MALICIOUS_OFFSET).astype(int)
    y_pred_bin = (y_pred >= MALICIOUS_OFFSET).astype(int)
    y_mal_proba = y_proba_all[:, MALICIOUS_OFFSET:].sum(axis=1)
    print(f"\nAggregate (benign vs malicious): accuracy={accuracy_score(y_bin, y_pred_bin):.4f}  "
          f"roc_auc={roc_auc_score(y_bin, y_mal_proba):.4f}")

    print("\nDetailed classification report:")
    print(classification_report(y, y_pred, target_names=SUBCLASS_ORDER))

    return {"accuracy": acc, "balanced_accuracy": bal_acc, "precision": prec,
            "recall": rec, "f1": f1, "roc_auc": auc, "confusion_matrix": cm}


def report_feature_importance(pipeline, X_test, y_test):
    print(f"\n{'='*70}\nFEATURE IMPORTANCE (permutation, on held-out test split)\n{'='*70}")
    result = permutation_importance(
        pipeline, X_test, y_test, n_repeats=20, random_state=42, n_jobs=-1
    )
    order = result.importances_mean.argsort()[::-1]
    for rank, idx in enumerate(order, start=1):
        print(f"{rank}. {FEATURE_NAMES[idx]:<24} "
              f"mean_importance={result.importances_mean[idx]:.4f}  "
              f"std={result.importances_std[idx]:.4f}")


def main():
    print("Generating synthetic forensic dataset...")
    df = build_synthetic_dataset(n_total=6000)
    print(f"Dataset shape: {df.shape}")
    print(f"\nClass balance ({NUM_CLASSES}-class):")
    for name, count in df["label"].value_counts().sort_index().items():
        print(f"  {SUBCLASS_ORDER[name]:<20} {count:>5}  ({count/len(df)*100:.1f}%)")

    X = df[FEATURE_NAMES].values
    y = df["label"].values

    pipeline = build_pipeline(model_type="hgb")

    # 5-fold CV for a leakage-safe generalization estimate on the full data
    evaluate_cv(pipeline, X, y, n_splits=5)

    # Separate held-out split purely for permutation feature importance,
    # so importance isn't computed on data the final fitted model has seen
    # during its own training pass below.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    holdout_pipeline = build_pipeline(model_type="hgb")
    holdout_pipeline.fit(X_train, y_train)
    report_feature_importance(holdout_pipeline, X_test, y_test)

    # ---- Final production fit on ALL available data ----
    # Once CV has validated generalization and importance has been
    # inspected on the held-out split, we refit on the complete dataset so
    # the shipped artifact benefits from every available sample.
    print(f"\n{'='*70}\nFITTING FINAL PRODUCTION PIPELINE ON FULL DATASET\n{'='*70}")
    final_pipeline = build_pipeline(model_type="hgb")
    final_pipeline.fit(X, y)

    # ---- Pre-save sanity gate: live-machine canary profiles ----
    # Encode the real-world profiles that motivated this training run.
    # The model must separate them BEFORE the artifact is allowed to replace
    # the previous pickle; a failure aborts with the old model left intact.
    # Each canary: (name, feature_vector, score_bound, direction, expected_technique_or_None)
    canaries = [
        ("powershell_like",    [10, 25, 2_000_000, 20, 0, 1, 4], 35.0, "below", None),
        ("radeon_like",        [1, 60, 65_536,     69, 0, 0, 59], 35.0, "below", None),
        ("bun_like",           [12, 13, 6_889_472, 22, 0, 0, 0], 35.0, "below", None),
        ("python_like",        [2, 2, 135_168,     2, 0, 0, 0], 50.0, "below", None),
        ("lighting_util_like", [1, 1, 4_096,      12, 0, 0, 1], 50.0, "below", None),
        ("shellcode_beacon",   [2, 2, 50_000,      9, 1, 0, 0], 70.0, "above", "mal_shellcode"),
        ("reflective_dll",     [3, 4, 180_000,    14, 1, 0, 2], 70.0, "above", "mal_reflective"),
    ]
    print(f"\n{'='*70}\nSANITY GATE: CANARY PROFILES (multi-class)\n{'='*70}")
    gate_ok = True
    for label, feats, bound, direction, expected_tech in canaries:
        vec = np.array([feats], dtype=float)
        proba = final_pipeline.predict_proba(vec)[0]
        mal_score = float(sum(proba[MALICIOUS_OFFSET:])) * 100.0
        score_ok = mal_score < bound if direction == "below" else mal_score > bound
        # When an expected technique is specified, verify it is the top malicious class
        top_mal_idx = int(np.argmax(proba[MALICIOUS_OFFSET:])) + MALICIOUS_OFFSET
        top_mal_class = SUBCLASS_ORDER[top_mal_idx]
        tech_ok = (expected_tech is None) or (top_mal_class == expected_tech)
        ok = score_ok and tech_ok
        gate_ok &= ok
        cmp_txt = "<" if direction == "below" else ">"
        tech_note = f"  top={top_mal_class}" if expected_tech else ""
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:<22} score={mal_score:6.2f}  "
              f"(req {cmp_txt} {bound:.0f}){tech_note}")
    if not gate_ok:
        print("\n[!] Sanity gate FAILED -- refusing to overwrite the existing model.")
        sys.exit(1)

    print(f"\nModel output: {NUM_CLASSES}-class classifier, classes={SUBCLASS_ORDER}")

    output_path = settings.model_path
    with open(output_path, "wb") as f:
        pickle.dump(final_pipeline, f)

    print(f"\nSaved production pipeline (scaler + classifier bundled) to '{output_path}'")
    print(f"Feature order expected by predict_proba(): {FEATURE_NAMES}")
    print("\nDone.")


if __name__ == "__main__":
    main()