"""
services
========
Domain business logic and operating system service abstractions for ShadowMem.
"""

from services.forensics import (
    execute_scan,
    evaluate_process,
    load_model,
    classify_score,
    is_jit_engine,
    is_benign_managed_runtime,
    get_cached_processes,
    set_cached_processes,
    get_scan_lock,
    perform_scan_and_diff,
    perform_scan_and_diff_locked,
)
from services.containment import (
    isolate_process,
    resume_process,
    get_audit_trail,
    record_audit,
    refresh_isolated_set,
)
from services.alerts import (
    ws_manager,
    ConnectionManager,
    threat_alert_frame,
    build_memory_map,
    broadcast_scan_updates,
    ensure_scan_ticker,
    scan_ticker_loop,
    simulate_attack_alert,
    SIMULATE_SCENARIOS,
    SIMULATE_SEVERITIES,
    SIMULATE_TARGETS,
)
from services.sandbox import (
    check_wsl_available,
    check_docker_ready,
    get_sandbox_health,
    submit_sample_job,
    get_job_result,
    list_jobs,
)
from services.supply_chain import (
    check_pefile_available,
    compute_sha256,
    is_binary_signed,
    is_suspicious_filepath,
    inspect_module_file,
    scan_process_modules,
    scan_directory_modules,
    get_supply_chain_health,
)

__all__ = [
    # Forensics
    "execute_scan",
    "evaluate_process",
    "load_model",
    "classify_score",
    "is_jit_engine",
    "is_benign_managed_runtime",
    "get_cached_processes",
    "set_cached_processes",
    "get_scan_lock",
    "perform_scan_and_diff",
    "perform_scan_and_diff_locked",
    # Containment
    "isolate_process",
    "resume_process",
    "get_audit_trail",
    "record_audit",
    "refresh_isolated_set",
    # Alerts & Streaming
    "ws_manager",
    "ConnectionManager",
    "threat_alert_frame",
    "build_memory_map",
    "broadcast_scan_updates",
    "ensure_scan_ticker",
    "scan_ticker_loop",
    "simulate_attack_alert",
    "SIMULATE_SCENARIOS",
    "SIMULATE_SEVERITIES",
    "SIMULATE_TARGETS",
    # Sandbox
    "check_wsl_available",
    "check_docker_ready",
    "get_sandbox_health",
    "submit_sample_job",
    "get_job_result",
    "list_jobs",
    # Supply Chain
    "check_pefile_available",
    "compute_sha256",
    "is_binary_signed",
    "is_suspicious_filepath",
    "inspect_module_file",
    "scan_process_modules",
    "scan_directory_modules",
    "get_supply_chain_health",
]
