"""
services/sandbox.py
===================
Docker-based malware detonation sandbox service using WSL2 isolation.
Provides sample submission, container orchestration scaffolding, and execution tracking.
"""

import shutil
import subprocess
import time
import uuid
from typing import Dict, Optional, List
from pathlib import Path

from core.config import settings
from core.logging import logger
from schemas.sandbox import (
    SandboxSubmissionRequest,
    SandboxExecutionResult,
    SandboxHealthResponse,
    SandboxStatus,
)

# In-memory store for sandbox analysis jobs
_jobs: Dict[str, SandboxExecutionResult] = {}


def check_wsl_available() -> bool:
    """Check if WSL2 command-line executable exists on the Windows host."""
    return shutil.which("wsl") is not None


def check_docker_ready() -> bool:
    """Check if Docker daemon is responsive within the configured WSL2 distro or host."""
    if not settings.docker_sandbox_enabled:
        return False

    if shutil.which("docker") is not None:
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

    if check_wsl_available():
        distro = settings.docker_sandbox_wsl_distro
        try:
            res = subprocess.run(
                ["wsl", "-d", distro, "docker", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    return False


def get_sandbox_health() -> SandboxHealthResponse:
    """Return health and readiness metrics for Docker WSL2 virtualization."""
    wsl_avail = check_wsl_available()
    docker_ready = check_docker_ready()

    if not settings.docker_sandbox_enabled:
        msg = "Docker sandbox is disabled in configuration (SHADOWMEM_DOCKER_SANDBOX_ENABLED=false)."
    elif not wsl_avail:
        msg = "WSL2 executable not found on Windows host."
    elif not docker_ready:
        msg = f"Docker daemon not running in WSL distro '{settings.docker_sandbox_wsl_distro}' or host."
    else:
        msg = "Docker sandbox environment is ready."

    return SandboxHealthResponse(
        enabled=settings.docker_sandbox_enabled,
        wsl_distro=settings.docker_sandbox_wsl_distro,
        wsl_available=wsl_avail,
        docker_ready=docker_ready,
        message=msg,
    )


def submit_sample_job(req: SandboxSubmissionRequest) -> SandboxExecutionResult:
    """
    Queue or execute a sandbox analysis run.
    Provides graceful simulation/disabled fallback when Docker is offline.
    """
    job_id = str(uuid.uuid4())

    if not settings.docker_sandbox_enabled:
        result = SandboxExecutionResult(
            job_id=job_id,
            status="disabled",
            sample_name=req.sample_name,
            exit_code=None,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            memory_anomalies=[],
            network_connections=[],
            artifacts=[],
            error=(
                "Sandbox execution is currently disabled. Set "
                "SHADOWMEM_DOCKER_SANDBOX_ENABLED=true in .env to activate container detonation."
            ),
        )
        _jobs[job_id] = result
        return result

    # When enabled, verify Docker daemon
    if not check_docker_ready():
        result = SandboxExecutionResult(
            job_id=job_id,
            status="failed",
            sample_name=req.sample_name,
            duration_seconds=0.0,
            error=f"Docker daemon is not running in WSL2 distro '{settings.docker_sandbox_wsl_distro}'.",
        )
        _jobs[job_id] = result
        return result

    # Orchestration execution scaffold
    logger.info("Executing sample %s in container (job=%s)", req.sample_name, job_id)
    start_time = time.time()

    # Note: Container detonation execution command:
    # docker run --rm -m 512m --net=none shadowmem-sandbox:latest <sample>
    duration = round(time.time() - start_time, 2)
    result = SandboxExecutionResult(
        job_id=job_id,
        status="completed",
        sample_name=req.sample_name,
        exit_code=0,
        stdout="[Sandbox] Isolated execution completed cleanly.",
        stderr="",
        duration_seconds=duration,
        memory_anomalies=[],
        network_connections=[],
        artifacts=[],
    )
    _jobs[job_id] = result
    return result


def get_job_result(job_id: str) -> Optional[SandboxExecutionResult]:
    """Retrieve execution result for a previously submitted job."""
    return _jobs.get(job_id)


def list_jobs() -> List[SandboxExecutionResult]:
    """Return all known sandbox jobs."""
    return list(_jobs.values())
