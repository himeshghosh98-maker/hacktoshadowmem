"""
schemas/sandbox.py
==================
Pydantic schemas for the Docker WSL2 malware detonation sandbox.
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


SandboxStatus = Literal[
    "queued",
    "running",
    "completed",
    "failed",
    "timeout",
    "disabled",
]


class SandboxSubmissionRequest(BaseModel):
    """Payload to trigger a sandboxed execution run."""
    model_config = ConfigDict(extra="ignore")

    sample_path: Optional[str] = Field(None, description="Absolute path on host to executable/script to detonate")
    sample_base64: Optional[str] = Field(None, description="Base64 encoded binary content if uploading directly")
    sample_name: str = Field("sample.bin", description="Filename to assign inside sandbox container")
    arguments: List[str] = Field(default_factory=list, description="Command line arguments for sample execution")
    timeout_seconds: int = Field(60, ge=5, le=600, description="Maximum execution timeout in seconds")
    network_enabled: bool = Field(False, description="Whether to allow simulated/restricted outbound network egress")
    memory_dump_interval_sec: Optional[int] = Field(None, description="Interval in seconds to capture memory snapshots")


class SandboxHealthResponse(BaseModel):
    """Status of Docker engine and WSL2 virtualization layer."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(..., description="Whether sandbox integration is enabled in settings")
    wsl_distro: str = Field(..., description="Target WSL2 distribution name")
    wsl_available: bool = Field(..., description="Whether WSL2 executable is available on Windows host")
    docker_ready: bool = Field(..., description="Whether Docker daemon is running inside WSL2")
    message: str = Field(..., description="Diagnostic detail or readiness status")


class SandboxExecutionResult(BaseModel):
    """Telemetry and outcome of a sandboxed execution session."""
    model_config = ConfigDict(extra="ignore")

    job_id: str = Field(..., description="Unique job identifier")
    status: SandboxStatus = Field(..., description="Execution status")
    sample_name: str = Field(..., description="Target sample name")
    exit_code: Optional[int] = Field(None, description="Process exit code inside container")
    stdout: str = Field("", description="Standard output captured from container")
    stderr: str = Field("", description="Standard error captured from container")
    duration_seconds: float = Field(0.0, description="Observed runtime duration")
    memory_anomalies: List[str] = Field(default_factory=list, description="Anomalies detected in container memory")
    network_connections: List[Dict[str, Any]] = Field(default_factory=list, description="Observed socket activity")
    artifacts: List[str] = Field(default_factory=list, description="Paths to captured memory dumps or artifacts")
    error: Optional[str] = Field(None, description="Error message if execution failed")
