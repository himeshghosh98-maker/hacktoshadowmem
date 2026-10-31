"""
schemas/forensics.py
====================
Pydantic models for memory forensic scans, process telemetry, and detection summaries.
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


ProcessStatus = Literal[
    "Malicious (Injected)",
    "Suspicious",
    "Legitimate JIT Engine",
    "Clean",
]

SystemPosture = Literal[
    "Threat Detected",
    "Protected",
]


class ProcessClassification(BaseModel):
    """Forensic technique details from MITRE ATT&CK reference lookup."""
    model_config = ConfigDict(extra="ignore")

    mitre_id: Optional[str] = Field(None, description="MITRE ATT&CK technique identifier, e.g. T1055.001")
    display_name: Optional[str] = Field(None, description="Human-readable technique name")
    short_description: Optional[str] = Field(None, description="Summary of the adversarial mechanism")
    typical_indicators: Optional[str] = Field(None, description="Forensic artifacts typically observed")
    recommended_response: Optional[str] = Field(None, description="Playbook steps for incident response")


class UnbackedRegion(BaseModel):
    """Detailed metadata for a committed MEM_PRIVATE executable allocation."""
    model_config = ConfigDict(extra="ignore")

    base_address: Any = Field(..., description="Virtual memory base address (int or hex string)")
    size: int = Field(..., description="Region size in bytes")
    protection: str = Field(..., description="Current memory protection (e.g. PAGE_EXECUTE_READWRITE)")
    allocation_protect: Optional[str] = Field(None, description="Initial allocation protection (e.g. PAGE_READWRITE)")


class ProcessEntry(BaseModel):
    """Evaluated forensic record for an active Windows process."""
    model_config = ConfigDict(extra="ignore")

    pid: int = Field(..., description="Process Identifier")
    name: str = Field(..., description="Process image name")
    exe: str = Field("", description="Fully qualified image path on disk")
    rwx_count: int = Field(0, description="Count of PAGE_EXECUTE_READWRITE committed regions")
    unbacked_exec_count: int = Field(0, description="Count of unbacked private executable regions")
    total_rwx_bytes: int = Field(0, description="Aggregate byte size of RWX allocations")
    allocated_kb: float = Field(0.0, description="Kilobytes of RWX allocations")
    num_threads: int = Field(0, description="Active thread count")
    thread_unbacked_start: int = Field(0, description="Count of threads whose start address is in unbacked memory")
    vad_protection_anomaly: int = Field(0, description="Count of allocations with RW -> RX/RWX protection flips")
    threat_score: float = Field(0.0, ge=0.0, le=100.0, description="Normalized composite threat score (0-100)")
    status: ProcessStatus = Field("Clean", description="Forensic verdict")
    jit_engine: bool = Field(False, description="Whether process is a legitimate JIT compiler")
    model_used: bool = Field(True, description="Whether ML classifier was used (vs fallback heuristic)")
    classification: Optional[ProcessClassification] = Field(None, description="Associated MITRE technique details")
    unbacked_regions: List[UnbackedRegion] = Field(default_factory=list, description="Raw unbacked region descriptors")
    is_isolated: Optional[bool] = Field(False, description="Whether the process threads are suspended")
    attribution: Optional[Dict[str, float]] = Field(default_factory=dict, description="Feature attribution percentage breakdown")
    attribution_reasons: Optional[List[str]] = Field(default_factory=list, description="Forensic explanation rationale bullets")
    entropy: Optional[float] = Field(None, description="Sampled memory entropy score")


class ScanSummary(BaseModel):
    """Aggregate statistics for a completed system memory scan."""
    model_config = ConfigDict(extra="ignore")

    total_scanned: int = Field(..., description="Total active processes inspected")
    anomalies_detected: int = Field(..., description="Total malicious and suspicious processes")
    malicious_count: int = Field(..., description="Count of confirmed malicious processes")
    suspicious_count: int = Field(..., description="Count of suspicious processes")
    jit_engine_count: int = Field(..., description="Count of allowlisted JIT processes")
    clean_count: int = Field(..., description="Count of clean processes")
    system_posture: SystemPosture = Field(..., description="Overall system posture")
    model_loaded: bool = Field(..., description="Whether the ML pipeline is loaded and active")


class ScanResponse(BaseModel):
    """Full API payload returned by /api/scan and /api/v1/scan."""
    model_config = ConfigDict(extra="ignore")

    summary: ScanSummary
    processes: List[ProcessEntry]


class HexDumpLine(BaseModel):
    """A single 16-byte formatted line of memory hex inspection."""
    model_config = ConfigDict(extra="ignore")

    offset: str = Field(..., description="Hex offset within inspected buffer, e.g. '0x0000'")
    hex_bytes: str = Field(..., description="Space-separated hex byte representation")
    ascii_chars: str = Field(..., description="Printable ASCII characters with '.' for non-printable")


class MemoryDumpResponse(BaseModel):
    """Response payload for low-level memory region inspection."""
    model_config = ConfigDict(extra="ignore")

    pid: int = Field(..., description="Target process ID")
    name: str = Field(..., description="Process name")
    base_address: str = Field(..., description="Inspected memory base address in hex")
    size: int = Field(..., description="Inspected buffer size in bytes")
    protection: str = Field(..., description="Protection flag of the inspected region")
    entropy: float = Field(..., description="Shannon entropy score (0.0 to 8.0)")
    is_shellcode_suspect: bool = Field(..., description="Whether bytes match shellcode / payload signatures")
    hex_lines: List[HexDumpLine] = Field(default_factory=list, description="Formatted hex dump lines")
    disassembly_hints: List[str] = Field(default_factory=list, description="Forensic pattern hints observed in memory")
