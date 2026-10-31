"""
schemas/alerts.py
=================
Pydantic models for WebSocket alert frames, simulation triggers, and memory maps.
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


SeverityLevel = Literal["critical", "warn", "info", "ok"]
BlockStatus = Literal["clean", "suspicious", "infected"]


class SimulateAlertRequest(BaseModel):
    """Body schema for POST /simulate/alert and /api/v1/simulate/alert."""
    model_config = ConfigDict(extra="ignore")

    scenario: str = Field(
        "cobalt_strike_reflective_injection",
        description="Attack pattern: cobalt_strike_reflective_injection, process_hollowing, dll_injection"
    )
    severity: str = Field(
        ...,
        description="Alert severity level: critical, warn, info"
    )


class SimulateAlertResponse(BaseModel):
    """Response returned when a test alert simulation is broadcast."""
    model_config = ConfigDict(extra="ignore")

    status: str = Field("broadcast", description="Broadcast status flag")
    alert_id: str = Field(..., description="UUID assigned to the broadcasted alert")
    scenario: str = Field(..., description="Simulated attack scenario")
    severity: str = Field(..., description="Simulated severity")


class ProcessMeta(BaseModel):
    """Process summary embedded inside alert and memory map payloads."""
    model_config = ConfigDict(extra="ignore")

    pid: Optional[int] = Field(None, description="Process PID")
    name: Optional[str] = Field(None, description="Process name")
    image_path: Optional[str] = Field(None, description="Executable path on disk")
    status: Optional[str] = Field(None, description="Forensic status")


class DetectionMeta(BaseModel):
    """Detection findings attached to an alert frame."""
    model_config = ConfigDict(extra="ignore")

    is_malicious: bool = Field(..., description="Whether detection indicates malicious activity")
    confidence: float = Field(..., description="Model confidence or scaled threat score (0-1)")
    classifier: str = Field("ShadowMem-v1", description="Classifier identifier")
    technique: Optional[str] = Field(None, description="MITRE ATT&CK technique label")
    threat_score: Optional[float] = Field(None, description="Normalized threat score (0-100)")
    status: Optional[str] = Field(None, description="Classification status")
    scenario: Optional[str] = Field(None, description="Scenario ID if generated via simulation")


class AlertFrame(BaseModel):
    """Alert event broadcast over WebSocket /ws/alerts."""
    model_config = ConfigDict(extra="ignore")

    type: Literal["alert"] = Field("alert", description="Message type")
    event_id: str = Field(..., description="Unique event UUID")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    severity: SeverityLevel = Field(..., description="Event severity")
    process: Optional[ProcessMeta] = Field(None, description="Process involved in the detection")
    detection: Optional[DetectionMeta] = Field(None, description="Forensic detection attributes")
    message: Optional[str] = Field(None, description="Human-readable notification text")


class MemoryBlock(BaseModel):
    """Individual virtual address space block for the live-map visualizer."""
    model_config = ConfigDict(extra="ignore")

    index: int = Field(..., description="0-indexed sequence in the block grid")
    base_address: str = Field(..., description="Hex formatted base virtual address (0x...)")
    size: int = Field(..., description="Byte size of the block")
    protection: str = Field(..., description="Memory protection string (PAGE_EXECUTE_READWRITE, etc.)")
    state: str = Field("MEM_COMMIT", description="Memory allocation state")
    type: str = Field("MEM_PRIVATE", description="Memory type")
    status: BlockStatus = Field("clean", description="Block threat rating: clean, suspicious, infected")


class MemoryMapFrame(BaseModel):
    """Virtual address space layout frame broadcast over WebSocket /ws/alerts."""
    model_config = ConfigDict(extra="ignore")

    type: Literal["memory_map"] = Field("memory_map", description="Message type")
    event_id: str = Field(..., description="Unique frame UUID")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    process: Optional[ProcessMeta] = Field(None, description="Process whose address space is represented")
    blocks: List[MemoryBlock] = Field(default_factory=list, description="Array of memory blocks")
