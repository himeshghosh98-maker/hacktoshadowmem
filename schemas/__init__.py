"""
schemas package
===============
Unified Pydantic request and response models for ShadowMem API layer.
"""

from schemas.forensics import (
    ProcessStatus,
    SystemPosture,
    ProcessClassification,
    UnbackedRegion,
    ProcessEntry,
    ScanSummary,
    ScanResponse,
)

from schemas.containment import (
    ContainmentAction,
    AuditActionType,
    IsolateRequest,
    ContainmentResponse,
    AuditAction,
    AuditResponse,
)

from schemas.alerts import (
    SeverityLevel,
    BlockStatus,
    SimulateAlertRequest,
    SimulateAlertResponse,
    ProcessMeta,
    DetectionMeta,
    AlertFrame,
    MemoryBlock,
    MemoryMapFrame,
)

from schemas.sandbox import (
    SandboxStatus,
    SandboxSubmissionRequest,
    SandboxHealthResponse,
    SandboxExecutionResult,
)

from schemas.supply_chain import (
    SupplyChainPosture,
    ModuleIntegrityFinding,
    SupplyChainScanRequest,
    SupplyChainScanResponse,
    SupplyChainHealthResponse,
)

__all__ = [
    # Forensics
    "ProcessStatus",
    "SystemPosture",
    "ProcessClassification",
    "UnbackedRegion",
    "ProcessEntry",
    "ScanSummary",
    "ScanResponse",
    # Containment
    "ContainmentAction",
    "AuditActionType",
    "IsolateRequest",
    "ContainmentResponse",
    "AuditAction",
    "AuditResponse",
    # Alerts & Simulation
    "SeverityLevel",
    "BlockStatus",
    "SimulateAlertRequest",
    "SimulateAlertResponse",
    "ProcessMeta",
    "DetectionMeta",
    "AlertFrame",
    "MemoryBlock",
    "MemoryMapFrame",
    # Sandbox (Docker WSL2)
    "SandboxStatus",
    "SandboxSubmissionRequest",
    "SandboxHealthResponse",
    "SandboxExecutionResult",
    # Supply Chain Scanner
    "SupplyChainPosture",
    "ModuleIntegrityFinding",
    "SupplyChainScanRequest",
    "SupplyChainScanResponse",
    "SupplyChainHealthResponse",
]
