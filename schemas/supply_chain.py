"""
schemas/supply_chain.py
=======================
Pydantic schemas for the software supply chain and module integrity scanner.
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


SupplyChainPosture = Literal[
    "Protected",
    "Suspicious",
    "Vulnerable",
]


class ModuleIntegrityFinding(BaseModel):
    """Integrity evaluation for an individual loaded DLL, binary, or package."""
    model_config = ConfigDict(extra="ignore")

    module_name: str = Field(..., description="File name of the module (e.g. ntdll.dll)")
    file_path: str = Field(..., description="Fully qualified file path on disk")
    is_signed: bool = Field(False, description="Whether the module carries a valid digital signature")
    signer_identity: Optional[str] = Field(None, description="CN / Subject of signing certificate")
    sha256: str = Field(..., description="SHA-256 cryptographic digest of the binary file")
    is_suspicious_location: bool = Field(False, description="Flagged if loaded from %TEMP%, user AppData, or unusual directory")
    is_known_vulnerable: bool = Field(False, description="Flagged if known vulnerable component or CVE matches")
    anomaly_description: Optional[str] = Field(None, description="Diagnostic details on observed supply chain risk")


class SupplyChainScanRequest(BaseModel):
    """Target specification for supply chain verification."""
    model_config = ConfigDict(extra="ignore")

    pid: Optional[int] = Field(None, description="Target process PID whose loaded modules should be evaluated")
    target_path: Optional[str] = Field(None, description="Filesystem directory or binary path to scan")


class SupplyChainScanResponse(BaseModel):
    """Aggregate findings of a supply chain integrity scan."""
    model_config = ConfigDict(extra="ignore")

    target: str = Field(..., description="Target process name/PID or scanned path")
    total_modules_scanned: int = Field(0, description="Total loaded modules or libraries inspected")
    unsigned_count: int = Field(0, description="Count of unsigned binaries detected")
    suspicious_count: int = Field(0, description="Count of binaries with suspicious locations or integrity flags")
    posture: SupplyChainPosture = Field("Protected", description="Composite supply-chain security posture")
    findings: List[ModuleIntegrityFinding] = Field(default_factory=list, description="Array of module findings")


class SupplyChainHealthResponse(BaseModel):
    """Readiness status of the supply chain scanner subsystem."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(..., description="Whether supply chain scanner is enabled in configuration")
    pefile_available: bool = Field(..., description="Whether pefile binary inspection library is available")
    message: str = Field(..., description="Subsystem health description")
