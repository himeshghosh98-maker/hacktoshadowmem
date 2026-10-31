"""
schemas/containment.py
======================
Pydantic models for process isolation (containment), resumption, and audit logging.
"""

from typing import List, Optional, Literal
from pydantic import BaseModel, Field, ConfigDict


ContainmentAction = Literal["suspended", "resumed"]
AuditActionType = Literal["isolate", "resume"]


class IsolateRequest(BaseModel):
    """Optional request body when isolating a process."""
    model_config = ConfigDict(extra="ignore")

    reason: Optional[str] = Field("", description="Justification or ticket ID for process containment")


class ContainmentResponse(BaseModel):
    """Result of an isolate or resume action."""
    model_config = ConfigDict(extra="ignore")

    pid: Optional[int] = Field(None, description="Target process PID")
    name: Optional[str] = Field(None, description="Process name or identifier")
    action: ContainmentAction = Field(..., description="Action performed: suspended or resumed")
    success: bool = Field(..., description="Whether operation succeeded")
    error: Optional[str] = Field(None, description="Error or diagnostic detail message")
    suspended_count: Optional[int] = Field(None, description="Count of threads successfully suspended")
    resumed_count: Optional[int] = Field(None, description="Count of threads successfully resumed")
    failed_count: Optional[int] = Field(None, description="Count of threads that could not be opened/modified")


class AuditAction(BaseModel):
    """Individual entry in the containment audit log."""
    model_config = ConfigDict(extra="ignore")

    pid: int = Field(..., description="Target process PID")
    name: str = Field(..., description="Target process name")
    action: AuditActionType = Field(..., description="Action taken: isolate or resume")
    success: bool = Field(..., description="Outcome of the operation")
    reason: Optional[str] = Field(None, description="Operator justification or error message")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of the action")


class AuditResponse(BaseModel):
    """Full containment audit log returned by /api/audit and /api/v1/audit."""
    model_config = ConfigDict(extra="ignore")

    actions: List[AuditAction] = Field(default_factory=list, description="Ordered history of containment actions")
