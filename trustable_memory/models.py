"""
Pydantic models for API request/response and internal domain objects.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class MemoryStatus(str, Enum):
    active = "active"
    quarantined = "quarantined"
    retracted = "retracted"


class SourceType(str, Enum):
    document = "document"
    ticket = "ticket"
    runbook = "runbook"
    api = "api"
    agent = "agent"


class OutputKind(str, Enum):
    recommendation = "recommendation"
    action_log = "action_log"
    alert = "alert"


# ---------------------------------------------------------------------------
# Write-memory request
# ---------------------------------------------------------------------------

class WriteMemoryRequest(BaseModel):
    tenant_id: str = Field(..., description="Tenant identifier")
    agent_name: str = Field(..., description="Agent writing this memory")
    agent_role: str = Field(default="generic", description="Agent role label")
    topic: str = Field(..., description="Short topic key, e.g. 'cpu_fix_payments'")
    value: str = Field(..., description="Memory content (free text)")
    trust: float = Field(default=0.8, ge=0.0, le=1.0)
    source_url: str = Field(..., description="URL or identifier of the source")
    source_type: SourceType = Field(default=SourceType.document)
    source_trust: float = Field(default=0.8, ge=0.0, le=1.0)
    derived_from_ids: list[str] = Field(
        default_factory=list,
        description="Memory IDs this memory was derived from",
    )
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Write-output request
# ---------------------------------------------------------------------------

class WriteOutputRequest(BaseModel):
    tenant_id: str
    agent_name: str
    agent_role: str = "generic"
    kind: OutputKind = OutputKind.recommendation
    text: str
    used_memory_ids: list[str] = Field(
        default_factory=list,
        description="Memory IDs consumed to produce this output",
    )


# ---------------------------------------------------------------------------
# Response shapes
# ---------------------------------------------------------------------------

class MemoryResponse(BaseModel):
    id: str
    topic: str
    value: str
    status: MemoryStatus
    trust: float
    agent_name: str
    source_url: str
    created_at: str
    derived_from_ids: list[str] = []


class OutputResponse(BaseModel):
    id: str
    kind: str
    text: str
    status: str
    agent_name: str
    used_memory_ids: list[str] = []


class BlastRadiusResponse(BaseModel):
    root_memory_id: str
    affected_memories: list[str]
    affected_outputs: list[str]
    total_affected: int


class QuarantineResponse(BaseModel):
    root_memory_id: str
    memories_quarantined: int
    outputs_quarantined: int
