"""
FastAPI application — Memory write/read endpoints (M1) + blast-radius/quarantine (M2).

Endpoints:
  POST /tenants/{tenant_id}/memories                    Write a new memory
  POST /tenants/{tenant_id}/outputs                     Write a new output
  GET  /tenants/{tenant_id}/memories                    List active memories
  GET  /tenants/{tenant_id}/memories/{mem_id}           Get one memory
  GET  /tenants/{tenant_id}/memories/{mem_id}/blast-radius   M2: downstream nodes
  POST /tenants/{tenant_id}/memories/{mem_id}/retract   M2: cascade quarantine
  GET  /healthz                                         Liveness probe
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from trustable_memory.db import ensure_schema
from trustable_memory.graph_ops import (
    cascade_quarantine,
    get_active_memories,
    get_blast_radius,
    get_memory_by_id,
    write_memory,
    write_output,
)
from trustable_memory.models import (
    BlastRadiusResponse,
    MemoryResponse,
    OutputResponse,
    QuarantineResponse,
    WriteMemoryRequest,
    WriteOutputRequest,
)

app = FastAPI(
    title="Trustable Memory API",
    description="Graph-backed provenance memory layer for ops agents.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Memory endpoints (M1)
# ---------------------------------------------------------------------------

@app.post("/tenants/{tenant_id}/memories", response_model=MemoryResponse, status_code=201)
def create_memory(tenant_id: str, body: WriteMemoryRequest):
    """Write a new memory with full provenance to the graph."""
    body = body.model_copy(update={"tenant_id": tenant_id})
    return write_memory(body)


@app.get("/tenants/{tenant_id}/memories", response_model=list[MemoryResponse])
def list_memories(
    tenant_id: str,
    topic: str | None = Query(default=None),
    min_trust: float = Query(default=0.0, ge=0.0, le=1.0),
):
    """List active memories, optionally filtered by topic and minimum trust."""
    rows = get_active_memories(tenant_id, topic=topic, min_trust=min_trust)
    return [
        MemoryResponse(
            id=r["id"],
            topic=r["topic"],
            value=r["value"],
            status=r["status"],
            trust=r["trust"],
            agent_name=r["agent_name"],
            source_url=r["source_url"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@app.get("/tenants/{tenant_id}/memories/{memory_id}", response_model=MemoryResponse)
def get_memory(tenant_id: str, memory_id: str):
    """Fetch a single memory by ID (any status)."""
    row = get_memory_by_id(tenant_id, memory_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Memory not found")
    return MemoryResponse(
        id=row["id"],
        topic=row["topic"],
        value=row["value"],
        status=row["status"],
        trust=row["trust"],
        agent_name=row["agent_name"],
        source_url=row["source_url"],
        created_at=row["created_at"],
        derived_from_ids=row.get("derived_from_ids") or [],
    )


# ---------------------------------------------------------------------------
# Output endpoints (M1)
# ---------------------------------------------------------------------------

@app.post("/tenants/{tenant_id}/outputs", response_model=OutputResponse, status_code=201)
def create_output(tenant_id: str, body: WriteOutputRequest):
    """Record an agent output linked to the memories it consumed."""
    body = body.model_copy(update={"tenant_id": tenant_id})
    return write_output(body)


# ---------------------------------------------------------------------------
# M2: Blast-radius and cascade quarantine
# ---------------------------------------------------------------------------

@app.get(
    "/tenants/{tenant_id}/memories/{memory_id}/blast-radius",
    response_model=BlastRadiusResponse,
)
def blast_radius(tenant_id: str, memory_id: str):
    """
    Return the full downstream blast radius of a memory:
    every memory derived from it (transitively) and every
    output that consumed it or any of its descendants.
    """
    row = get_memory_by_id(tenant_id, memory_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Memory not found")
    result = get_blast_radius(tenant_id, memory_id)
    return BlastRadiusResponse(
        root_memory_id=result["root_memory_id"],
        affected_memories=result["affected_memories"],
        affected_outputs=result["affected_outputs"],
        total_affected=result["total_affected"],
    )


@app.post(
    "/tenants/{tenant_id}/memories/{memory_id}/retract",
    response_model=QuarantineResponse,
)
def retract_memory(tenant_id: str, memory_id: str):
    """
    Retract a memory and cascade-quarantine all downstream memories and outputs.
    The root memory is set to 'retracted'; everything built on it is 'quarantined'.
    """
    row = get_memory_by_id(tenant_id, memory_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Memory not found")
    result = cascade_quarantine(tenant_id, memory_id)
    return QuarantineResponse(
        root_memory_id=result["root_memory_id"],
        memories_quarantined=result["memories_quarantined"],
        outputs_quarantined=result["outputs_quarantined"],
    )


# ---------------------------------------------------------------------------
# M4: Full Graph Dump for UI Visualization & Benchmark API
# ---------------------------------------------------------------------------

import csv
import os
from fastapi.responses import HTMLResponse, RedirectResponse

from trustable_memory.graph_ops import get_tenant_graph_dump


@app.get("/tenants/{tenant_id}/graph")
def get_graph(tenant_id: str):
    """Return nodes and edges for full graph visualization."""
    return get_tenant_graph_dump(tenant_id)


@app.get("/benchmark/results")
def get_benchmark_results():
    """Return parsed rows from benchmark/results.csv."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(base_dir, "benchmark", "results.csv")
    if not os.path.exists(csv_path):
        return {"rows": []}
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return {"rows": list(reader)}


@app.get("/", include_in_schema=False)
def index_redirect():
    return RedirectResponse(url="/ui")


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
def serve_ui():
    """Serve the single-page frontend application."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ui_path = os.path.join(base_dir, "frontend", "index.html")
    if not os.path.exists(ui_path):
        raise HTTPException(status_code=404, detail="Frontend UI not found")
    with open(ui_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

