"""
Core graph operations — all work is done in Cypher, not Python loops.

Design notes
------------
- MERGE is used for Agent and Source nodes so they are singletons per tenant.
- Memory nodes get UUIDs and carry full provenance as properties.
- DERIVED_FROM edges are created in a single UNWIND+MATCH+MERGE statement.
- All timestamps are stored as ISO-8601 strings (FalkorDB has no native
  datetime type; queries compare strings lexicographically which works for
  ISO-8601 sorted order).

FalkorDB header format: result.header == [[type_int, col_name], ...]
Use _rows(result) to get list[dict] from any query result.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional


def _rows(result) -> list[dict]:
    """Convert FalkorDB QueryResult → list of plain dicts.

    FalkorDB headers are [[type_int, col_name], ...]; extract name at [1].
    """
    keys = [h[1] for h in result.header]
    return [dict(zip(keys, row)) for row in result.result_set]

from .db import tenant_graph, ensure_schema
from .models import (
    WriteMemoryRequest,
    WriteOutputRequest,
    MemoryStatus,
    MemoryResponse,
    OutputResponse,
)


# ---------------------------------------------------------------------------
# Memory writes
# ---------------------------------------------------------------------------

def write_memory(req: WriteMemoryRequest) -> MemoryResponse:
    """
    Persist a new Memory node with full provenance.

    Cypher operations performed (in order):
    1. MERGE Agent node.
    2. MERGE Source node.
    3. CREATE Memory node with all properties.
    4. CREATE (Agent)-[:WROTE]->(Memory) edge.
    5. CREATE (Memory)-[:SOURCED_FROM]->(Source) edge.
    6. UNWIND derived_from list → MATCH existing Memory → MERGE DERIVED_FROM.

    Returns the created MemoryResponse.
    """
    ensure_schema(req.tenant_id)
    g = tenant_graph(req.tenant_id)

    memory_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    valid_from = req.valid_from.isoformat() if req.valid_from else now
    valid_to = req.valid_to.isoformat() if req.valid_to else ""

    # Step 1-5: merge agent, merge source, create memory + edges
    cypher_main = """
    MERGE (a:Agent {name: $agent_name})
      ON CREATE SET a.role = $agent_role
    MERGE (s:Source {url: $source_url})
      ON CREATE SET s.type = $source_type, s.trust = $source_trust
    CREATE (m:Memory {
        id:         $memory_id,
        topic:      $topic,
        value:      $value,
        status:     $status,
        trust:      $trust,
        created_at: $created_at,
        valid_from: $valid_from,
        valid_to:   $valid_to
    })
    CREATE (a)-[:WROTE]->(m)
    CREATE (m)-[:SOURCED_FROM]->(s)
    RETURN m.id AS id
    """
    g.query(
        cypher_main,
        {
            "agent_name": req.agent_name,
            "agent_role": req.agent_role,
            "source_url": req.source_url,
            "source_type": req.source_type.value,
            "source_trust": req.source_trust,
            "memory_id": memory_id,
            "topic": req.topic,
            "value": req.value,
            "status": MemoryStatus.active.value,
            "trust": req.trust,
            "created_at": now,
            "valid_from": valid_from,
            "valid_to": valid_to,
        },
    )

    # Step 6: create DERIVED_FROM edges in one shot using UNWIND
    if req.derived_from_ids:
        cypher_derived = """
        MATCH (m:Memory {id: $memory_id})
        UNWIND $parent_ids AS pid
          MATCH (p:Memory {id: pid})
          MERGE (m)-[:DERIVED_FROM]->(p)
        """
        g.query(
            cypher_derived,
            {"memory_id": memory_id, "parent_ids": req.derived_from_ids},
        )

    return MemoryResponse(
        id=memory_id,
        topic=req.topic,
        value=req.value,
        status=MemoryStatus.active,
        trust=req.trust,
        agent_name=req.agent_name,
        source_url=req.source_url,
        created_at=now,
        derived_from_ids=req.derived_from_ids,
    )


# ---------------------------------------------------------------------------
# Output writes
# ---------------------------------------------------------------------------

def write_output(req: WriteOutputRequest) -> OutputResponse:
    """
    Record an agent Output and link it to every Memory it consumed.

    Cypher:
    1. MERGE Agent.
    2. CREATE Output node.
    3. CREATE (Agent)-[:PRODUCED]->(Output) edge.
    4. UNWIND used_memory_ids → MATCH Memory → MERGE (Memory)-[:USED_BY]->(Output).
    """
    ensure_schema(req.tenant_id)
    g = tenant_graph(req.tenant_id)

    output_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    cypher_output = """
    MERGE (a:Agent {name: $agent_name})
      ON CREATE SET a.role = $agent_role
    CREATE (o:Output {
        id:     $output_id,
        kind:   $kind,
        text:   $text,
        status: 'active',
        created_at: $created_at
    })
    CREATE (a)-[:PRODUCED]->(o)
    RETURN o.id AS id
    """
    g.query(
        cypher_output,
        {
            "agent_name": req.agent_name,
            "agent_role": req.agent_role,
            "output_id": output_id,
            "kind": req.kind.value,
            "text": req.text,
            "created_at": now,
        },
    )

    if req.used_memory_ids:
        cypher_used = """
        MATCH (o:Output {id: $output_id})
        UNWIND $mem_ids AS mid
          MATCH (m:Memory {id: mid})
          MERGE (m)-[:USED_BY]->(o)
        """
        g.query(
            cypher_used,
            {"output_id": output_id, "mem_ids": req.used_memory_ids},
        )

    return OutputResponse(
        id=output_id,
        kind=req.kind.value,
        text=req.text,
        status="active",
        agent_name=req.agent_name,
        used_memory_ids=req.used_memory_ids,
    )


# ---------------------------------------------------------------------------
# Memory reads (for agents consuming memories)
# ---------------------------------------------------------------------------

def get_active_memories(
    tenant_id: str,
    topic: Optional[str] = None,
    min_trust: float = 0.0,
) -> list[dict]:
    """
    Fetch active memories optionally filtered by topic and minimum trust.

    Agents MUST call this (not raw DB access) so they automatically
    skip quarantined / retracted memories.
    """
    ensure_schema(tenant_id)
    g = tenant_graph(tenant_id)

    if topic:
        cypher = """
        MATCH (a:Agent)-[:WROTE]->(m:Memory)-[:SOURCED_FROM]->(s:Source)
        WHERE m.status = 'active'
          AND m.topic   = $topic
          AND m.trust  >= $min_trust
        RETURN m.id        AS id,
               m.topic     AS topic,
               m.value     AS value,
               m.trust     AS trust,
               m.status    AS status,
               m.created_at AS created_at,
               a.name      AS agent_name,
               s.url       AS source_url
        ORDER BY m.trust DESC
        """
        params = {"topic": topic, "min_trust": min_trust}
    else:
        cypher = """
        MATCH (a:Agent)-[:WROTE]->(m:Memory)-[:SOURCED_FROM]->(s:Source)
        WHERE m.status = 'active'
          AND m.trust >= $min_trust
        RETURN m.id        AS id,
               m.topic     AS topic,
               m.value     AS value,
               m.trust     AS trust,
               m.status    AS status,
               m.created_at AS created_at,
               a.name      AS agent_name,
               s.url       AS source_url
        ORDER BY m.trust DESC
        """
        params = {"min_trust": min_trust}

    result = g.query(cypher, params)
    return _rows(result)


def get_memory_by_id(tenant_id: str, memory_id: str) -> Optional[dict]:
    """Fetch a single memory by ID (any status)."""
    ensure_schema(tenant_id)
    g = tenant_graph(tenant_id)
    cypher = """
    MATCH (a:Agent)-[:WROTE]->(m:Memory {id: $memory_id})-[:SOURCED_FROM]->(s:Source)
    OPTIONAL MATCH (m)-[:DERIVED_FROM]->(p:Memory)
    RETURN m.id         AS id,
           m.topic      AS topic,
           m.value      AS value,
           m.trust      AS trust,
           m.status     AS status,
           m.created_at AS created_at,
           a.name       AS agent_name,
           s.url        AS source_url,
           collect(p.id) AS derived_from_ids
    """
    result = g.query(cypher, {"memory_id": memory_id})
    rows = _rows(result)
    return rows[0] if rows else None


# ===========================================================================
# M2: Blast-radius query and cascade quarantine
# ===========================================================================

def get_blast_radius(tenant_id: str, memory_id: str) -> dict:
    """
    Return every downstream node reachable from a Memory via
    DERIVED_FROM (reversed: children derived FROM this memory)
    and USED_BY edges, at any depth.

    Cypher strategy:
    A  Direct outputs of root (depth 1)
    B1 Memories derived (transitively) from root (depth = path length)
       WITH child, min(length(path)) AS depth ensures diamond paths collapse to min depth.
    B2 Outputs of those derived memories (depth = path length + 1)
       WITH o, min(length(path) + 1) AS depth ensures outputs get real dynamic depth.
    """
    ensure_schema(tenant_id)
    g = tenant_graph(tenant_id)

    # ── A: direct USED_BY outputs from root (depth 1) ─────────────────────
    cypher_a = """
    MATCH (root:Memory {id: $id})-[:USED_BY]->(o:Output)
    RETURN DISTINCT 'Output' AS kind,
           o.id              AS node_id,
           o.status          AS status,
           1                 AS depth
    """

    # ── B1: all memories derived from root — deduplicated, min depth ────────
    cypher_b1 = """
    MATCH path = (child:Memory)-[:DERIVED_FROM*1..10]->(root:Memory {id: $id})
    WITH child, min(length(path)) AS depth
    RETURN DISTINCT 'Memory' AS kind,
           child.id          AS node_id,
           child.status      AS status,
           depth
    """

    # ── B2: outputs of derived memories, depth = path_length + 1 ──────────
    cypher_b2 = """
    MATCH path = (child:Memory)-[:DERIVED_FROM*1..10]->(root:Memory {id: $id})
    MATCH (child)-[:USED_BY]->(o:Output)
    WITH o, min(length(path) + 1) AS depth
    RETURN DISTINCT 'Output' AS kind,
           o.id              AS node_id,
           o.status          AS status,
           depth
    """

    rows_a  = _rows(g.query(cypher_a,  {"id": memory_id}))
    rows_b1 = _rows(g.query(cypher_b1, {"id": memory_id}))
    rows_b2 = _rows(g.query(cypher_b2, {"id": memory_id}))

    # Merge, keeping minimum depth per node_id
    seen: dict[str, dict] = {}
    for row in rows_a + rows_b1 + rows_b2:
        nid = row["node_id"]
        if nid not in seen or row["depth"] < seen[nid]["depth"]:
            seen[nid] = row

    nodes = sorted(seen.values(), key=lambda r: (r["depth"], r["node_id"]))
    memories = [r["node_id"] for r in nodes if r["kind"] == "Memory"]
    outputs  = [r["node_id"] for r in nodes if r["kind"] == "Output"]

    return {
        "root_memory_id":    memory_id,
        "affected_memories": memories,
        "affected_outputs":  outputs,
        "total_affected":    len(nodes),
        "nodes":             nodes,   # full detail: kind, node_id, status, depth
    }


def cascade_quarantine(tenant_id: str, memory_id: str) -> dict:
    """
    Retract the root memory and quarantine every downstream memory/output
    in a SINGLE atomic Cypher statement.

    Single-statement structure:
        MATCH root  →  SET root retracted
        WITH root
        OPTIONAL MATCH derived children  →  SET quarantined
        WITH root, collect(DISTINCT child.id)
        OPTIONAL MATCH root outputs      →  SET quarantined
        WITH root, child_ids, collect(DISTINCT o1.id)
        OPTIONAL MATCH derived children again
        OPTIONAL MATCH their outputs     →  SET quarantined
        RETURN root.id, child_ids, root_out_ids, collect(DISTINCT o2.id)
    """
    ensure_schema(tenant_id)
    g = tenant_graph(tenant_id)

    cypher = """
    MATCH (root:Memory {id: $id})
    SET root.status = 'retracted'
    WITH root

    OPTIONAL MATCH (child:Memory)-[:DERIVED_FROM*1..10]->(root)
    WHERE child IS NOT NULL
    SET child.status = 'quarantined'
    WITH root, collect(DISTINCT child.id) AS child_ids

    OPTIONAL MATCH (root)-[:USED_BY]->(o1:Output)
    WHERE o1 IS NOT NULL
    SET o1.status = 'quarantined'
    WITH root, child_ids, collect(DISTINCT o1.id) AS root_out_ids

    OPTIONAL MATCH (c2:Memory)-[:DERIVED_FROM*1..10]->(root)
    OPTIONAL MATCH (c2)-[:USED_BY]->(o2:Output)
    WHERE o2 IS NOT NULL
    SET o2.status = 'quarantined'

    RETURN root.id                 AS root_id,
           child_ids,
           root_out_ids,
           collect(DISTINCT o2.id) AS desc_out_ids
    """
    rows = _rows(g.query(cypher, {"id": memory_id}))
    row  = rows[0] if rows else {}

    child_ids    = [x for x in (row.get("child_ids")    or []) if x is not None]
    root_out_ids = [x for x in (row.get("root_out_ids") or []) if x is not None]
    desc_out_ids = [x for x in (row.get("desc_out_ids") or []) if x is not None]
    all_out_ids  = list(dict.fromkeys(root_out_ids + desc_out_ids))  # dedupe, stable order

    return {
        "root_memory_id":         memory_id,
        "root_status":            "retracted",
        "memories_quarantined":   len(child_ids),
        "outputs_quarantined":    len(all_out_ids),
        "quarantined_memory_ids": child_ids,
        "quarantined_output_ids": all_out_ids,
        "total_affected":         1 + len(child_ids) + len(all_out_ids),
    }


def get_tenant_graph_dump(tenant_id: str) -> dict:
    """
    Read-only full graph dump for the UI visualization.
    Returns all nodes (with status, kind, detail) and edges (with relationships).
    """
    ensure_schema(tenant_id)
    g = tenant_graph(tenant_id)

    nodes = []
    edges = []

    # 1. Memories
    m_res = _rows(g.query(
        "MATCH (m:Memory) RETURN m.id AS id, m.topic AS topic, m.value AS value, m.status AS status, m.trust AS trust, m.created_at AS created_at"
    ))
    for row in m_res:
        nodes.append({
            "id": row["id"],
            "kind": "Memory",
            "label": f"Memory\n[{row.get('topic', '')}]",
            "status": row.get("status", "active"),
            "trust": row.get("trust", 1.0),
            "detail": row.get("value", ""),
        })

    # 2. Outputs
    o_res = _rows(g.query(
        "MATCH (o:Output) RETURN o.id AS id, o.kind AS kind, o.text AS text, o.status AS status, o.created_at AS created_at"
    ))
    for row in o_res:
        nodes.append({
            "id": row["id"],
            "kind": "Output",
            "label": f"Output\n({row.get('kind', '')})",
            "status": row.get("status", "active"),
            "trust": None,
            "detail": row.get("text", ""),
        })

    # 3. Agents
    a_res = _rows(g.query(
        "MATCH (a:Agent) RETURN a.name AS id, a.role AS role"
    ))
    for row in a_res:
        nodes.append({
            "id": row["id"],
            "kind": "Agent",
            "label": f"Agent\n{row.get('id', '')}",
            "status": "active",
            "trust": 1.0,
            "detail": f"Role: {row.get('role', '')}",
        })

    # 4. Sources
    s_res = _rows(g.query(
        "MATCH (s:Source) RETURN s.url AS id, s.type AS type, s.trust AS trust"
    ))
    for row in s_res:
        nodes.append({
            "id": row["id"],
            "kind": "Source",
            "label": f"Source\n({row.get('type', '')})",
            "status": "active",
            "trust": row.get("trust", 1.0),
            "detail": row.get("id", ""),
        })

    # 5. Edges
    edge_queries = [
        "MATCH (a:Agent)-[:WROTE]->(m:Memory) RETURN a.name AS from_id, m.id AS to_id, 'WROTE' AS label",
        "MATCH (m:Memory)-[:SOURCED_FROM]->(s:Source) RETURN m.id AS from_id, s.url AS to_id, 'SOURCED_FROM' AS label",
        "MATCH (c:Memory)-[:DERIVED_FROM]->(p:Memory) RETURN c.id AS from_id, p.id AS to_id, 'DERIVED_FROM' AS label",
        "MATCH (m:Memory)-[:USED_BY]->(o:Output) RETURN m.id AS from_id, o.id AS to_id, 'USED_BY' AS label",
    ]
    for eq in edge_queries:
        rows = _rows(g.query(eq))
        for r in rows:
            edges.append({
                "from": r["from_id"],
                "to": r["to_id"],
                "label": r["label"],
            })

    return {"nodes": nodes, "edges": edges}


