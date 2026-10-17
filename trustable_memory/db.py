"""
FalkorDB connection and per-tenant graph helpers.

Each tenant gets its own named graph: "tenant_<id>".
The module keeps a single connection pool shared across all graphs.
"""
from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

_FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost")
_FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))


@lru_cache(maxsize=1)
def get_client() -> FalkorDB:
    """Return a cached FalkorDB client (one per process)."""
    return FalkorDB(host=_FALKORDB_HOST, port=_FALKORDB_PORT)


def tenant_graph(tenant_id: str):
    """Return the FalkorDB Graph object for a given tenant."""
    client = get_client()
    return client.select_graph(f"tenant_{tenant_id}")


def ensure_schema(tenant_id: str) -> None:
    """
    Create indexes and constraints for a tenant graph.

    Idempotent — safe to call at startup and in tests.
    FalkorDB uses CREATE INDEX ON syntax; duplicates are silently ignored.
    """
    g = tenant_graph(tenant_id)

    # Node-label indexes for fast lookups
    _safe_index(g, "CREATE INDEX ON :Memory(id)")
    _safe_index(g, "CREATE INDEX ON :Memory(status)")
    _safe_index(g, "CREATE INDEX ON :Memory(topic)")
    _safe_index(g, "CREATE INDEX ON :Agent(name)")
    _safe_index(g, "CREATE INDEX ON :Source(url)")
    _safe_index(g, "CREATE INDEX ON :Output(id)")


def _safe_index(g, cypher: str) -> None:
    """Execute a CREATE INDEX statement, ignoring 'already exists' errors."""
    try:
        g.query(cypher)
    except Exception as exc:
        msg = str(exc).lower()
        if "already indexed" in msg or "equivalent index" in msg:
            return
        raise
