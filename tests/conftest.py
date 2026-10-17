"""
Shared pytest fixtures.

Requires a running FalkorDB instance (docker-compose up -d).
Each test uses an isolated tenant graph named "tenant_test_<uuid>" and
deletes it after the test, so tests never interfere with each other.
"""
from __future__ import annotations

import uuid

import pytest

from trustable_memory.db import get_client, ensure_schema


@pytest.fixture()
def tenant_id() -> str:
    """Provide an ephemeral tenant ID and clean up after the test."""
    tid = f"test_{uuid.uuid4().hex[:8]}"
    ensure_schema(tid)
    yield tid
    # Teardown: drop the whole tenant graph
    try:
        client = get_client()
        g = client.select_graph(f"tenant_{tid}")
        g.delete()
    except Exception:
        pass  # graph may already be gone
