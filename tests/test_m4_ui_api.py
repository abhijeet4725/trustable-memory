"""
tests/test_m4_ui_api.py

Tests for M4 endpoints:
  - GET /tenants/{tenant_id}/graph
  - GET /benchmark/results
  - GET /ui
  - GET / (redirects to /ui)
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from trustable_memory.api import app
from trustable_memory.graph_ops import write_memory, write_output
from trustable_memory.models import (
    OutputKind,
    SourceType,
    WriteMemoryRequest,
    WriteOutputRequest,
)


@pytest.fixture()
def client():
    return TestClient(app)


class TestM4Endpoints:
    def test_ui_and_redirect(self, client):
        res_ui = client.get("/ui")
        assert res_ui.status_code == 200
        assert "Trustable Memory" in res_ui.text

        res_root = client.get("/", follow_redirects=False)
        assert res_root.status_code in (302, 307)
        assert res_root.headers["location"] == "/ui"

    def test_benchmark_results_endpoint(self, client):
        res = client.get("/benchmark/results")
        assert res.status_code == 200
        data = res.json()
        assert "rows" in data
        assert len(data["rows"]) == 10

    def test_tenant_graph_dump(self, client, tenant_id):
        # Write sample node
        m = write_memory(
            WriteMemoryRequest(
                tenant_id=tenant_id,
                agent_name="agent-dump",
                agent_role="tester",
                topic="dump_test",
                value="Testing graph dump",
                trust=0.9,
                source_url="https://test.dump.internal",
                source_type=SourceType.document,
                source_trust=0.9,
            )
        )
        o = write_output(
            WriteOutputRequest(
                tenant_id=tenant_id,
                agent_name="agent-dump",
                agent_role="tester",
                kind=OutputKind.recommendation,
                text="Dump output",
                used_memory_ids=[m.id],
            )
        )

        res = client.get(f"/tenants/{tenant_id}/graph")
        assert res.status_code == 200
        dump = res.json()
        assert "nodes" in dump
        assert "edges" in dump

        node_ids = [n["id"] for n in dump["nodes"]]
        assert m.id in node_ids
        assert o.id in node_ids

        # Check edge
        edge_types = [e["label"] for e in dump["edges"]]
        assert "WROTE" in edge_types
        assert "SOURCED_FROM" in edge_types
        assert "USED_BY" in edge_types
