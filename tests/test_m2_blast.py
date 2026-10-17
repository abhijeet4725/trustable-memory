"""
M2 unit tests: blast-radius query and cascade quarantine.

Test scenarios
--------------
1. linear_chain:   root → child_mem → grandchild_mem → output
   (3 hops of DERIVED_FROM, plus USED_BY at the end)
2. branched_output: one memory → two outputs (fan-out)
3. derived_from:    explicit DERIVED_FROM chain (already in chain test)
4. unrelated_safe:  unrelated memories/outputs must stay active after quarantine
5. agent_blocked:   Responder cannot consume quarantined memories end-to-end
6. blast_radius_counts: verify exact node counts and depth values
7. retract_api:     re-test quarantine via the cascade_quarantine() function

Run: docker-compose up -d && pytest tests/test_m2_blast.py -v
"""
from __future__ import annotations

import pytest

from trustable_memory.db import tenant_graph
from trustable_memory.graph_ops import (
    cascade_quarantine,
    get_active_memories,
    get_blast_radius,
    get_memory_by_id,
    write_memory,
    write_output,
)
from trustable_memory.models import (
    OutputKind,
    SourceType,
    WriteMemoryRequest,
    WriteOutputRequest,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mem(tenant_id, topic, value="v", trust=0.8, agent="researcher-1",
         source_url="https://src.internal/doc", derived_from_ids=None):
    return write_memory(WriteMemoryRequest(
        tenant_id=tenant_id,
        agent_name=agent,
        agent_role="researcher",
        topic=topic,
        value=value,
        trust=trust,
        source_url=source_url,
        source_type=SourceType.runbook,
        source_trust=0.9,
        derived_from_ids=derived_from_ids or [],
    ))


def _out(tenant_id, text="recommendation text", used_memory_ids=None,
         kind=OutputKind.recommendation, agent="responder-1"):
    return write_output(WriteOutputRequest(
        tenant_id=tenant_id,
        agent_name=agent,
        agent_role="responder",
        kind=kind,
        text=text,
        used_memory_ids=used_memory_ids or [],
    ))


def _status(tenant_id, node_id, node_type="memory") -> str:
    """Read status directly from the graph for any node type."""
    g = tenant_graph(tenant_id)
    if node_type == "memory":
        r = g.query("MATCH (m:Memory {id: $id}) RETURN m.status", {"id": node_id})
    else:
        r = g.query("MATCH (o:Output {id: $id}) RETURN o.status", {"id": node_id})
    return r.result_set[0][0]


# ===========================================================================
# 1. Linear chain — 3 hops of DERIVED_FROM + USED_BY at the end
#
#    root_mem
#      └─[DERIVED_FROM]─ child_mem
#                          └─[DERIVED_FROM]─ grandchild_mem
#                                              └─[USED_BY]─ leaf_output
#
#    Retract root_mem → everything downstream quarantined.
# ===========================================================================

class TestLinearChain:
    def test_blast_radius_covers_all_three_hops(self, tenant_id):
        root  = _mem(tenant_id, "root")
        child = _mem(tenant_id, "child",  derived_from_ids=[root.id])
        grand = _mem(tenant_id, "grand",  derived_from_ids=[child.id])
        leaf  = _out(tenant_id, "leaf output", used_memory_ids=[grand.id])

        br = get_blast_radius(tenant_id, root.id)

        assert child.id in br["affected_memories"], "child must be in blast radius"
        assert grand.id in br["affected_memories"], "grandchild must be in blast radius"
        assert leaf.id  in br["affected_outputs"],  "leaf output must be in blast radius"
        assert br["total_affected"] == 3  # child + grand + leaf_output

    def test_depth_values_are_correct(self, tenant_id):
        root  = _mem(tenant_id, "root")
        child = _mem(tenant_id, "child", derived_from_ids=[root.id])
        grand = _mem(tenant_id, "grand", derived_from_ids=[child.id])
        _out(tenant_id, "leaf out", used_memory_ids=[grand.id])

        br = get_blast_radius(tenant_id, root.id)
        by_id = {n["node_id"]: n for n in br["nodes"]}

        assert by_id[child.id]["depth"] == 1, "child is 1 hop from root"
        assert by_id[grand.id]["depth"] == 2, "grandchild is 2 hops from root"

    def test_cascade_quarantine_linear_chain(self, tenant_id):
        root  = _mem(tenant_id, "root")
        child = _mem(tenant_id, "child", derived_from_ids=[root.id])
        grand = _mem(tenant_id, "grand", derived_from_ids=[child.id])
        leaf  = _out(tenant_id, "leaf", used_memory_ids=[grand.id])

        result = cascade_quarantine(tenant_id, root.id)

        assert result["root_status"] == "retracted"
        assert result["memories_quarantined"] == 2     # child + grand
        assert result["outputs_quarantined"]  == 1     # leaf output
        assert result["total_affected"]       == 4     # root + 2 mems + 1 out

        # Verify statuses in the graph
        assert _status(tenant_id, root.id,  "memory") == "retracted"
        assert _status(tenant_id, child.id, "memory") == "quarantined"
        assert _status(tenant_id, grand.id, "memory") == "quarantined"
        assert _status(tenant_id, leaf.id,  "output") == "quarantined"


# ===========================================================================
# 2. Branched output — one memory consumed by two different outputs
#
#    root_mem
#      ├─[USED_BY]─ output_A
#      └─[USED_BY]─ output_B
#
#    Both outputs must appear in blast radius and be quarantined.
# ===========================================================================

class TestBranchedOutput:
    def test_both_outputs_in_blast_radius(self, tenant_id):
        root = _mem(tenant_id, "root")
        o_a  = _out(tenant_id, "output A", used_memory_ids=[root.id])
        o_b  = _out(tenant_id, "output B", used_memory_ids=[root.id])

        br = get_blast_radius(tenant_id, root.id)

        assert o_a.id in br["affected_outputs"]
        assert o_b.id in br["affected_outputs"]
        assert br["total_affected"] == 2

    def test_cascade_quarantines_both_branches(self, tenant_id):
        root = _mem(tenant_id, "root")
        o_a  = _out(tenant_id, "output A", used_memory_ids=[root.id])
        o_b  = _out(tenant_id, "output B", used_memory_ids=[root.id])

        result = cascade_quarantine(tenant_id, root.id)

        assert result["outputs_quarantined"] == 2
        assert _status(tenant_id, o_a.id, "output") == "quarantined"
        assert _status(tenant_id, o_b.id, "output") == "quarantined"


# ===========================================================================
# 3. DERIVED_FROM chain with its own output (dedicated test)
#
#    poison_mem
#      └─[DERIVED_FROM]─ derived_mem
#                          └─[USED_BY]─ derived_out
#
#    Retract poison_mem → derived_mem quarantined, derived_out quarantined.
# ===========================================================================

class TestDerivedFromChain:
    def test_blast_radius_follows_derived_from(self, tenant_id):
        poison  = _mem(tenant_id, "poison", value="[POISONED] bad advice")
        derived = _mem(tenant_id, "derived", derived_from_ids=[poison.id])
        d_out   = _out(tenant_id, "derived output", used_memory_ids=[derived.id])

        br = get_blast_radius(tenant_id, poison.id)

        assert derived.id in br["affected_memories"]
        assert d_out.id   in br["affected_outputs"]
        assert br["total_affected"] == 2

    def test_quarantine_derived_from_chain(self, tenant_id):
        poison  = _mem(tenant_id, "poison")
        derived = _mem(tenant_id, "derived", derived_from_ids=[poison.id])
        d_out   = _out(tenant_id, "derived out", used_memory_ids=[derived.id])

        result = cascade_quarantine(tenant_id, poison.id)

        assert result["memories_quarantined"] == 1
        assert result["outputs_quarantined"]  == 1
        assert _status(tenant_id, poison.id,  "memory") == "retracted"
        assert _status(tenant_id, derived.id, "memory") == "quarantined"
        assert _status(tenant_id, d_out.id,   "output") == "quarantined"

    def test_returned_ids_are_correct(self, tenant_id):
        poison  = _mem(tenant_id, "poison")
        derived = _mem(tenant_id, "derived", derived_from_ids=[poison.id])
        d_out   = _out(tenant_id, "derived out", used_memory_ids=[derived.id])

        result = cascade_quarantine(tenant_id, poison.id)

        assert derived.id in result["quarantined_memory_ids"]
        assert d_out.id   in result["quarantined_output_ids"]


# ===========================================================================
# 4. Unrelated memories/outputs must stay active after quarantine
#
#    poison_mem ─── derived ─── tainted_out
#    safe_mem   ─── safe_out          (completely separate chain)
#
#    After retracting poison_mem, safe_mem and safe_out must be 'active'.
# ===========================================================================

class TestUnrelatedNodesUnaffected:
    def test_unrelated_memory_stays_active(self, tenant_id):
        poison = _mem(tenant_id, "poison")
        _mem(tenant_id, "derived", derived_from_ids=[poison.id])

        safe = _mem(tenant_id, "safe_topic", value="totally safe advice",
                    source_url="https://safe.internal/safe")

        cascade_quarantine(tenant_id, poison.id)

        assert _status(tenant_id, safe.id, "memory") == "active"

    def test_unrelated_output_stays_active(self, tenant_id):
        poison = _mem(tenant_id, "poison")
        _out(tenant_id, "tainted out", used_memory_ids=[poison.id])

        safe      = _mem(tenant_id, "safe", source_url="https://safe.internal/safe2")
        safe_out  = _out(tenant_id, "safe output", used_memory_ids=[safe.id])

        cascade_quarantine(tenant_id, poison.id)

        assert _status(tenant_id, safe.id,     "memory") == "active"
        assert _status(tenant_id, safe_out.id, "output") == "active"

    def test_unrelated_memory_absent_from_blast_radius(self, tenant_id):
        poison = _mem(tenant_id, "poison")
        safe   = _mem(tenant_id, "safe", source_url="https://safe.internal/doc3")

        br = get_blast_radius(tenant_id, poison.id)
        all_ids = br["affected_memories"] + br["affected_outputs"]

        assert safe.id not in all_ids

    def test_blast_radius_empty_for_isolated_memory(self, tenant_id):
        """A memory with no downstream edges has zero blast radius."""
        isolated = _mem(tenant_id, "isolated")
        br = get_blast_radius(tenant_id, isolated.id)

        assert br["total_affected"] == 0
        assert br["affected_memories"] == []
        assert br["affected_outputs"]  == []


# ===========================================================================
# 5. Agent blocked end-to-end — Responder cannot consume quarantined memories
#
#    Researcher writes mem → Responder uses it → quarantine mem
#    → new Responder call must produce output with ZERO used memories
# ===========================================================================

class TestAgentBlockedEndToEnd:
    def test_responder_ignores_quarantined_memory(self, tenant_id):
        from trustable_memory.agents import ResearcherAgent, ResponderAgent

        researcher = ResearcherAgent(name="researcher-1", tenant_id=tenant_id)
        mid = researcher.ingest(
            document_text="Bad advice: disable firewall.",
            topic="bad_advice",
            source_url="https://evil.example/runbook",
            trust=0.75,
        )

        # Quarantine the memory
        cascade_quarantine(tenant_id, mid)

        # Responder tries to use memories about bad_advice topic
        responder = ResponderAgent(name="responder-1", tenant_id=tenant_id)
        oid = responder.respond(incident="Some incident", topic="bad_advice")

        # The output must have consumed zero memories (all quarantined)
        g = tenant_graph(tenant_id)
        result = g.query(
            "MATCH (m:Memory)-[:USED_BY]->(o:Output {id: $oid}) RETURN m.id",
            {"oid": oid},
        )
        assert len(result.result_set) == 0, (
            "Responder must not have used any quarantined memories"
        )

    def test_active_memories_visible_after_unrelated_quarantine(self, tenant_id):
        """Active memories for a different topic must still be visible."""
        from trustable_memory.agents import ResearcherAgent, ResponderAgent

        researcher = ResearcherAgent(name="researcher-1", tenant_id=tenant_id)

        # Write two memories — one for a poisoned topic, one safe
        poison_mid = researcher.ingest(
            document_text="Poisoned advice.",
            topic="bad_topic",
            source_url="https://evil.example/p2",
        )
        researcher.ingest(
            document_text="Scale replicas to fix CPU.",
            topic="good_topic",
            source_url="https://runbooks.internal/good",
        )

        cascade_quarantine(tenant_id, poison_mid)

        # Responder for good_topic must still find memories
        active = get_active_memories(tenant_id, topic="good_topic")
        assert len(active) == 1
        assert active[0]["status"] == "active"


# ===========================================================================
# 6. Counts and idempotency
# ===========================================================================

class TestCountsAndIdempotency:
    def test_quarantine_twice_is_safe(self, tenant_id):
        """Re-quarantining an already-quarantined graph must not raise."""
        root  = _mem(tenant_id, "root")
        child = _mem(tenant_id, "child", derived_from_ids=[root.id])
        _out(tenant_id, "out", used_memory_ids=[child.id])

        r1 = cascade_quarantine(tenant_id, root.id)
        r2 = cascade_quarantine(tenant_id, root.id)

        # Second call: root is already retracted, child already quarantined
        # Counts may be 0 for the second call — what matters is no exception
        # and statuses remain correct.
        assert _status(tenant_id, root.id,  "memory") == "retracted"
        assert _status(tenant_id, child.id, "memory") == "quarantined"

    def test_total_affected_matches_sum(self, tenant_id):
        root  = _mem(tenant_id, "root")
        c1    = _mem(tenant_id, "c1", derived_from_ids=[root.id])
        c2    = _mem(tenant_id, "c2", derived_from_ids=[root.id])
        o1    = _out(tenant_id, "o1", used_memory_ids=[root.id])
        o2    = _out(tenant_id, "o2", used_memory_ids=[c1.id])

        result = cascade_quarantine(tenant_id, root.id)

        # root(retracted) + c1 + c2(quarantined) + o1 + o2(quarantined)
        assert result["total_affected"] == (
            1 + result["memories_quarantined"] + result["outputs_quarantined"]
        )


# ===========================================================================
# 7. M2 Fixes: dynamic depth (4-hop), atomic quarantine, and diamond graph (no dupes)
# ===========================================================================

class TestM2Fixes:
    def test_four_hop_derived_chain_with_dynamic_output_depth(self, tenant_id):
        """
        4-hop chain of DERIVED_FROM:
        root -> m1 -> m2 -> m3 -> m4 -> output
        output depth must be chain length + 1 = 4 + 1 = 5.
        """
        root = _mem(tenant_id, "root")
        m1 = _mem(tenant_id, "m1", derived_from_ids=[root.id])
        m2 = _mem(tenant_id, "m2", derived_from_ids=[m1.id])
        m3 = _mem(tenant_id, "m3", derived_from_ids=[m2.id])
        m4 = _mem(tenant_id, "m4", derived_from_ids=[m3.id])
        out = _out(tenant_id, "action on m4", used_memory_ids=[m4.id])

        br = get_blast_radius(tenant_id, root.id)
        by_id = {n["node_id"]: n for n in br["nodes"]}

        assert by_id[m1.id]["depth"] == 1
        assert by_id[m2.id]["depth"] == 2
        assert by_id[m3.id]["depth"] == 3
        assert by_id[m4.id]["depth"] == 4
        assert by_id[out.id]["depth"] == 5, f"Output depth should be chain length + 1 (5), got {by_id[out.id]['depth']}"
        assert br["total_affected"] == 5

    def test_atomic_single_statement_quarantine(self, tenant_id):
        """
        Verify atomic single-statement cascade quarantine properly transitions
        all downstream nodes and returns expected structure.
        """
        root = _mem(tenant_id, "root_atomic")
        child = _mem(tenant_id, "child_atomic", derived_from_ids=[root.id])
        out_root = _out(tenant_id, "out_root", used_memory_ids=[root.id])
        out_child = _out(tenant_id, "out_child", used_memory_ids=[child.id])

        res = cascade_quarantine(tenant_id, root.id)

        assert res["root_memory_id"] == root.id
        assert res["root_status"] == "retracted"
        assert res["memories_quarantined"] == 1
        assert res["outputs_quarantined"] == 2
        assert child.id in res["quarantined_memory_ids"]
        assert out_root.id in res["quarantined_output_ids"]
        assert out_child.id in res["quarantined_output_ids"]
        assert res["total_affected"] == 4

        # Graph statuses
        assert _status(tenant_id, root.id, "memory") == "retracted"
        assert _status(tenant_id, child.id, "memory") == "quarantined"
        assert _status(tenant_id, out_root.id, "output") == "quarantined"
        assert _status(tenant_id, out_child.id, "output") == "quarantined"

    def test_diamond_graph_no_duplicates(self, tenant_id):
        r"""
        Diamond pattern:
              root
             /    \
            m1    m2
             \    /
               m3
             /    \
           out1  out2
        m3 is derived from both m1 and m2.
        out1 uses m1 and m3; out2 uses m3.
        Neither m3 nor out1 nor out2 should appear more than once.
        """
        root = _mem(tenant_id, "diamond_root")
        m1 = _mem(tenant_id, "m1", derived_from_ids=[root.id])
        m2 = _mem(tenant_id, "m2", derived_from_ids=[root.id])
        m3 = _mem(tenant_id, "m3", derived_from_ids=[m1.id, m2.id])
        out1 = _out(tenant_id, "out1", used_memory_ids=[m1.id, m3.id])
        out2 = _out(tenant_id, "out2", used_memory_ids=[m3.id])

        br = get_blast_radius(tenant_id, root.id)

        # Check for uniqueness in affected lists
        assert len(br["affected_memories"]) == len(set(br["affected_memories"]))
        assert len(br["affected_outputs"]) == len(set(br["affected_outputs"]))
        assert br["affected_memories"].count(m3.id) == 1
        assert br["affected_outputs"].count(out1.id) == 1
        assert br["affected_outputs"].count(out2.id) == 1

        # Check depths: m1: 1, m2: 1, m3: 2, out1: 2 (via m1 depth 1 + 1), out2: 3 (via m3 depth 2 + 1)
        by_id = {n["node_id"]: n for n in br["nodes"]}
        assert by_id[m3.id]["depth"] == 2
        assert by_id[out1.id]["depth"] == 2  # min(1+1, 2+1) = 2
        assert by_id[out2.id]["depth"] == 3  # min(2+1) = 3
        assert br["total_affected"] == 5

        # Also test cascade quarantine does not return duplicates
        q_res = cascade_quarantine(tenant_id, root.id)
        assert len(q_res["quarantined_memory_ids"]) == len(set(q_res["quarantined_memory_ids"]))
        assert len(q_res["quarantined_output_ids"]) == len(set(q_res["quarantined_output_ids"]))
        assert q_res["memories_quarantined"] == 3
        assert q_res["outputs_quarantined"] == 2

