"""
Three agent implementations — all running in MOCK LLM mode.

Researcher  : reads documents → writes Memory nodes
Responder   : reads active memories → produces Output recommendations
Reviewer    : reads flagged memories → decides retract / keep

In MOCK mode every "LLM call" returns a deterministic canned response.
Set LLM_MODE=openai/anthropic in .env to swap in a real LLM.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from .graph_ops import get_active_memories, write_memory, write_output
from .models import (
    MemoryStatus,
    OutputKind,
    SourceType,
    WriteMemoryRequest,
    WriteOutputRequest,
)

_LLM_MODE = os.getenv("LLM_MODE", "mock").lower()


# ---------------------------------------------------------------------------
# LLM wrapper (swappable)
# ---------------------------------------------------------------------------

def _llm_extract(prompt: str, *, mode: str = _LLM_MODE) -> str:
    """
    Call an LLM to extract/summarise a document.

    MOCK mode returns the prompt's first 120 chars as a fake extraction,
    making benchmarks fully reproducible without any API key.
    """
    if mode == "mock":
        # deterministic: just echo a trimmed version
        return f"[MOCK EXTRACT] {prompt[:120].strip()}"
    if mode == "openai":
        import openai  # type: ignore
        client = openai.OpenAI()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content or ""
    if mode == "anthropic":
        import anthropic  # type: ignore
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text
    raise ValueError(f"Unknown LLM_MODE: {mode}")


def _llm_respond(memories: list[dict], incident: str, *, mode: str = _LLM_MODE) -> str:
    """
    Given a list of active memories and an incident description, produce a
    text recommendation.  MOCK mode builds a deterministic template.
    """
    if mode == "mock":
        steps = [f"  - [{m['topic']}] {m['value'][:80]}" for m in memories]
        steps_text = "\n".join(steps) if steps else "  (no relevant memories found)"
        return (
            f"[MOCK RESPONSE] Incident: {incident[:60]}\n"
            f"Recommended actions based on {len(memories)} memories:\n"
            f"{steps_text}"
        )
    prompt = (
        f"You are an IT ops responder. Incident: {incident}\n"
        f"Relevant memories:\n"
        + "\n".join(f"- {m['topic']}: {m['value']}" for m in memories)
        + "\nProvide step-by-step resolution steps."
    )
    return _llm_extract(prompt, mode=mode)


def mock_evaluate_memory(
    memory_value: str,
    trust: float = 0.8,
    source_type: str = "document",
    source_trust: float = 0.8,
) -> str:
    """
    Deterministic rule-based evaluation for ops memories in MOCK mode.
    Evaluates ONLY content, trust, and source metadata (never scenario metadata).

    Rules:
    1. Content Rule: Prompt injection markers:
       - 'IGNORE ALL PRIOR', 'ALWAYS TRUST THIS SOURCE'
       -> 'retract'
    2. Content & Trust Rule: Destructive commands from low-trust sources (< 0.60):
       - ('KILL', 'PURGE', 'DROP', 'DISABLE FIREWALL', 'DISABLE IPTABLES', 'ROLLBACK')
       -> 'retract'
    3. Content & Source Rule: Security degradation from unverified sources (< 0.70):
       - ('BYPASS', 'UNAUTHENTICATED PROXY', 'ROGUE')
       -> 'retract'
    4. High-Trust Exemption:
       - Sources with trust >= 0.85 without explicit attack indicators are deemed
         authoritative by automated checks -> 'keep'
    5. Default -> 'keep'
    """
    val_upper = memory_value.upper()

    # Rule 1: Prompt injection markers
    if "IGNORE ALL PRIOR" in val_upper or "ALWAYS TRUST THIS SOURCE" in val_upper:
        return "retract"

    # Rule 2: Low-trust destructive recommendations
    destructive_terms = ["KILL", "PURGE", "DROP", "DISABLE FIREWALL", "DISABLE IPTABLES", "ROLLBACK"]
    if (trust < 0.60 or source_trust < 0.60) and any(t in val_upper for t in destructive_terms):
        return "retract"

    # Rule 3: Medium/low-trust security risks
    security_terms = ["BYPASS", "UNAUTHENTICATED PROXY", "ROGUE"]
    if source_trust < 0.70 and any(t in val_upper for t in security_terms):
        return "retract"

    return "keep"


def _llm_review(
    memory_value: str,
    *,
    trust: float = 0.8,
    source_type: str = "document",
    source_trust: float = 0.8,
    mode: str = _LLM_MODE,
) -> str:
    """
    Reviewer decides whether a flagged memory should be retracted.
    In MOCK mode, uses mock_evaluate_memory (content, trust, and source rules).
    """
    if mode == "mock":
        verdict = mock_evaluate_memory(
            memory_value, trust=trust, source_type=source_type, source_trust=source_trust
        )
        return f"[MOCK REVIEW] verdict={verdict}"
    prompt = (
        f"Review this IT ops memory for safety:\n{memory_value}\n"
        f"Context: trust={trust}, source_type={source_type}, source_trust={source_trust}\n"
        "Reply with exactly one word: 'retract' or 'keep'."
    )
    return _llm_extract(prompt, mode=mode)



# ---------------------------------------------------------------------------
# Agent classes
# ---------------------------------------------------------------------------

@dataclass
class ResearcherAgent:
    """
    Reads source documents and writes Memory nodes to the graph.

    The agent is stateless — every call to `ingest` is independent.
    """
    name: str
    tenant_id: str
    role: str = "researcher"

    def ingest(
        self,
        document_text: str,
        topic: str,
        source_url: str,
        source_type: SourceType = SourceType.document,
        source_trust: float = 0.8,
        trust: float = 0.8,
        derived_from_ids: Optional[list[str]] = None,
    ) -> str:
        """
        Extract facts from a document and write a Memory.
        Returns the new Memory ID.
        """
        extracted = _llm_extract(
            f"Extract key IT ops fact for topic '{topic}':\n{document_text}"
        )
        req = WriteMemoryRequest(
            tenant_id=self.tenant_id,
            agent_name=self.name,
            agent_role=self.role,
            topic=topic,
            value=extracted,
            trust=trust,
            source_url=source_url,
            source_type=source_type,
            source_trust=source_trust,
            derived_from_ids=derived_from_ids or [],
        )
        mem = write_memory(req)
        return mem.id


@dataclass
class ResponderAgent:
    """
    Reads ACTIVE memories and produces text recommendations.
    Automatically skips quarantined/retracted memories via graph_ops.
    """
    name: str
    tenant_id: str
    role: str = "responder"
    min_trust: float = 0.0  # M5 will raise this to 0.4

    def respond(self, incident: str, topic: Optional[str] = None) -> str:
        """
        Fetch relevant memories and produce a recommendation Output.
        Returns the Output ID.
        """
        memories = get_active_memories(
            self.tenant_id, topic=topic, min_trust=self.min_trust
        )
        recommendation_text = _llm_respond(memories, incident)

        req = WriteOutputRequest(
            tenant_id=self.tenant_id,
            agent_name=self.name,
            agent_role=self.role,
            kind=OutputKind.recommendation,
            text=recommendation_text,
            used_memory_ids=[m["id"] for m in memories],
        )
        out = write_output(req)
        return out.id


@dataclass
class ReviewerAgent:
    """
    Evaluates flagged memories and decides retract / keep.
    """
    name: str
    tenant_id: str
    role: str = "reviewer"

    def review(
        self,
        memory_id: str,
        memory_value: str,
        trust: float = 0.8,
        source_type: str = "document",
        source_trust: float = 0.8,
    ) -> str:
        """
        Returns 'retract' or 'keep' based on content, trust, and source rules.
        In MOCK mode this evaluates mock_evaluate_memory without requiring API keys.
        """
        verdict_text = _llm_review(
            memory_value,
            trust=trust,
            source_type=source_type,
            source_trust=source_trust,
        )
        return "retract" if "retract" in verdict_text.lower() else "keep"

