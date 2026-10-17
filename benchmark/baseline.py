"""
benchmark/baseline.py

A FAIR plain shared-memory baseline store without graph provenance.
Key features:
  - De-duplication: duplicate (topic, value) writes return the existing entry.
  - Latest-write-wins: newer writes on a topic take precedence for responder queries.
  - No graph: no provenance edges (WROTE, SOURCED_FROM, USED_BY, DERIVED_FROM).
  - No status field: memories and outputs are either in the store or deleted.
  - Recovery via text search: when a memory is retracted, the baseline must rely
    on substring/text search across all stored outputs to identify tainted responses.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class BaselineMemory:
    id: str
    topic: str
    value: str
    source_url: str
    created_at: str


@dataclass
class BaselineOutput:
    id: str
    kind: str
    text: str
    created_at: str
    quarantined: bool = False  # simulated flag for when text search deletes/flags output


class BaselineMemoryStore:
    def __init__(self):
        # topic -> list of memories (ordered by insertion time)
        self.memories: dict[str, list[BaselineMemory]] = {}
        # memory_id -> BaselineMemory for fast ID lookup
        self.memory_by_id: dict[str, BaselineMemory] = {}
        # all outputs
        self.outputs: list[BaselineOutput] = []

    def write_memory(self, topic: str, value: str, source_url: str) -> str:
        """
        Write a memory with deduplication.
        If identical topic and value already exists, reuse its ID.
        """
        now = datetime.now(timezone.utc).isoformat()
        if topic in self.memories:
            for existing in self.memories[topic]:
                if existing.value.strip() == value.strip():
                    return existing.id

        mid = str(uuid.uuid4())
        mem = BaselineMemory(
            id=mid,
            topic=topic,
            value=value,
            source_url=source_url,
            created_at=now,
        )
        if topic not in self.memories:
            self.memories[topic] = []
        self.memories[topic].append(mem)
        self.memory_by_id[mid] = mem
        return mid

    def get_memories(self, topic: Optional[str] = None) -> list[BaselineMemory]:
        """
        Retrieve memories. Latest-write-wins: returns most recent memories first.
        """
        if topic:
            items = self.memories.get(topic, [])
            return list(reversed(items))
        all_items: list[BaselineMemory] = []
        for topic_items in self.memories.values():
            all_items.extend(topic_items)
        return sorted(all_items, key=lambda x: x.created_at, reverse=True)

    def write_output(self, kind: str, text: str) -> str:
        """
        Record an output. Notice: NO provenance edges link this to memories.
        """
        oid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        out = BaselineOutput(id=oid, kind=kind, text=text, created_at=now)
        self.outputs.append(out)
        return oid

    def retract(self, memory_id: str, search_query: Optional[str] = None) -> dict:
        """
        Fair baseline recovery:
        1. Remove the retracted memory from store.
        2. Since there are NO graph edges (no USED_BY), search outputs using plain text
           search (substring matching) for the memory's content or search_query.
        """
        mem = self.memory_by_id.pop(memory_id, None)
        if mem:
            if mem.topic in self.memories:
                self.memories[mem.topic] = [m for m in self.memories[mem.topic] if m.id != memory_id]

        query = search_query or (mem.value if mem else "")
        recovered_output_ids: list[str] = []

        if query:
            # Baseline searches output text for key phrases from the retracted memory
            query_lower = query.lower()
            for out in self.outputs:
                if not out.quarantined and query_lower in out.text.lower():
                    out.quarantined = True
                    recovered_output_ids.append(out.id)

        return {
            "retracted_memory_id": memory_id,
            "recovered_output_ids": recovered_output_ids,
            "outputs_recovered_count": len(recovered_output_ids),
        }
