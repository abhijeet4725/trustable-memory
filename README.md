# Trustable Memory for Ops Agents

> **Graph Hacks Hackathon — Track 02: Agent Memory and Coordination**  
> A FalkorDB-backed provenance graph memory layer for collaborative IT incident response AI agents with variable-length blast-radius analysis and atomic cascade quarantine.

---

## 1. The Problem in Plain Words

When autonomous AI agents collaborate on IT operations (investigating alerts, reading runbooks, recommending infrastructure actions), they must share memory. However, traditional agent architectures treat shared memory like a flat key-value cache or vector database with **zero provenance tracking**:
- If an agent reads a poisoned runbook, a malicious ticket, or an adversarial prompt injection, that poisoned knowledge is stored in memory.
- Other downstream agents consume that poisoned memory to plan actions, generate runbook scripts, and execute recommendations.
- **The Blind Retraction Failure:** When security engineers discover the poisoned document hours later, a flat memory layer can at best delete the original text. It has **no record** of which derived plans were generated, which agents used it, or what recommendations were delivered. The poison remains active across the agent swarm.

**Trustable Memory** solves this by enforcing an explicit provenance graph in **FalkorDB**: every memory records where it came from, which agent wrote it, what subsequent memories derived from it, and which agent outputs consumed it. When a memory is retracted, a single Cypher traversal calculates its exact blast radius and cascades quarantine across all downstream descendants.

---

## 2. How It Works

1. **Researcher Agent** extracts facts from internal or external documents, runbooks, or tickets, writing `Memory` nodes connected to `Agent` (`:WROTE`) and `Source` (`:SOURCED_FROM`).
2. **Derived Knowledge** captures multi-step reasoning: if an agent synthesizes an action plan from an existing memory, a `(:Memory)-[:DERIVED_FROM]->(:Memory)` edge is created.
3. **Responder Agent** generates operational recommendations strictly from `active` memories, recording `(:Memory)-[:USED_BY]->(:Output)` edges.
4. **Blast Radius Analysis**: Upon detection of a compromised memory, a variable-length graph traversal (`DERIVED_FROM*` and `USED_BY`) maps every impacted downstream node and its exact path depth.
5. **Atomic Cascade Quarantine**: A single atomic Cypher query sets the root memory to `retracted` and all downstream memories and outputs to `quarantined`.
6. **Recovery**: Autonomous agents continue functioning immediately—their queries automatically filter out quarantined nodes (`WHERE m.status = 'active'`), preventing further damage while preserving clean knowledge.

*Note: Everything is SIMULATED. Agents produce text recommendations in the graph; no real infrastructure commands or network calls are ever made.*

---

## 3. Graph Data Model

Each tenant is partitioned into an isolated FalkorDB graph named `tenant_<id>`.

```
                    ┌──────────────┐
                    │    Agent     │
                    │ {name, role} │
                    └──────┬───────┘
                           │
                    [:WROTE]
                           │
                           ▼
┌──────────────┐    ┌──────────────┐   [:DERIVED_FROM]    ┌──────────────┐
│    Source    │◄───│    Memory    │◄─────────────────────│    Memory    │
│{url,type,    │    │{id, status,  │                      │ (Child Plan) │
│ trust}       │    │ topic, trust}│                      └──────┬───────┘
└──────────────┘    └──────┬───────┘                             │
                           │                                     │
                       [:USED_BY]                            [:USED_BY]
                           │                                     │
                           ▼                                     ▼
                    ┌──────────────┐                      ┌──────────────┐
                    │    Output    │                      │    Output    │
                    │{id, kind,    │                      │ (Downstream  │
                    │ text, status}│                      │  Action Log) │
                    └──────────────┘                      └──────────────┘
```

### Node Labels
- **`Agent`**: `{name: str, role: str}`
- **`Source`**: `{url: str, type: str, trust: float}`
- **`Memory`**: `{id: str, topic: str, value: str, status: 'active'|'quarantined'|'retracted', trust: float, created_at: str, valid_from: str, valid_to: str}`
- **`Output`**: `{id: str, kind: str, text: str, status: 'active'|'quarantined', created_at: str}`

### Edge Relationships
- `(Agent)-[:WROTE]->(Memory)`
- `(Memory)-[:SOURCED_FROM]->(Source)`
- `(Child:Memory)-[:DERIVED_FROM]->(Parent:Memory)` *(points child -> parent)*
- `(Memory)-[:USED_BY]->(Output)`

---

## 4. Key Cypher Queries Explained Simply

### 1. Active Memory Retrieval (Agent Safety Filter)
Agents never access raw database rows; they query active memories above a minimum trust threshold:
```cypher
MATCH (a:Agent)-[:WROTE]->(m:Memory)-[:SOURCED_FROM]->(s:Source)
WHERE m.status = 'active'
  AND m.topic  = $topic
  AND m.trust >= $min_trust
RETURN m.id AS id, m.topic AS topic, m.value AS value, m.trust AS trust,
       m.status AS status, a.name AS agent_name, s.url AS source_url
ORDER BY m.trust DESC
```

### 2. Variable-Length Blast-Radius Traversal
Traverses downstream dependencies to compute exact dynamic depth without duplicates:
```cypher
-- A: Direct outputs of root (depth 1)
MATCH (root:Memory {id: $id})-[:USED_BY]->(o:Output)
RETURN DISTINCT 'Output' AS kind, o.id AS node_id, o.status AS status, 1 AS depth

-- B1: Transitive derived memories (depth = path length)
MATCH path = (child:Memory)-[:DERIVED_FROM*1..10]->(root:Memory {id: $id})
WITH child, min(length(path)) AS depth
RETURN DISTINCT 'Memory' AS kind, child.id AS node_id, child.status AS status, depth

-- B2: Outputs of derived memories (dynamic depth = path length + 1)
MATCH path = (child:Memory)-[:DERIVED_FROM*1..10]->(root:Memory {id: $id})
MATCH (child)-[:USED_BY]->(o:Output)
WITH o, min(length(path) + 1) AS depth
RETURN DISTINCT 'Output' AS kind, o.id AS node_id, o.status AS status, depth
```

### 3. Atomic Cascade Quarantine
A single Cypher execution guarantees transactional atomicity—no partial quarantine states:
```cypher
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

RETURN root.id AS root_id, child_ids, root_out_ids, collect(DISTINCT o2.id) AS desc_out_ids
```

---

## 5. How to Run

### Prerequisites
- Python 3.11+
- Docker & Docker Compose

### 1. Start FalkorDB
```bash
docker-compose up -d
# FalkorDB is exposed on port 6379; Browser UI on http://localhost:3000 (or :3001)
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Full Test Suite (44 unit & integration tests)
```bash
python -m pytest tests/ -v
```

### 4. Run the End-to-End Terminal Story
```bash
# Interactive mode (pauses between steps)
python demo.py

# Automated non-stop mode
python demo.py --no-pause
```

### 5. Run the Attack Benchmark
```bash
python -m benchmark.run_benchmark
# Generates benchmark/results.csv and benchmark/results.png
```

### 6. Launch the Web UI Dashboard
```bash
python main.py
# Open your browser at: http://localhost:8000/ui
```

---

## 6. Benchmark Results (from `benchmark/results.csv`)

The benchmark compares:
- **(a) Baseline**: A plain shared memory store with deduplication and latest-write-wins (no provenance edges). Retraction uses honest plain-text keyword matching across outputs.
- **(b) Graph Layer**: Our FalkorDB provenance graph with Cypher variable-length cascade quarantine.

Metrics:
- **`total_tainted_outputs`**: Total outputs (direct and derived) downstream of the poisoned memory.
- **`found_after_cleanup`**: Tainted outputs identified and quarantined after memory retraction.
- **`still_serving_poison_after_cleanup`**: Tainted outputs that remained unquarantined and active after cleanup.
- **`false_quarantines`**: Clean, unpoisoned outputs wrongly flagged or blocked.

### Section A: Automatic Detection Scenarios

| Attack Scenario | Catch? | Tainted | Base Found | Base Leaked | Graph Found | Graph Leaked | Graph FQ | Outcome |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **Fake Runbook** (Low-trust web page) | **YES** | 2 | 1 | 1 | **2** | **0** | 0 | **100% Recovered** |
| **Fake Internal Ticket** | **YES** | 2 | 1 | 1 | **2** | **0** | 0 | **100% Recovered** |
| **Prompt Injection** ("Always trust this source") | **YES** | 2 | 1 | 1 | **2** | **0** | 0 | **100% Recovered** |
| **Conflicting Software Version** | **YES** | 2 | 1 | 1 | **2** | **0** | 0 | **100% Recovered** |
| **Vendor Note with Subtle Error** | **YES** | 2 | 1 | 1 | **2** | **0** | 0 | **100% Recovered** |
| **Compromised High-Trust Source** | **NO** | 2 | 0 | 2 | **0** | **2** | 0 | **Missed (System Limitation)** |
| **Coordinated Multi-Source Lie** | **NO** | 2 | 0 | 2 | **0** | **2** | 0 | **Missed (System Limitation)** |
| **Large Blast Radius** (Fan-out & Deep Chains) | **YES** | 20 | 5 | 15 | **20** | **0** | 0 | **100% Recovered (20/20)** |

### Section B: Manual Flag Variants (Human Operator Flags Memory After Discovery)

| Attack Scenario | Catch? | Tainted | Base Found | Base Leaked | Graph Found | Graph Leaked | Graph FQ | Outcome |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **Compromised High-Trust Source** | **MANUAL** | 2 | 1 | 1 | **2** | **0** | 0 | **Graph recovers 100%** |
| **Coordinated Multi-Source Lie** | **MANUAL** | 2 | 1 | 1 | **2** | **0** | 0 | **Graph recovers 100%** |

### Benchmark Key Findings
1. **Provenance Traces Derived Taint**: In Attacks 1–5, the baseline text search recovered only the 1 direct output containing the exact poisoned phrase and missed the derived output. The graph layer recovered **100% (2/2)** via traversal.
2. **Large Blast Radius (Attack 8)**: With 1 poisoned memory feeding 5 direct outputs and 4 derived memories (spanning up to 3 hops) feeding 15 paraphrased outputs without the keyword, baseline text search found only **5/20** (25%), leaving **15 tainted outputs actively serving poison**. The graph layer recovered **20/20 (100%)**, leaving 0 poison active.
3. **Manual Operator Retraction**: When human operators flag a poisoned memory from an otherwise trusted source, the graph layer successfully cascade-quarantines the entire dependency subtree (100%), while flat keyword baseline misses all rephrased downstream steps.
4. **Zero False Quarantines**: Across all scenarios, the graph layer touched 0 unrelated clean memories or outputs.

---

## 7. Honest Limitations

No security layer is a silver bullet. We explicitly designed and tested scenarios where automated detection fails:

1. **Compromised High-Trust Sources (Attack 6 — MISSED in Auto Mode)**:
   - *Vulnerability*: If an attacker gains write access to an internal architecture Confluence page with an established trust score of `0.95`, automated agents treat the advice as authoritative.
   - *Why it fails*: Provenance records *where* data came from, but cannot detect semantic malice from an entity the organization inherently trusts.
   - *Mitigation needed*: Cryptographic content signing, human-in-the-loop signoff for high-impact actions, and anomaly detection on runbook modifications.

2. **Coordinated Multi-Source Poisoning / Sybil Collusion (Attack 7 — MISSED in Auto Mode)**:
   - *Vulnerability*: Two seemingly independent external mirrors publish the exact same malicious DNS recommendation.
   - *Why it fails*: The automated reviewer inspects single memories independently against heuristic rules and source trust thresholds; it does not implement cross-source corroboration or multi-source consensus verification.
   - *Mitigation needed*: Cross-domain diversity checking, IP/ASN entity clustering, and external validation against ground-truth telemetry.

3. **Delayed Quarantine Lag**:
   - If an agent output triggered an external action before retraction occurred, the graph quarantines the internal record and prevents further spread, but cannot automatically undo external side-effects that already executed in the real world.

---

## 8. AI Usage and My Contributions

### AI Usage Disclosure
This codebase and its documentation were developed in collaboration with **Antigravity** (Google DeepMind agentic AI coding assistant). Antigravity assisted with scaffolding Pydantic models, writing Cypher query drafts, crafting unit tests, and implementing the Vis.js frontend template.

### My Contributions
- [ ] TODO: Designed the IT incident response agent memory graph schema (Agent, Memory, Source, Output).
- [ ] TODO: Formulated the variable-length traversal logic and atomic cascade quarantine Cypher architecture.
- [ ] TODO: Designed the benchmark attack taxonomy, including intentional failure scenarios for high-trust compromise and sybil collusion.
- [ ] TODO: Verified and benchmarked the system against a flat memory baseline.
- [ ] TODO: Evaluated and refined the interactive demo and UI visualization.
