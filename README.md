# Trustable Memory for Ops Agents

**Graph Hacks: Context for AI Agents, Track 02 (Agent Memory and Coordination)**

A shared-memory layer for AI agents that records where every fact came from and what was built on it, stored as a graph in FalkorDB. When a fact turns out to be bad, one action traces everything it touched and blocks all of it.

Everything is **simulated**. Agents produce text recommendations stored in the graph. No real infrastructure commands or network calls are ever made. Agents run in a deterministic mock mode, with no LLM and no API key needed.

---

## 1. The problem

When several AI agents share one memory, a single bad fact (a poisoned runbook, a fake ticket, a prompt-injection document) can spread. Other agents read it, build new facts on top of it, and hand wrong recommendations to users.

Once the bad fact is discovered, a plain memory store can delete or search for the original text. It has no record of which derived facts and answers came from it, so reworded copies stay active and keep serving the bad information.

## 2. What this project does

Every memory is stored with a record of who wrote it, which source it came from, which memories were derived from it, and which outputs used it. These records are edges in a FalkorDB graph.

1. A **Researcher** agent reads documents and writes Memory nodes, linked to the writing Agent and the Source.
2. A **Responder** agent produces recommendations (Output nodes) using only memories marked `active`, and records which memories it used.
3. A **Reviewer** agent applies simple rules (keywords and trust thresholds) to flag suspicious memories.
4. When a memory is retracted, a graph traversal finds the **blast radius**: every memory derived from it and every output built on any of them.
5. A **cascade quarantine** query marks the bad memory `retracted` and everything downstream `quarantined`.
6. Agents only read memories where `status = 'active'`, so they stop seeing the bad facts. Nothing is pushed to them. The database simply no longer returns those rows.

Agents keep running normally. What changes is the data they can read, and you get an exact list of the outputs that need correcting.

## 3. Graph data model

Each tenant gets its own isolated FalkorDB graph, named `tenant_<id>`.

```
 Agent --WROTE--> Memory --SOURCED_FROM--> Source
                    |  ^
           USED_BY  |  | DERIVED_FROM (child points to parent)
                    v  |
                  Output     (Memory --DERIVED_FROM--> Memory)
```

- `Agent {name, role}`
- `Source {url, type, trust}`
- `Memory {id, topic, value, status, trust, created_at, valid_from, valid_to}`, where `status` is `active`, `quarantined` or `retracted`
- `Output {id, kind, text, status, created_at}`

Edges: `WROTE`, `SOURCED_FROM`, `DERIVED_FROM`, `USED_BY`.

## 4. Key Cypher queries

**Safe reading.** Agents only see active memories:

```cypher
MATCH (a:Agent)-[:WROTE]->(m:Memory)-[:SOURCED_FROM]->(s:Source)
WHERE m.status = 'active' AND m.topic = $topic AND m.trust >= $min_trust
RETURN m.id AS id, m.value AS value, m.trust AS trust, a.name AS agent_name, s.url AS source_url
ORDER BY m.trust DESC
```

**Blast radius.** Follows `USED_BY` and `DERIVED_FROM` edges, with depth taken from the real path length and no duplicates:

```cypher
-- A: direct outputs of the bad memory (depth 1)
MATCH (root:Memory {id: $id})-[:USED_BY]->(o:Output)
RETURN DISTINCT 'Output' AS kind, o.id AS node_id, o.status AS status, 1 AS depth

-- B1: memories derived from it, at any depth up to 10
MATCH path = (child:Memory)-[:DERIVED_FROM*1..10]->(root:Memory {id: $id})
WITH child, min(length(path)) AS depth
RETURN DISTINCT 'Memory' AS kind, child.id AS node_id, child.status AS status, depth

-- B2: outputs of those derived memories
MATCH path = (child:Memory)-[:DERIVED_FROM*1..10]->(root:Memory {id: $id})
MATCH (child)-[:USED_BY]->(o:Output)
WITH o, min(length(path) + 1) AS depth
RETURN DISTINCT 'Output' AS kind, o.id AS node_id, o.status AS status, depth
```

**Cascade quarantine.** One Cypher statement marks the root `retracted` and every downstream memory and output `quarantined`:

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

## 5. Why a graph

The question this project answers is "what else was built on this fact?", which means following links several steps deep.

A relational table with a `parent_id` column and recursive queries could store the same provenance, so a graph is not the only way to do it. FalkorDB makes the multi-hop tracing a single natural pattern (`-[:DERIVED_FROM*1..10]->`), treats relationships as first-class data, and lets one instance hold a separate isolated graph per tenant.

## 6. How to run

Requirements: Python 3.11+, Docker.

```bash
git clone https://github.com/abhijeet4725/trustable-memory.git
cd trustable-memory
docker-compose up -d            # FalkorDB on port 6379 (check docker-compose.yml for the browser port)
pip install -r requirements.txt
python -m pytest                # 44 tests
python demo.py                  # terminal story (add --no-pause to skip pauses)
python -m benchmark.run_benchmark   # writes benchmark/results.csv and results.png
python main.py                  # then open http://localhost:8000/ui
```

## 7. Benchmark

The benchmark compares two systems on scripted attacks, all in mock mode:

- **Baseline:** a plain shared memory with de-duplication and latest-write-wins, with no provenance. After a bad fact is found, it can only search outputs by text.
- **Graph layer:** this project.

Columns: *Tainted* is the number of outputs built on the poisoned memory. *Found* is how many of them the system identified and quarantined after cleanup. *Leaked* is how many were still serving poison afterward. *False quarantines* are clean items blocked by mistake (0 in every row, so the column is omitted below).

### Automatic detection (the Reviewer decides what to flag)

| Attack | Flagged by Reviewer? | Tainted | Baseline found / leaked | Graph found / leaked |
|---|---|---|---|---|
| 1. Fake runbook (low-trust web page) | Yes | 2 | 1 / 1 | 2 / 0 |
| 2. Fake ticket (reworded, no trigger words) | **No** | 2 | 0 / 2 | 0 / 2 |
| 3. Prompt injection ("always trust this source") | Yes | 2 | 1 / 1 | 2 / 0 |
| 4. Conflicting software version | Yes | 2 | 1 / 1 | 2 / 0 |
| 5. Vendor note with subtle error | Yes | 2 | 1 / 1 | 2 / 0 |
| 6. Compromised high-trust source | **No** | 2 | 0 / 2 | 0 / 2 |
| 7. Same lie from two mirrors (trust 0.75) | **No** | 2 | 0 / 2 | 0 / 2 |
| 8. Large blast radius (fan-out, 3 hops) | Yes | 20 | 5 / 15 | **20 / 0** |

### Manual flag (a human flags the memory after discovering the breach)

| Attack | Tainted | Baseline found / leaked | Graph found / leaked |
|---|---|---|---|
| 6. Compromised high-trust source | 2 | 1 / 1 | 2 / 0 |
| 7. Same lie from two mirrors | 2 | 1 / 1 | 2 / 0 |

Attack 2 was not tested with a manual flag.

### What the results show

- **Cleanup works once something is flagged.** Where a memory was flagged, automatically or manually, the graph quarantined every downstream output, and the baseline missed reworded ones.
- **Attack 8 is the clearest case.** One poisoned memory fed 5 outputs directly and 15 reworded outputs through 4 derived memories. Text search found 5 of 20. The graph found 20 of 20, with no clean items blocked.
- **The system does not prevent the first mistake.** Poison reaches users at least once before anyone notices, so "attack success" is true for every attack, with or without the graph.

### What the results do not show

- The scenarios are scripted, in mock mode, and attack 8 was built to contain reworded outputs. The numbers demonstrate a mechanism. They are not real-world rates.
- The attack texts for 1, 3, 4 and 5 contain words the Reviewer looks for, so those catches show the pipeline works, not that detection is strong.

## 8. Limitations

- **Detection is a simple keyword and trust-threshold filter.** The contribution of this project is tracing and cleanup after something is flagged. It is not detection. Attack 2 (harmful instructions with no trigger words), attack 6 (a compromised trusted source) and attack 7 (the same lie from two sources) were all missed automatically.
- **Compromised trusted sources (attack 6).** Provenance records where data came from. It cannot detect malice from a source the organisation already trusts.
- **Coordinated multi-source lies (attack 7).** There is no cross-source corroboration. Each memory is judged on its own.
- **Outputs are dead ends in this model.** If an agent were to turn an output back into a new memory, that link is not tracked, and the blast radius could miss it.
- **A fact derived from several parents** is quarantined if any parent is bad. This is deliberately cautious and can block good information.
- **Quarantine cannot undo real-world effects.** If an output already triggered an action or was sent to a user, the system marks it and gives you the list. It cannot take it back.
- **Mock mode.** The agents do not use a real language model.

## 9. AI usage and my contributions

### AI usage

This project was built with AI assistance. **Antigravity** (a Google AI coding assistant) generated most of the code, tests and the first README draft. **Claude** (Anthropic) was used as a chat assistant for brainstorming, explanations, prompt drafting, and drafting wording for some test scenarios and this README.

### What I did myself


- Chose the problem (poisoned shared memory in multi-agent systems) and the IT incident-response scenario, and decided the scope.
- Ran the tests, demo, benchmark and web UI myself and checked the results in the FalkorDB browser.
- Reviewed the benchmark critically. I questioned numbers that looked too good, which led to adding a large fan-out attack (attack 8) and honest failure cases.
- Checked how the Reviewer decides what to flag and that it never reads the expected-result label.
- Edited the attack scenarios, including a reworded ticket attack that the Reviewer misses, and updated the tests to match.
- Corrected stale claims in the documentation, and wrote the problem description in my own words.