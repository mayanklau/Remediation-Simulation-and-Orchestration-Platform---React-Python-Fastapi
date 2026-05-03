# Knowledge Base + Planner Foundation

The platform now follows the KB + Planner Agent foundation architecture from the provided reference.

Implemented foundation contracts:

- MongoDB is the canonical system of record.
- Qdrant, PageIndex, Neo4j, and S3-compatible storage are derived indexes that rebuild from MongoDB.
- Every KB record uses an OCSF-style contract with `record_id`, `tenant_id`, `entity_ids`, `source_scanner`, temporal validity, confidence, classification, hashes, and embedding model version.
- Ingestion is idempotent on `source_id + content_hash`.
- Entity resolution happens before canonical storage.
- PII scrubbing happens before vectorization.
- Retrieval uses a single KB facade with semantic, keyword, graph, and temporal modes.
- Results merge by `record_id`, rerank, hydrate from MongoDB, and return with provenance.
- The planner is a deterministic shell using intent extraction, policy gates, retrieval planning, manifest-constrained DAG execution, grounding, verification, W3C PROV, and human approval for side effects.
- Tool and module agents register by typed manifest, including scopes, classifications, cost, side effects, approval needs, and KB dependencies.
- The on-prem posture uses small-context discipline: deterministic routing first, bounded retrieval chunks, budgets, cache-friendly prompts, and LLM calls only for hard cases.

The exposed contract lives at:

- API: `/api/kb-planner-foundation`
- UI: `KB Planner`

Production integrations still need customer-specific runtime services and credentials, but the app now has the foundation contract required for module agents to register cleanly against a shared knowledge and planning layer.
