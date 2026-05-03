def build_kb_planner_foundation() -> dict:
    stores = foundation_stores()
    ingestion_pipeline = ingestion_stages()
    planner_pipeline = planner_stages()
    manifest = tool_manifest()
    non_negotiables = kb_non_negotiables() + planner_non_negotiables()
    return {
        "summary": {
            "canonical_store": "mongodb",
            "derived_stores": len([store for store in stores if not store["canonical"]]),
            "ingestion_stages": len(ingestion_pipeline),
            "retrieval_modes": len(retrieval_facade()["modes"]),
            "planner_stages": len(planner_pipeline),
            "registered_capabilities": len(manifest),
            "non_negotiables": len(non_negotiables),
            "status": "implemented_contract",
            "verdict": "aligned_to_kb_planner_foundation",
        },
        "guiding_principles": [
            "MongoDB is the system of record; Qdrant, PageIndex, Neo4j, and S3 are rebuildable derived indexes.",
            "The planner is a deterministic shell with model calls inside controlled steps.",
            "Security retrieval is hybrid: exact, semantic, graph, and temporal.",
            "OCSF-style records are typed, versioned, tenant-scoped, and signed before indexing.",
            "LLM calls are skipped whenever deterministic routing, cache, or manifest rules can answer safely.",
        ],
        "data_contract": {
            "required_fields": ["record_id", "ocsf", "tenant_id", "entity_ids", "source_scanner", "collected_at", "valid_from", "valid_to", "confidence", "classification", "content_hash", "signing_hash", "embedding_model_version"],
            "foreign_key_rule": "record_id is the foreign key in vector payloads, PageIndex metadata, graph nodes, and object metadata.",
            "rebuild_rule": "If a derived store disappears, rebuild it from MongoDB without losing canonical facts.",
            "idempotency_key": ["source_id", "content_hash"],
        },
        "stores": stores,
        "ingestion_pipeline": ingestion_pipeline,
        "retrieval_facade": retrieval_facade(),
        "planner_pipeline": planner_pipeline,
        "tool_manifest": manifest,
        "non_negotiables": non_negotiables,
        "build_order": [
            "Define OCSF/Pydantic record wrapper and entity model.",
            "Stand up MongoDB, Qdrant, PageIndex, Neo4j, and S3-compatible storage behind interfaces.",
            "Build ingestors through normalizer, entity resolver, PII scrubber, and canonical Mongo write.",
            "Add hybrid retrieval and reranking behind the KB facade.",
            "Create eval harness and golden query set before tuning retrieval.",
            "Register tools and module agents through a typed manifest.",
            "Add deterministic router and DAG planner before adding model reasoning.",
            "Attach LLM only for uncertain or high-context queries with structured outputs.",
            "Write provenance, verification, budgets, and human approval gates.",
            "Register the first module agent and validate end-to-end.",
        ],
        "open_decisions": [
            {"item": "Embedding model", "default": "bge-m3", "revisit_when": "Customer mandates NVIDIA stack"},
            {"item": "Reranker", "default": "bge-reranker-base", "revisit_when": "Latency budget is exhausted"},
            {"item": "Object storage", "default": "S3-compatible abstraction", "revisit_when": "Customer has mandated storage platform"},
            {"item": "Reasoning model", "default": "Qwen/Llama/local SLM via provider abstraction", "revisit_when": "GPU footprint or data residency changes"},
            {"item": "Keyword path", "default": "Mongo text/Atlas Search", "revisit_when": "Log-style recall requires OpenSearch"},
        ],
    }


def foundation_stores() -> list[dict]:
    return [
        {"id": "mongodb", "role": "Canonical store and audit history", "tool": "MongoDB", "canonical": True, "rebuild_source": "self", "tenant_isolation": "tenant_id shard key and collection-level indexes"},
        {"id": "qdrant", "role": "Semantic vectors", "tool": "Qdrant", "canonical": False, "rebuild_source": "MongoDB KBRecord", "tenant_isolation": "per-tenant collections"},
        {"id": "pageindex", "role": "Large document structure", "tool": "PageIndex", "canonical": False, "rebuild_source": "MongoDB record plus object blob", "tenant_isolation": "tenant metadata and scoped indexes"},
        {"id": "neo4j", "role": "Relationships, attack paths, identity graph, W3C PROV", "tool": "Neo4j", "canonical": False, "rebuild_source": "MongoDB entities and events", "tenant_isolation": "per-tenant database or tenant labels"},
        {"id": "s3", "role": "Raw blobs and immutable artifacts", "tool": "S3-compatible storage", "canonical": False, "rebuild_source": "MongoDB metadata", "tenant_isolation": "tenant bucket/prefix policy"},
    ]


def ingestion_stages() -> list[dict]:
    return [
        {"id": "source", "name": "Source connector", "input": "scanner, document, API, or export", "output": "raw payload", "gates": ["source_id", "tenant_id", "collection_time"]},
        {"id": "normalize", "name": "OCSF normalizer", "input": "raw payload", "output": "typed security record", "gates": ["schema_version", "source_scanner", "required_fields"]},
        {"id": "entity_resolution", "name": "Entity resolution", "input": "typed record", "output": "entity_ids", "gates": ["asset_key", "identity_key", "confidence"]},
        {"id": "pii_scrub", "name": "PII scrubber", "input": "record content", "output": "scrubbed content", "gates": ["classification", "scrub_rules", "pre_embed_check"]},
        {"id": "canonical_write", "name": "Canonical Mongo write", "input": "scrubbed record", "output": "KBRecord", "gates": ["content_hash", "signing_hash", "idempotency_key"]},
        {"id": "derived_indexes", "name": "Derived index fanout", "input": "record.created", "output": "vector, graph, page, object indexes", "gates": ["record_id", "embedding_model_version", "cache_invalidation"]},
    ]


def retrieval_facade() -> dict:
    return {
        "rule": "Planner and module agents call one KB facade, never individual stores directly.",
        "modes": ["semantic", "keyword", "graph", "temporal"],
        "merge_key": "record_id",
        "flow": ["fan_out", "merge_by_record_id", "rerank", "hydrate_from_mongo", "return_with_provenance"],
        "safeguards": ["tenant_scope_required", "classification_gate", "freshness_window", "max_context_chunks_10"],
    }


def planner_stages() -> list[dict]:
    return [
        {"id": "intent", "name": "Intent and entity extraction", "input": "user query", "output": "typed intent", "gates": ["deterministic_classifier_first"]},
        {"id": "policy", "name": "Policy/RBAC/classification gate", "input": "intent", "output": "allow or deny", "gates": ["required_scope", "classification_allowed"]},
        {"id": "retrieval_plan", "name": "Retrieval plan", "input": "intent", "output": "hybrid KB search plan", "gates": ["modes", "filters", "budget"]},
        {"id": "tool_dag", "name": "Tool DAG", "input": "retrieved facts", "output": "manifest-constrained plan", "gates": ["registered_tool", "json_schema_output"]},
        {"id": "execution", "name": "Parallel execution", "input": "DAG", "output": "step results", "gates": ["max_steps", "max_wall_time", "max_cost"]},
        {"id": "grounding", "name": "Aggregation and grounding", "input": "step results", "output": "grounded answer", "gates": ["record_id_citations", "no_uncited_claims"]},
        {"id": "verification", "name": "Verification and provenance", "input": "grounded answer", "output": "response or HITL request", "gates": ["w3c_prov_write", "side_effect_approval"]},
    ]


def tool_manifest() -> list[dict]:
    return [
        {"agent_id": "crvm.attack_path", "description": "Builds vulnerability chains and before/after remediation risk.", "required_scopes": ["finding:read", "report:read"], "data_classifications": ["internal"], "side_effects": False, "requires_approval": False, "kb_dependencies": ["mongodb", "neo4j", "qdrant"]},
        {"agent_id": "crvm.remediation_planner", "description": "Creates simulation-first remediation plans with rollback and evidence.", "required_scopes": ["simulation:run"], "data_classifications": ["internal"], "side_effects": False, "requires_approval": False, "kb_dependencies": ["mongodb", "neo4j"]},
        {"agent_id": "crvm.connector_sync", "description": "Ingests scanner exports and produces OCSF-like KB records.", "required_scopes": ["connector:run"], "data_classifications": ["internal", "pii"], "side_effects": True, "requires_approval": True, "kb_dependencies": ["mongodb"]},
        {"agent_id": "crvm.evidence_pack", "description": "Builds audit evidence from canonical records and execution history.", "required_scopes": ["evidence:write"], "data_classifications": ["internal"], "side_effects": True, "requires_approval": True, "kb_dependencies": ["mongodb", "s3"]},
    ]


def kb_non_negotiables() -> list[str]:
    return [
        "OCSF-style schema exists before any ingestor.",
        "Entity resolution runs before storage.",
        "PII scrubbing runs before vectorization.",
        "Retrieval is hybrid, never vector-only.",
        "Tenant isolation is physical/logical per store, not only a filter.",
        "embedding_model_version is stamped on every vector.",
        "Golden retrieval eval set runs on every retrieval change.",
        "Idempotency uses source_id plus content_hash.",
        "Cache invalidation fires when source records change.",
        "Every fact is time-aware with valid_from and valid_to.",
    ]


def planner_non_negotiables() -> list[str]:
    return [
        "LLM output is constrained to registered manifest schemas.",
        "Deterministic routing handles the common path before model calls.",
        "Budgets are enforced in middleware, not prompts.",
        "Every answer cites KB record_ids.",
        "Every plan step writes W3C PROV.",
        "Side-effecting tools require human approval.",
        "Empty-KB and agent-down cases return explicit states.",
        "Planner state and agent state remain separated.",
    ]
