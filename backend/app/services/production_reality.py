from typing import Literal

ProductionRealityStatus = Literal["implemented", "ready_to_wire", "external_required"]


def build_production_reality_model() -> dict:
    layers = [
        _layer("runtime", "Runtime And Container Hardening", "platform", "Make API, web, and workers safe to run under production orchestration.", [
            _control("non_root_images", "Non-root container images", "ready_to_wire", "Dockerfile contracts and security scan gate", "wire final base images and registry policy"),
            _control("health_probes", "Liveness, readiness, and startup probes", "implemented", "health endpoint and go-live probe contracts", "map probes into Helm/Kubernetes manifests"),
            _control("graceful_shutdown", "Graceful worker and API shutdown", "ready_to_wire", "worker lane idempotency and retry model", "attach signal handling to deployed process manager"),
            _control("resource_limits", "CPU and memory requests/limits", "ready_to_wire", "deployment sizing model", "set per-customer limits after load test"),
        ]),
        _layer("networking", "Networking, Edge, And Rate Limits", "sre", "Protect public APIs, internal services, web sockets, and connector traffic.", [
            _control("rate_limits", "Tenant-aware rate limiting", "ready_to_wire", "route permission map and request IDs", "deploy Redis or gateway-backed counters"),
            _control("waf", "WAF and virtual patch policy", "implemented", "virtual patching module and path-breaker controls", "wire customer WAF provider"),
            _control("load_balancer", "Load balancer health and timeout policy", "external_required", "go-live checklist", "configure in target cloud"),
            _control("egress_allowlist", "Connector egress allowlist", "ready_to_wire", "connector catalog and endpoint fields", "enforce at network boundary"),
        ]),
        _layer("data", "Database, Storage, Backup, And DR", "data-platform", "Keep tenant data durable, recoverable, indexed, and region-safe.", [
            _control("migrations", "Schema migrations and index checks", "implemented", "Mongo index and migration contracts", "run against customer staging database"),
            _control("backup_restore", "Backup and restore runbooks", "ready_to_wire", "go-live rollback sequence", "attach managed database snapshots and restore tests"),
            _control("object_storage", "Immutable evidence object storage", "external_required", "evidence pack model", "configure customer bucket, retention, and KMS"),
            _control("data_residency", "Data residency policy", "ready_to_wire", "enterprise readiness catalog", "bind tenant to allowed regions"),
        ]),
        _layer("async", "Queues, Schedulers, And Dead Letters", "platform", "Move long work out of the request path with replayable, correlated jobs.", [
            _control("worker_lanes", "Dedicated ingestion, simulation, connector, evidence, and report lanes", "implemented", "production effectiveness worker contracts", "run workers as independent processes"),
            _control("dead_letters", "Dead-letter queues with replay policy", "ready_to_wire", "dead-letter operating rule", "wire queue provider and replay admin action"),
            _control("idempotency", "Idempotency keys and correlation IDs", "implemented", "lane contracts and audit correlation IDs", "enforce at queue persistence layer"),
            _control("backpressure", "Backpressure and burst handling", "ready_to_wire", "queue-depth signal model", "connect queue metrics to autoscaling"),
        ]),
        _layer("observability", "Logging, Metrics, Traces, And SLOs", "sre", "Make production failures measurable and actionable.", [
            _control("structured_logs", "Structured logs with request and audit correlation", "implemented", "observability endpoint and middleware IDs", "ship logs to customer SIEM"),
            _control("otel_traces", "OpenTelemetry traces", "ready_to_wire", "OTEL endpoint config flag", "configure collector and sampling"),
            _control("slo_burn", "SLO and error-budget burn alerts", "external_required", "production effectiveness signal catalog", "define customer SLO targets and alert routes"),
            _control("runbooks", "Incident and rollback runbooks", "implemented", "go-live and production ops runbooks", "customer tabletop exercise"),
        ]),
        _layer("release", "CI/CD, Security Gates, And Rollback", "devsecops", "Prevent unsafe releases and make rollback boring.", [
            _control("quality_gates", "Lint, typecheck, tests, build, dependency and container scans", "implemented", "CI/CD quality gate model", "enable branch protection in GitHub"),
            _control("progressive_delivery", "Canary or blue-green rollout", "ready_to_wire", "automation hook catalog", "wire Kubernetes or cloud deployment strategy"),
            _control("secret_rotation", "Secret rotation and external secret manager", "external_required", "secret reference-only connector profiles", "connect customer vault"),
            _control("release_evidence", "Release evidence and customer acceptance", "implemented", "reports, audit, evidence packs, go-live signoff", "capture final customer signoff"),
        ]),
    ]
    controls = [control for layer in layers for control in layer["controls"]]
    implemented = len([item for item in controls if item["status"] == "implemented"])
    ready = len([item for item in controls if item["status"] == "ready_to_wire"])
    external = len([item for item in controls if item["status"] == "external_required"])
    return {
        "summary": {
            "layers": len(layers),
            "controls": len(controls),
            "implemented": implemented,
            "ready_to_wire": ready,
            "external_required": external,
            "production_reality_score": round(((implemented + ready * 0.65) / len(controls)) * 100),
            "posture": "production_capable_customer_infra_required" if external else "production_ready",
            "below_waterline_closed": implemented + ready,
        },
        "layers": layers,
        "launch_blockers": [item["name"] for item in controls if item["status"] == "external_required"],
        "next_actions": [
            "Run the full stack in staging with production environment validation enabled.",
            "Attach managed database, queue, cache, object storage, secret manager, telemetry collector, and alert routes.",
            "Run load, soak, backup-restore, failover, and rollback drills before live remediation execution.",
            "Keep live execution dry-run or approval-gated until customer identity, secrets, and change policies are configured.",
        ],
    }


def _layer(layer_id: str, name: str, owner: str, purpose: str, controls: list[dict]) -> dict:
    return {"id": layer_id, "name": name, "owner": owner, "purpose": purpose, "controls": controls}


def _control(control_id: str, name: str, status: ProductionRealityStatus, evidence: str, gap: str) -> dict:
    return {"id": control_id, "name": name, "status": status, "evidence": evidence, "gap": gap}
