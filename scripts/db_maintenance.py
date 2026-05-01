#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def backup(uri: str, database: str, output: str | None) -> None:
    target = Path(output or f"backups/remediation-twin-mongo-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    target.mkdir(parents=True, exist_ok=True)
    subprocess.run(["mongodump", "--uri", uri, "--db", database, "--out", str(target)], check=True)
    print(json.dumps({"status": "ok", "backup_path": str(target)}, indent=2))


def restore(uri: str, database: str, source: str) -> None:
    source_path = Path(source)
    subprocess.run(["mongorestore", "--uri", uri, "--drop", "--nsInclude", f"{database}.*", str(source_path)], check=True)
    print(json.dumps({"status": "ok", "restored_from": str(source_path)}, indent=2))


def index_manifest() -> None:
    indexes = {
        "tenants": [["slug"]],
        "assets": [["tenant_id", "external_id"], ["tenant_id", "environment"]],
        "findings": [["tenant_id", "fingerprint"], ["tenant_id", "business_risk_score"]],
        "source_findings": [["tenant_id", "source", "source_id"]],
        "remediation_actions": [["tenant_id", "status"]],
        "simulations": [["tenant_id", "created_at"]],
        "workflow_items": [["tenant_id", "status"]],
        "audit_logs": [["tenant_id", "created_at"]],
        "report_snapshots": [["tenant_id", "created_at"]],
        "connector_runs": [["tenant_id", "created_at"]],
        "policies": [["tenant_id", "policy_type"]],
    }
    print(json.dumps({"status": "ok", "required_indexes": indexes}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["backup", "restore", "index-manifest"])
    parser.add_argument("--uri", default="mongodb://localhost:27017")
    parser.add_argument("--database", default="remediation_twin")
    parser.add_argument("--path")
    args = parser.parse_args()
    if args.command == "backup":
        backup(args.uri, args.database, args.path)
    elif args.command == "restore":
        if not args.path:
            raise SystemExit("--path is required for restore")
        restore(args.uri, args.database, args.path)
    else:
        index_manifest()


if __name__ == "__main__":
    main()
