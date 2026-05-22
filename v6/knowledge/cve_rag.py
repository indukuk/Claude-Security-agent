"""
V6 CVE RAG — Retrieves relevant vulnerability seeds for the zero-day agent.

Selects CVE seeds based on target application characteristics
(tech stack, architecture patterns, data stores).
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

SEEDS_DIR = Path(__file__).parent / "cve_seeds"


def get_relevant_seeds(app_characteristics: dict) -> str:
    """
    Retrieve CVE seeds relevant to the target application.

    Args:
        app_characteristics: dict with keys like 'has_dynamodb', 'has_s3',
            'has_cognito', 'has_bedrock', 'has_ai_agent', 'multi_tenant', etc.
    """
    seeds = []

    # Load all seed files
    all_seeds = {}
    if SEEDS_DIR.exists():
        for seed_file in sorted(SEEDS_DIR.glob("*.md")):
            all_seeds[seed_file.stem] = seed_file.read_text()

    # Select based on characteristics
    if app_characteristics.get("multi_tenant"):
        if "multi_tenant_idor" in all_seeds:
            seeds.append(all_seeds["multi_tenant_idor"])

    if app_characteristics.get("has_jwt") or app_characteristics.get("has_cognito"):
        if "jwt_unsigned_decode" in all_seeds:
            seeds.append(all_seeds["jwt_unsigned_decode"])

    if app_characteristics.get("has_bedrock") or app_characteristics.get("has_ai_agent"):
        if "shared_ai_memory" in all_seeds:
            seeds.append(all_seeds["shared_ai_memory"])

    if app_characteristics.get("has_s3"):
        if "path_traversal_s3" in all_seeds:
            seeds.append(all_seeds["path_traversal_s3"])

    if app_characteristics.get("has_code_execution") or app_characteristics.get("has_sandbox"):
        if "sandbox_blocklist_bypass" in all_seeds:
            seeds.append(all_seeds["sandbox_blocklist_bypass"])

    # If no specific match, include all seeds (small set)
    if not seeds:
        seeds = list(all_seeds.values())

    return "\n\n---\n\n".join(seeds)


def detect_characteristics(evidence_text: str) -> dict:
    """Detect application characteristics from evidence package."""
    text_lower = evidence_text.lower()
    return {
        "multi_tenant": "tenant_id" in text_lower or "customer_id" in text_lower,
        "has_dynamodb": "dynamodb" in text_lower or "table.get_item" in text_lower,
        "has_s3": "s3" in text_lower or "presigned" in text_lower,
        "has_cognito": "cognito" in text_lower or "user_pool" in text_lower,
        "has_jwt": "jwt" in text_lower or "bearer" in text_lower,
        "has_bedrock": "bedrock" in text_lower or "invoke_model" in text_lower,
        "has_ai_agent": "agent" in text_lower and ("memory" in text_lower or "invoke_agent" in text_lower),
        "has_code_execution": "sandbox" in text_lower or "exec(" in text_lower,
        "has_sandbox": "sandbox" in text_lower or "blocklist" in text_lower,
        "has_lambda": "lambda" in text_lower,
    }
