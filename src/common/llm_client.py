"""
LLM client wrapper with cost tracking, budget enforcement, and retry.
Uses AWS Bedrock for Claude model access.
"""
from __future__ import annotations


import json
import time
import hashlib
import logging
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    calls: int = 0


@dataclass
class CostTracker:
    budget: float
    spent: float = 0.0
    usage_log: list[LLMUsage] = field(default_factory=list)

    @property
    def remaining(self) -> float:
        return self.budget - self.spent

    def can_afford(self, estimated_cost: float) -> bool:
        return self.spent + estimated_cost <= self.budget

    def record(self, usage: LLMUsage):
        self.spent += usage.cost_usd
        self.usage_log.append(usage)


class BudgetExhausted(Exception):
    pass


class LLMClient:
    # Pricing per 1M tokens (approximate, Bedrock)
    PRICING = {
        "input": 3.00 / 1_000_000,
        "output": 15.00 / 1_000_000,
    }

    def __init__(self, config):
        self.config = config
        self.cost_tracker = CostTracker(budget=config.total_budget)
        self._cache: dict[str, str] = {}
        self._client = boto3.client("bedrock-runtime", region_name="us-east-1")

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float | None = None,
        task_type: str = "reasoning",
    ) -> str:
        model = model or self._select_model(task_type)
        temperature = temperature if temperature is not None else self.config.temperature

        estimated_cost = self._estimate_cost(system_prompt, user_prompt)
        if not self.cost_tracker.can_afford(estimated_cost):
            raise BudgetExhausted(
                f"Estimated ${estimated_cost:.4f} exceeds remaining "
                f"${self.cost_tracker.remaining:.4f}"
            )

        cache_key = self._cache_key(system_prompt, user_prompt, model)
        if cache_key in self._cache:
            logger.debug("Cache hit for LLM call")
            return self._cache[cache_key]

        response_text = self._call_with_retry(
            model=model,
            system=system_prompt,
            user_message=user_prompt,
            temperature=temperature,
        )

        self._cache[cache_key] = response_text
        return response_text

    def _select_model(self, task_type: str) -> str:
        if task_type in ("reasoning", "correlation", "contextual"):
            return self.config.reasoning_model
        return self.config.fast_model

    def _call_with_retry(
        self, model: str, system: str, user_message: str, temperature: float
    ) -> str:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 4096,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user_message}],
        }

        for attempt in range(self.config.max_retries + 1):
            try:
                response = self._client.invoke_model(
                    modelId=model,
                    contentType="application/json",
                    accept="application/json",
                    body=json.dumps(body),
                )

                result = json.loads(response["body"].read())
                content = result["content"][0]["text"]

                usage = LLMUsage(
                    input_tokens=result["usage"]["input_tokens"],
                    output_tokens=result["usage"]["output_tokens"],
                    cost_usd=self._compute_cost(result["usage"]),
                    calls=1,
                )
                self.cost_tracker.record(usage)

                logger.info(
                    f"LLM call: {usage.input_tokens} in, {usage.output_tokens} out, "
                    f"${usage.cost_usd:.4f} (total: ${self.cost_tracker.spent:.4f})"
                )

                return content

            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "ThrottlingException" and attempt < self.config.max_retries:
                    wait = 2**attempt
                    logger.warning(f"Rate limited, retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    raise

        raise RuntimeError("LLM call failed after retries")

    def _estimate_cost(self, system_prompt: str, user_prompt: str) -> float:
        input_tokens = (len(system_prompt) + len(user_prompt)) // 4
        output_tokens = 2000  # Conservative estimate
        return (
            input_tokens * self.PRICING["input"]
            + output_tokens * self.PRICING["output"]
        )

    def _compute_cost(self, usage: dict) -> float:
        return (
            usage["input_tokens"] * self.PRICING["input"]
            + usage["output_tokens"] * self.PRICING["output"]
        )

    def _cache_key(self, system: str, user: str, model: str) -> str:
        content = f"{model}:{system}:{user}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    @property
    def total_cost(self) -> float:
        return self.cost_tracker.spent

    @property
    def remaining_budget(self) -> float:
        return self.cost_tracker.remaining
