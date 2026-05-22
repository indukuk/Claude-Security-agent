# Track B Zero-Day Prompt Variant Comparison

## Results Summary

| Metric | Variant A (Assumptions) | Variant B (Spec Inference) | Variant C (AI/Anomaly) |
|--------|:-:|:-:|:-:|
| **Findings count** | 5 | 5 | 7 |
| **Genuinely novel** | 4 | 3 | 6 |
| **AI/LLM-specific** | 1 | 2 | 5 |
| **File:line citations** | All 5 | All 5 | All 7 |
| **Concrete exploits** | 4 | 3 | 5 |
| **False positives** | 0 | 1 (Finding 5 is borderline) | 0 |
| **Overlap with known** | 1 partial (Finding 5 observer) | 1 partial (Findings 2,3) | 1 partial (Finding 4 observer) |
| **Token usage** | ~112K | ~98K | ~96K |
| **Tool calls** | 41 | 52 | 30 |
| **Runtime** | 156s | 166s | 155s |

## Unique Findings Per Variant

### Only in Variant A:
- **Sandbox code injection via S3 key interpolation** — filename breaks out of string literal in preamble code; blocklist only checks LLM-generated code, not preamble
- **Usage accounting collision** — user-supplied session_id="usage#victim-tenant" overwrites billing records via DynamoDB key namespace collision
- **RBAC bypass via query_on_data intent** — viewer role can reach sandbox code execution through data-query path that only gates "evaluation" intent

### Only in Variant B:
- **Mem0 vector search not tenant-scoped** — single pgvector collection with only user_id partition; cosine similarity operates over ALL tenants' embeddings
- **Presigned URL outlives authorization context** — 300s URL validity not bound to session/JWT, survives role downgrade or user removal

### Only in Variant C:
- **Prompt injection via stored evaluation results** — multi-hop: upload → evaluate → store → retrieve → inject into new prompt (crosses DynamoDB boundary)
- **Agent routing manipulation via keyword stuffing** — deterministic keyword matching forces unintended evaluation/code-execution path
- **Mem0 long-term behavioral drift** — accumulated memory poisoning compounds across sessions
- **Auth token replay across Bedrock sessions** — client-controlled session_id + persistent token in session attributes

### Found by Multiple Variants:
- **Cross-tenant memory poisoning (memory_id = tenant_id)** — A, B, C all found this ✓
- **Observer as cross-tenant exfil tool** — A, C both analyzed deeply (beyond "missing auth")
- **Sandbox blocklist bypass** — A, C both found (different angles)

## Quality Assessment

### Variant A: "Question Assumptions"
**Strengths:**
- Found the DynamoDB key namespace collision (Finding 3) — deeply creative, no other variant got this
- The sandbox preamble injection is a genuine RCE vector
- The RBAC bypass via confused-deputy intent routing is architecturally novel

**Weaknesses:**
- Finding 5 (observer) overlaps with known findings
- Less AI-specific coverage

### Variant B: "Specification Inference"
**Strengths:**
- Most rigorous structure (spec → violation → proof)
- The Mem0 vector search scoping issue is a genuine novel finding
- Presigned URL temporal decoupling is subtle and real

**Weaknesses:**
- Findings 2 and 3 partially overlap with known (IDOR, missing auth)
- Less adventurous — specs tend to rediscover known patterns with more formalism
- Most tool calls (52) — less efficient

### Variant C: "AI/LLM-Specific + Anomaly"
**Strengths:**
- Most findings (7) with zero false positives
- Best AI/LLM-specific coverage (5 findings in this category)
- Multi-hop prompt injection (Finding 2) is genuinely novel and high-impact
- Memory poisoning analysis most complete (immediate + long-term drift)
- Auth token replay via session_id is a creative attack chain
- Lowest tool calls (30) — most efficient

**Weaknesses:**
- Finding 4 (observer) partially overlaps with known
- Routing manipulation (Finding 5) is HIGH severity but may be hard to exploit reliably

## Winner Selection

### WINNER: Variant C (AI/Anomaly-First)

**Rationale:**
1. **Most novel findings** (7 vs 5) with zero false positives
2. **Best coverage of AI-specific attacks** — the domain where V6 must differentiate from traditional scanners
3. **Most efficient** — 30 tool calls vs 41/52, suggesting better-targeted investigation
4. **Multi-hop prompt injection** is the highest-value single finding (crosses storage boundaries)
5. **Memory poisoning both immediate + long-term** — most complete threat model

### RUNNER-UP: Variant A (Question Assumptions)

**Rationale:**
- The DynamoDB key collision and RBAC confused-deputy findings are uniquely valuable
- These represent the "question every assumption" style that finds architectural bugs

### RECOMMENDED: Combine C + A's unique findings

The production prompt should use Variant C's structure (anomaly-first + AI-specific focus) but ADD Variant A's "question assumptions" framing for the non-AI strategies. Specifically:

```
Variant C structure:
  Phase 1: Map normal patterns
  Phase 2: Find anomalies
  Phase 3: AI/LLM-specific vectors (5 categories) ← C's strength
  Phase 4: Cross-service interaction bugs

ADD from Variant A:
  Phase 5: "What does this code ASSUME? Under what conditions is that false?"
  Focus on: data model assumptions, namespace assumptions, temporal assumptions
```

## Novel Findings Combined (Deduplicated) — 12 Total

| # | Finding | Source | Category |
|---|---------|--------|----------|
| 1 | Cross-tenant memory poisoning (memory_id = tenant_id) | A+B+C | memory_poisoning |
| 2 | Prompt injection via stored evaluation results (multi-hop) | C | prompt_injection |
| 3 | Sandbox code injection via S3 key in preamble | A+C | code_execution |
| 4 | Sandbox blocklist bypass (import evasion) | C | tool_escalation |
| 5 | RBAC bypass via query_on_data intent (confused deputy) | A | routing_manipulation |
| 6 | Agent routing manipulation via keyword stuffing | C | routing_manipulation |
| 7 | DynamoDB key namespace collision (usage# prefix) | A | data_integrity |
| 8 | Mem0 vector search not tenant-scoped (pgvector) | B | context_bleed |
| 9 | Presigned URL outlives authorization context | B | temporal |
| 10 | Auth token replay via client-controlled session_id | C | credential_exposure |
| 11 | Mem0 long-term behavioral drift (accumulated poisoning) | C | memory_poisoning |
| 12 | Observer LLM-as-SSRF-amplifier (tool scoping) | A+C | cross_service |

**These 12 findings are ALL genuinely novel — none are in V5's deterministic findings or the AWS SA report.**
