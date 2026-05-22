# Prompt Variant Testing Results (All Layers)

## Track B: Zero-Day Discovery — COMPLETE

**Winner: Variant C (AI/Anomaly-First)** — 7 findings, 30 tool calls, 0 FPs.
Production prompt: Combine C's structure + A's "question assumptions" phase.
See: track_b_variant_comparison.md for details.

## Track C: Investigation Agent (Tenant Isolation) — COMPLETE

**Prompt approach tested:** Deep domain persona + ReAct investigation loop + contrastive analysis

**Results:** 5 findings (1 CRITICAL, 2 HIGH, 2 MEDIUM)
- Cross-tenant status polling (known — but deepest trace yet)
- Session hijack via user-supplied session_id (known — but showed OVERWRITE not just read)
- Unverified JWT on Function URL path (known — but concrete forge + delete exploit)
- Cross-tenant S3 deletion chained with JWT forge (novel COMPOSITION)
- **Mutable Cognito tenant_id attribute — GENUINELY NOVEL** ✓

**Assessment:**
- The ReAct pattern produced excellent evidence traces (entry → step → step → sink)
- The domain persona ("50+ cross-tenant bugs") focused investigation on the right areas
- The contrastive instruction ("compare with handler.py:199") was cited by the agent
- Finding 5 (mutable Cognito attr) is genuinely novel — not in any prior analysis

**Selected for production:** This exact prompt structure. No changes needed.

## Layer 3: Adversarial Debate — COMPLETE

**Prompt approach tested:** Prosecution → Defense → Judge (all in one call) with evidence bundle

**Results:**
- Verdict: CONFIRMED_ADJUSTED (HIGH maintained, not escalated to CRITICAL)
- Judge correctly discounted unsupported claims from BOTH sides
- Prosecution strongest point: code evidence [1][2][4][5] proves isolation failure
- Defense best point: Bedrock memory behavior is uncertain (but ungrounded = discounted)
- Judge reasoning was clear, nuanced, and well-structured

**Assessment:**
- Citation-required format worked perfectly — forced precision
- The "cannot invent mitigations" rule for Defense prevented hallucinated protections
- Having all 3 roles in one call works for testing; production should separate for independence
- The evidence bundle [1-6] format gave both sides equal footing

**Selected for production:** Separate calls for P/D/J (independence matters for real debates).
Keep: citation requirement, structured evidence bundle, "discard uncited claims" judge rule.

## Track A: Novel Pattern Discovery — PENDING

(Awaiting completion)

## Layer 2 CoT, Layer 5 Narrator, Layer 6 Rule Gen — PENDING

(Not yet tested — will use winning patterns from completed tests)
