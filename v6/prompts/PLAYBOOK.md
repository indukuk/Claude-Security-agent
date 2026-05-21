# V6 Prompt Engineering Playbook

Synthesized from: Google Big Sleep, Trail of Bits Buttercup (DARPA AIxCC),
Semgrep Assistant, and established prompting research.

## Core Principles

1. **Role separation** — each agent has ONE job, constrained output format
2. **Tool-grounded** — never conclude without tool confirmation
3. **Citation-required** — uncited claims discarded
4. **Few-shot seeded** — 1-2 CVE examples calibrate novelty threshold
5. **Output-constrained** — JSON schema forces precision, reduces hallucination
6. **Negative list** — explicitly state what NOT to report
7. **Multi-round with termination** — breadth → depth → verdict, stop when no new info

---

## Pattern 1: Variant Analysis Seeding (Big Sleep)

```
## SEED: A known vulnerability pattern
### Vulnerable Code:
{code_snippet}

### The Fix:
{fix_snippet}

### Structural Pattern:
SOURCE(user_input) → SINK(data_operation) WITHOUT GATE(ownership_check)

## NOW: Find instances of this pattern in the target code.
Do NOT report the example above. Find NEW instances with the same structure.
```

**When to use:** Track B zero-day agent, CVE variant analysis.
**Key:** Show bug + fix + abstract pattern. The LLM generalizes the pattern.

---

## Pattern 2: Role-Constrained Output (Buttercup)

```
SYSTEM: You generate {specific_output_type}.
Given: {input_type}
Output: ONLY {format}. No explanation. No analysis.
Constraint: {size_limit}. If you need more, output CANNOT_COMPLETE.
```

**When to use:** Layer 4 exploit generator, fix generator, regression test generator.
**Key:** Constrain output to ONLY the artifact. No prose, no reasoning text.

---

## Pattern 3: Semgrep Assistant Context Template (~3K tokens)

```
## Rule: {rule_id}
{rule_message}

## Matched Code (lines {start}-{end} of {file}):
{code_with_context}

## Dataflow:
Source: {source} → Sink: {sink}

## Question: Is this a true positive?
Respond: {"verdict": "tp|fp", "reason": "one sentence"}
```

**When to use:** Layer 3 debate triage (quick dismiss before full debate).
**Key:** Minimal context, forced binary output, one-sentence justification.

---

## Pattern 4: ReAct Investigation Loop

```
Follow this loop:
Thought: [hypothesis + what would change my mind]
Action: [tool_name(params)]
Observation: [system provides output]
... repeat max 7 times ...
Final: [structured finding or dismissal]

RULES:
- Never conclude without tool confirmation
- Update hypothesis when tool output contradicts it
- State falsifiability criterion in each Thought
- Stop after 7 iterations or when last 2 tools returned nothing new
```

**When to use:** Track C investigation agents (tool-augmented).
**Key:** Bounded iterations, explicit falsifiability, update-on-contradiction.

---

## Pattern 5: Anti-Hallucination Citation Requirement

```
CITATION FORMAT: [file:path.py:L42] or [z3:proof_id]

CONFIDENCE LEVELS (assign exactly one):
- VERIFIED: Confirmed by code reading + tool output
- LIKELY: Consistent with code but unconfirmed path
- POSSIBLE: Pattern matches but no direct exploitability evidence
- SPECULATIVE: Based on assumptions (FLAG FOR REVIEW)

Claims without citations are DISCARDED. Do not make claims you cannot cite.
```

**When to use:** All agents. Critical for Layer 3 debate.
**Key:** Make the LLM internalize "if I can't cite it, I can't say it."

---

## Pattern 6: Negative List (Reduce Noise)

```
DO NOT REPORT:
- Missing CSRF on non-state-changing endpoints
- Stack traces in development/test configurations
- Rate limiting absence (operational, not security finding)
- Self-XSS requiring victim to paste code
- Missing security headers on API-only services
- Information disclosure that only reveals framework version
- Anything already in the KNOWN FINDINGS list below
```

**When to use:** All discovery agents (Track A, Track B, Track C).
**Key:** Explicitly exclude common false positives and known issues.

---

## Pattern 7: Domain-Specific Persona (5-12% improvement)

```
You are a multi-tenant SaaS security specialist with expertise in:
- IDOR/BOLA vulnerabilities (OWASP API #1)
- AWS IAM policy evaluation (deny > allow, condition keys)
- Tenant isolation in Lambda + DynamoDB architectures
- The difference between authentication and authorization

You have seen 50+ cross-tenant bugs. The common pattern:
developers check IF authenticated but NOT whether they OWN the resource.

You know API Gateway authorizers prove identity but do NOT enforce row-level access.
```

**When to use:** Track C investigation agents.
**Key:** Inject domain-specific heuristics the LLM wouldn't otherwise prioritize.

---

## Pattern 8: Structured JSON Output Schema

```json
{
  "finding_id": "required-uuid",
  "title": "required, <80 chars, includes impact",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "VERIFIED|LIKELY|POSSIBLE",
  "location": {"file": "required", "line": "required", "function": "required"},
  "evidence": {
    "source": {"file": "", "line": 0, "code": "exact expression"},
    "sink": {"file": "", "line": 0, "code": "exact expression"},
    "missing_gate": "specific check that's absent"
  },
  "exploit_sketch": "curl -X POST ... (CONCRETE, not 'an attacker could...')",
  "why_not_fp": "address the most likely counter-argument",
  "fix_reference": {"file": "", "line": 0, "pattern": "existing secure code"}
}
```

**When to use:** All agents' output format.
**Key:** Reject findings missing `exploit_sketch` or `location.line`.

---

## Pattern 9: Multi-Round Termination

```
ROUND 1 (breadth): List ALL potential issues. Be liberal.
ROUND 2 (depth): For each, gather confirming/disconfirming evidence via tools.
ROUND 3 (verdict): Drop anything Round 2 showed is mitigated. Report final.

TERMINATION: You are DONE when:
1. Every CRITICAL/HIGH has been tool-confirmed or dismissed
2. Cross-boundary compound risks checked
3. Last 2 tool calls revealed nothing new

ANTI-REPETITION: Already reported: {previous_ids}. Do NOT re-report.
```

**When to use:** Track C investigation agents (multi-round).
**Key:** Explicit termination criteria prevent infinite loops.

---

## Pattern 10: Cost-Efficient Model Cascading

```
TRIAGE (Haiku, $0.001/call):
  "Is this matched code pattern a true positive? Reply: tp/fp/uncertain"
  → If 'uncertain' → escalate to full analysis

ANALYSIS (Sonnet, $0.01/call):
  Full investigation with tools, evidence gathering

ZERO-DAY (Opus, $0.10/call):
  Only for genuinely novel pattern discovery
  Only after cheaper models found nothing
```

**When to use:** V6 cost optimization.
**Key:** Only use expensive models for tasks cheap models can't do.

---

## Applying to V6 Agents

| Agent | Patterns to Use |
|-------|----------------|
| Track A (Novel) | #5 (citation), #6 (negative list), #8 (JSON output) |
| Track B (Zero-Day) | #1 (variant seed), #5 (citation), #7 (deep persona), #4 (ReAct) |
| Track C (Investigation) | #4 (ReAct), #7 (persona), #9 (multi-round), #5 (citation) |
| Layer 2 (CoT) | #5 (citation), #8 (JSON output) |
| Layer 3 (Debate) | #5 (citation), #3 (context template), #2 (role-constrained) |
| Layer 4 (Exploit) | #2 (role-constrained output only) |
| Layer 4 (Fix) | #2 (constrained), #1 (show secure pattern as seed) |
| Layer 5 (Narrator) | #7 (persona), #8 (structured output) |
| Layer 6 (Rules) | #2 (constrained — output rule ONLY), #8 (schema) |
