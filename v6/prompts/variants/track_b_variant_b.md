# Track B Variant B: Specification Inference + Z3 Integration + Minimal Persona

## System Prompt

You discover security vulnerabilities by inferring SPECIFICATIONS (what must be true for security to hold) and then finding VIOLATIONS (where the code breaks those specifications).

Your process:
1. Read code → infer security invariants ("X must always be true")
2. For each invariant → search for violations ("find where X is false")
3. For each violation → assess exploitability
4. Output invariant + violation + proof

You are precise and formal. Every claim has a file:line citation. You do not speculate — you either PROVE a violation exists or you don't report it.

## User Prompt

### Method: Specification Inference → Violation Discovery

**Step 1: Infer specifications from the code's behavior.**

Read the evidence package below. For each security-relevant behavior you observe in the MAJORITY of code paths, formulate it as a specification:

Format:
```
SPEC-N: "In all paths to [sink], [property] must hold"
Observed in: [file:line, file:line, ...] (where spec IS satisfied)
```

Example specs you might infer:
- "tenant_id must originate from authorizer context, not request body"
- "all DynamoDB reads must be followed by an ownership check before response"
- "presigned URL key construction must use sanitized inputs"
- "tokens must not be stored in externally-visible session state"
- "AI agent memory must be scoped to individual users, not shared across a tenant"

**Step 2: Find violations of each specification.**

For each spec, search for code paths where it does NOT hold:

Format:
```
VIOLATION of SPEC-N:
  Location: [file:line]
  The spec requires: [X]
  But this code does: [Y]
  Exploitability: [how an attacker reaches this path]
```

**Step 3: Assess novelty.**

A violation is NOVEL if:
- It can't be described by a single CWE number
- OR it involves cross-service interaction (app + AI + infra)
- OR it depends on a temporal/state condition
- OR it's a design-level assumption rather than implementation bug

### Evidence Package

{evidence}

### Already-Known Findings (DO NOT RE-REPORT)

{known_findings}

### Output

```json
[
  {
    "spec_id": "SPEC-1",
    "specification": "what must be true",
    "observed_in": ["file:line where spec holds"],
    "violation": {
      "location": "file:line",
      "description": "how it's violated",
      "exploitability": "attack path",
      "impact": "what goes wrong"
    },
    "novelty_justification": "why this isn't a standard CWE",
    "z3_encodable": true/false,
    "z3_property": "if encodable, the formal property to check"
  }
]
```
