# V5 Hybrid Design — Deterministic Foundation + LLM Discovery Loop

## The Problem

V5's current design has a blind spot: **it only finds what its rules and specs cover.**

The pure LLM found 2 things V5 missed entirely:
1. **Auth token stored in Bedrock session attributes** — credential exposure to a third-party AI service
2. **MCP server declares `required_permission` but never enforces it** — "declared but unenforced" pattern

These aren't edge cases. They represent a CLASS of vulnerability that no finite set of semgrep rules or absence specs will catch: **novel patterns that require understanding application semantics.**

The question isn't "V5 deterministic OR LLM reasoning" — it's "how do we wire the LLM so it finds novel patterns AND the deterministic layer guarantees nothing is missed?"

---

## The Hybrid Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         V5 HYBRID PIPELINE                                   │
│                                                                              │
│   Phase 1: Deterministic Sweep (ensures coverage — nothing missed)           │
│   Phase 2: LLM Discovery (finds novel patterns deterministic can't cover)    │
│   Phase 3: Feedback Loop (LLM discoveries become new deterministic rules)    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Phase 1: Deterministic Sweep (Layer 0 — unchanged)

Everything V5 already does:
- Enhanced CPG (10.5K nodes, inter-procedural)
- Semgrep (4 rule sets, 121 findings)
- Z3 formal IAM proofs (30 findings)
- Absence detector (12 must-guard specs)
- Differential analyzer (guard-set comparison)
- Zero trust (blast radius, lateral movement)
- Chain synthesizer (precondition/postcondition composition)

**Output: structured evidence package + known findings**

This guarantees: every pattern we've SEEN BEFORE is caught. 15/15 on known vulnerability classes.

### Phase 2: LLM Discovery (NEW — finds what rules don't cover)

The LLM's job is NOT to re-find what Phase 1 already caught. Its job is to find **novel patterns** by:

1. **Understanding application semantics** — what does this app DO? what SHOULD be true?
2. **Spotting anomalies** — code that is structurally unusual or contradicts its own declarations
3. **Cross-cutting concerns** — data flowing between services in unexpected ways
4. **Implicit contracts** — things the code CLAIMS (in comments, variable names, metadata) but doesn't ENFORCE

#### Discovery Agent Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ DISCOVERY AGENT                                                              │
│                                                                              │
│ Input:                                                                       │
│   1. Phase 1 findings (what we already know is wrong)                        │
│   2. Full source code (not snippets — the LLM needs to READ)                │
│   3. Evidence package (CPG summary, Z3 proofs, blast radii)                  │
│                                                                              │
│ Mandate:                                                                     │
│   "Phase 1 already found these 51 issues. Your job is to find what          │
│    it MISSED. Look for:                                                      │
│    - Patterns no rule covers (credentials in unusual places)                 │
│    - Code that contradicts its own declarations                              │
│    - Data flowing where it shouldn't (tokens to third-party services)        │
│    - Implicit security contracts that are violated                           │
│    - Anything that makes you say 'that's wrong' that isn't in the list"     │
│                                                                              │
│ Anti-pattern: DO NOT re-report Phase 1 findings. Only report NEW ones.       │
│                                                                              │
│ Output: Novel findings with evidence + suggested new rules                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Specific Discovery Strategies

**Strategy 1: "Declared but Unenforced" Scanner**

```
Prompt: "Read the code and find places where security controls are DECLARED 
         (in metadata, comments, type hints, variable names, data structures)
         but never actually ENFORCED in the execution path."

Examples the LLM would find:
- MCP server.py defines required_permission for each tool but never checks it
- Comments say "authorizer already verified" but no authorizer is configured
- Function is named "validate_input" but doesn't actually reject anything
- Config has "rate_limit: 100" but no code reads that config value
```

**Strategy 2: "Sensitive Data Flow to External Services" Scanner**

```
Prompt: "Trace all sensitive values (tokens, credentials, PII, tenant data)
         and identify where they are sent to EXTERNAL services (third-party APIs,
         managed services like Bedrock, logging systems, analytics)."

Examples the LLM would find:
- Auth token stored in Bedrock session attributes (visible to model, logged)
- Tenant evaluation data passed to Bedrock in prompts (data residency risk)
- Customer email/names in CloudWatch logs (PII exposure in logging)
- Session data serialized to JSON includes full JWT (token in logs)
```

**Strategy 3: "Implicit Contract Violation" Scanner**

```
Prompt: "Identify implicit security contracts by looking at how the MAJORITY
         of the code behaves, then find places that violate those contracts."

Examples:
- Most handlers use _get_tenant_id(event) but v2/v3 use body.get("customer_id")
- Most API responses strip internal fields, but one returns full DynamoDB item
- Most tools require confirmation for destructive actions, but one path doesn't
- Most S3 operations scope to tenant prefix, but one constructs arbitrary keys
```

**Strategy 4: "Attack Surface Expansion" Scanner**

```
Prompt: "Look for code paths that EXPAND the attack surface beyond what
         the architecture intends. Things that are reachable when they
         shouldn't be, or that expose more than the minimum needed."

Examples:
- Observer tool can query ANY log group (not just compliance agent ones)
- Evidence collector Lambda has table write access (only needs read for config)
- Agent proxy passes full token to Bedrock (only needs tenant_id)
- Self-signup creates admin (should create viewer)
```

**Strategy 5: "Temporal / State-Based" Scanner**

```
Prompt: "Look for vulnerabilities that depend on TIMING or STATE:
         - TOCTOU (time-of-check vs time-of-use)
         - Race conditions in multi-step operations
         - State that persists longer than intended
         - Session fixation or reuse across contexts"

Examples:
- Presigned URLs valid for 300s — can be reused/shared
- DynamoDB session TTL is 30 days — stale sessions accessible for a month
- Bedrock memory_id = tenant_id — shared across all users in a tenant
- No session invalidation on role change (viewer→admin JWT still valid)
```

### Phase 3: Feedback Loop (LLM discoveries → new deterministic rules)

This is the key innovation. When the LLM finds something new:

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│ LLM finds novel     │────▶│ Human reviews        │────▶│ Codify as new rule  │
│ vulnerability       │     │ (confirm real issue)  │     │ in Phase 1          │
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘
                                                                    │
                                                                    ▼
                                                          ┌─────────────────────┐
                                                          │ Next scan catches it │
                                                          │ deterministically    │
                                                          │ (zero LLM cost)      │
                                                          └─────────────────────┘
```

**Concrete example:**

1. LLM discovers: "auth token passed to Bedrock session attributes"
2. Human confirms: yes, that's a credential exposure finding
3. New rule added:

```python
# New absence detector spec
MustGuard(
    id="no-credentials-to-external-services",
    sink_pattern=r"sessionAttributes.*token|session_state.*auth|invoke_model.*token",
    guard_pattern=r"(token.*redact|strip.*auth|sanitize.*credential)",
    guard_type="credential_sanitization",
    scope="same_handler",
    severity="HIGH",
    title_template="Credentials passed to external service without redaction in {handler}",
    cwe="CWE-522",
)
```

4. Next run: Phase 1 catches this deterministically, for FREE, in 26s

**The LLM is a RULE DISCOVERY ENGINE, not just a scanner.** Each run teaches the deterministic layer new patterns.

---

## Implementation: The Discovery Agent

```python
# v5/agents/discovery/novel_pattern_agent.py

class NovelPatternDiscoveryAgent(InvestigationAgent):
    """
    Finds vulnerabilities that no existing rule covers.
    
    Operates AFTER Phase 1, receives the list of already-found issues,
    and is specifically instructed to find NEW things only.
    """
    
    def get_system_prompt(self) -> str:
        return """You are a security researcher looking for NOVEL vulnerabilities.
        
You are NOT looking for common patterns (those are already caught by automated tools).
You ARE looking for:
- Unusual data flows (credentials to places they shouldn't go)
- Declared-but-unenforced security controls  
- Implicit contracts violated by minority code paths
- Attack surface that exceeds the design intent
- Temporal/state-based issues (TOCTOU, session reuse, stale state)
- Cross-service trust assumptions that break under compromise

For each finding, also output a RULE SUGGESTION that could catch this
deterministically in future scans."""

    def get_investigation_prompt(self, context: AgentContext) -> str:
        return f"""## Novel Pattern Discovery

### Already found by automated tools (DO NOT re-report these):
{self._format_known_findings(context)}

### Source code to analyze:
{context.to_prompt_context()}

### Your mission:
Find vulnerabilities NOT in the list above. Focus on:

1. SENSITIVE DATA FLOW TO EXTERNAL SERVICES
   Where do tokens, credentials, PII, or tenant data get sent to 
   third-party or managed services? (Bedrock, CloudWatch, S3 metadata)

2. DECLARED-BUT-UNENFORCED CONTROLS
   Where does the code DECLARE a security control (in metadata, names,
   comments, config) but never actually CHECK it in the execution path?

3. IMPLICIT CONTRACT VIOLATIONS  
   What do 80% of code paths do that 20% don't? The 20% are likely bugs.

4. ATTACK SURFACE EXPANSION
   What can be reached/accessed that the architecture doesn't intend?
   What responds to requests it shouldn't? What returns more data than needed?

5. TEMPORAL/STATE ISSUES
   Race conditions, stale sessions, token reuse, TOCTOU.

For each finding, provide:
- The vulnerability
- Why existing rules missed it (what's novel about it)
- A RULE SUGGESTION for catching it deterministically next time
"""
```

---

## Implementation: Rule Generation from LLM Discoveries

```python
# v5/agents/discovery/rule_generator.py

class RuleGeneratorFromDiscovery:
    """
    Takes LLM-discovered findings and generates deterministic rules
    that can catch the same pattern in future scans without LLM.
    """
    
    def generate_rule(self, finding: dict) -> dict:
        """
        Convert a novel LLM finding into one of:
        - Semgrep YAML rule
        - Absence detector MustGuard spec
        - Differential analyzer pattern
        - Chain synthesizer capability mapping
        """
        category = finding.get("category", "")
        
        if "declared_but_unenforced" in category:
            return self._generate_absence_spec(finding)
        elif "data_flow_external" in category:
            return self._generate_semgrep_rule(finding)
        elif "implicit_contract" in category:
            return self._generate_differential_pattern(finding)
        elif "temporal" in category:
            return self._generate_absence_spec(finding)
        else:
            return self._generate_semgrep_rule(finding)
    
    def _generate_absence_spec(self, finding: dict) -> dict:
        """Generate a MustGuard spec from a discovered finding."""
        return {
            "type": "absence_spec",
            "spec": {
                "id": f"discovered-{finding['id']}",
                "sink_pattern": finding.get("sink_pattern", ""),
                "guard_pattern": finding.get("guard_pattern", ""),
                "guard_type": finding.get("guard_type", ""),
                "scope": "same_handler",
                "severity": finding.get("severity", "HIGH"),
                "title_template": finding.get("title", ""),
                "cwe": finding.get("cwe", ""),
            }
        }
    
    def _generate_semgrep_rule(self, finding: dict) -> dict:
        """Generate a Semgrep YAML rule from a discovered finding."""
        return {
            "type": "semgrep_rule",
            "rule": {
                "id": f"discovered-{finding['id']}",
                "pattern": finding.get("pattern", ""),
                "message": finding.get("description", ""),
                "severity": "ERROR" if finding.get("severity") == "HIGH" else "WARNING",
                "metadata": {
                    "cwe": finding.get("cwe", ""),
                    "category": finding.get("category", ""),
                    "discovered_by": "llm_novel_pattern_agent",
                }
            }
        }
```

---

## The Flywheel: Self-Improving Scanner

```
         ┌────────────────────────────────────────────────┐
         │                                                │
         ▼                                                │
    ┌──────────┐    catches known     ┌──────────┐       │
    │ Phase 1  │───────patterns──────▶│ Findings │       │
    │Determin. │                      │ (known)  │       │
    └──────────┘                      └──────────┘       │
         │                                                │
         │ evidence package                               │
         ▼                                                │
    ┌──────────┐    finds NOVEL       ┌──────────┐       │
    │ Phase 2  │─────patterns────────▶│ Findings │       │
    │ LLM Disc.│                      │ (novel)  │       │
    └──────────┘                      └──────────┘       │
         │                                                │
         │ novel findings                                 │
         ▼                                                │
    ┌──────────┐    generates new     ┌──────────┐       │
    │ Phase 3  │──────rules──────────▶│ New Rules│───────┘
    │ Rule Gen │                      │ (added to│
    └──────────┘                      │  Phase 1)│
                                      └──────────┘

    Each scan makes the next scan smarter.
    LLM cost decreases over time as more patterns are codified.
    Eventually: Phase 1 catches 95%+, Phase 2 only finds true novelties.
```

---

## Cost Model Over Time

| Scan # | Phase 1 Coverage | Phase 2 Novel Finds | LLM Cost | Total Findings |
|--------|-----------------|--------------------:|--------:|------:|
| 1 | 15/15 known | +2 novel | $2.50 | 17 |
| 2 | 17/17 (rules added) | +1 novel | $2.50 | 18 |
| 3 | 18/18 (rules added) | +0 novel | $2.50 | 18 |
| 4+ | 18/18 | 0 (skip Phase 2) | $0 | 18 |

After 3-4 scans of the same codebase, the LLM discovery phase finds nothing new — all patterns are codified. You can then run Phase 1 only ($0, 26s) for CI/CD gating, and Phase 2 only on major code changes or quarterly deep scans.

---

## Where This Fits in the V5 Pipeline

```
Layer 0: Deterministic Evidence Collection (Phase 1)     ← UNCHANGED
Layer 0.5: LLM Novel Pattern Discovery (Phase 2)         ← NEW
Layer 1: Deep Investigation Agents (use Phase 1+2)       ← feeds from both
Layer 2: CoT Synthesis                                    ← UNCHANGED  
Layer 3: Debate                                           ← UNCHANGED
Layer 4: Exploit + Fix                                    ← UNCHANGED
Layer 5: Narrative                                        ← includes novel findings
Layer 6: Rule Generation (Phase 3)                        ← NEW — outputs new specs
```

Layer 0.5 runs AFTER Phase 1 and BEFORE Layer 1. It:
- Receives the Phase 1 findings ("here's what we already know")
- Reads the full source code
- Finds ONLY things Phase 1 missed
- Its discoveries feed into Layer 1 investigation alongside Phase 1 findings

Layer 6 runs AFTER the full analysis and:
- Takes novel findings confirmed by debate (Layer 3)
- Generates new semgrep rules / absence specs / chain capabilities
- Writes them to `v5/rules/discovered/` for next scan

---

## Summary

The hybrid is not "deterministic vs LLM" — it's:

**Deterministic = RECALL (never miss a known pattern)**
**LLM = DISCOVERY (find unknown patterns)**
**Feedback loop = LEARNING (unknown → known over time)**

This means:
- First scan of a new codebase: Phase 1 ($0, 26s) + Phase 2 ($2.50, 5min) = full coverage
- Subsequent scans: Phase 1 only ($0, 26s) until code changes significantly
- The scanner gets SMARTER with each codebase it analyzes
- Novel findings from one codebase become rules that help ALL future scans
