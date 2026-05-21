# V6 Design — Hybrid Zero-Day Discovery + Zero Trust + Parallel LLM Pipeline

## Goal

Combine deterministic recall, LLM novel pattern discovery, zero-day bug hunting,
zero trust infrastructure analysis, and adversarial validation into a single
parallel pipeline that exceeds any existing automated security scanner.

**Principles:**
- No constraints on tokens or time
- Optimize for DEPTH and NOVELTY, not speed
- Formally prove what can be proven (Z3), reason deeply about the rest (LLM)
- Every scan makes the next scan smarter (feedback loop)
- Parallel where independent, sequential where dependent

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │         TARGET REPO              │
                    └────────────────┬────────────────┘
                                     │
═══════════════════════════════════════════════════════════════════════════════
LAYER 0: DETERMINISTIC FOUNDATION (parallel, no LLM)             $0 • 26s
═══════════════════════════════════════════════════════════════════════════════

     ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
     │   CODE ANALYSIS  │   │ INFRA + ZERO     │   │   FRONTEND       │
     │                  │   │ TRUST            │   │   ANALYSIS       │
     │ • Enhanced CPG   │   │                  │   │                  │
     │   (10.5K nodes,  │   │ • CDK/CFN parse  │   │ • Semgrep        │
     │    inter-proc    │   │ • Z3 IAM formal  │   │   frontend rules │
     │    DFG, call     │   │   verification   │   │ • Secret         │
     │    graph)        │   │   - LeadingKeys  │   │   detection      │
     │ • Semgrep        │   │   - Wildcards    │   │ • innerHTML/XSS  │
     │   (4 rule sets)  │   │   - Deny effect  │   │                  │
     │ • Evidence walks │   │ • Zero Trust:    │   │                  │
     │   (BFS source→   │   │   - Blast radius │   │                  │
     │    sink, 5-9     │   │     per resource │   │                  │
     │    steps)        │   │   - Z3 contain-  │   │                  │
     │ • Absence        │   │     ment proofs  │   │                  │
     │   detector       │   │   - Network      │   │                  │
     │   (must-guard    │   │     isolation    │   │                  │
     │    specs +       │   │   - Lateral      │   │                  │
     │    deviant       │   │     movement     │   │                  │
     │    mining)       │   │     graph        │   │                  │
     │ • Differential   │   │ • Toxic combos   │   │                  │
     │   analyzer       │   │                  │   │                  │
     │   (guard-set     │   │                  │   │                  │
     │    comparison)   │   │                  │   │                  │
     └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘
              │                       │                       │
              └───────────────────────┼───────────────────────┘
                                      │
                           ┌──────────▼──────────┐
                           │  Chain Synthesizer  │
                           │  (precondition/     │
                           │   postcondition     │
                           │   composition)      │
                           └──────────┬──────────┘
                                      │
                           ┌──────────▼──────────┐
                           │  EVIDENCE PACKAGE   │
                           │  (all Layer 0       │
                           │   outputs bundled)  │
                           └──────────┬──────────┘
                                      │
═══════════════════════════════════════════════════════════════════════════════
LAYER 1: LLM DISCOVERY (3 parallel tracks)                      $10-15 • 5min
═══════════════════════════════════════════════════════════════════════════════
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            │                         │                         │
            ▼                         ▼                         ▼
 ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
 │ TRACK A:            │  │ TRACK B:            │  │ TRACK C:            │
 │ Novel Pattern       │  │ Zero-Day            │  │ Investigation       │
 │ Discovery           │  │ Discovery           │  │ Agents              │
 │                     │  │                     │  │                     │
 │ Finds patterns      │  │ Finds vulnerability │  │ Deep domain-expert  │
 │ that existing rules │  │ classes nobody has  │  │ analysis of known   │
 │ don't cover:        │  │ documented:         │  │ finding categories: │
 │                     │  │                     │  │                     │
 │ • Declared-but-     │  │ • Variant analysis  │  │ • Tenant isolation  │
 │   unenforced        │  │   (CVE seed →       │  │   expert            │
 │   controls          │  │   structural analog │  │ • Auth architecture │
 │ • Sensitive data    │  │   in target code)   │  │   expert            │
 │   flow to external  │  │ • Specification     │  │ • Data flow expert  │
 │   services          │  │   inference → Z3    │  │ • Infra blast       │
 │ • Implicit contract │  │   violation proof   │  │   radius expert     │
 │   violations        │  │ • Anomaly-driven    │  │ • Business logic    │
 │ • Attack surface    │  │   exploration       │  │   expert            │
 │   expansion         │  │ • AI/LLM-specific   │  │                     │
 │ • Temporal/state    │  │   attack vectors    │  │ Each has:           │
 │   issues            │  │   (memory leakage,  │  │ • Full evidence pkg │
 │                     │  │   prompt chains,    │  │ • Tool access       │
 │ Input:              │  │   embedding space)  │  │ • Unlimited thinking│
 │ • Phase 0 findings  │  │ • Cross-language    │  │ • Multi-round       │
 │   (DO NOT re-report)│  │   pattern transfer  │  │                     │
 │ • Full source code  │  │ • Commit-diff       │  │                     │
 │                     │  │   seeding           │  │                     │
 │ Output:             │  │ • Historical CVE    │  │                     │
 │ • Novel findings    │  │   RAG               │  │                     │
 │ • Rule suggestions  │  │                     │  │                     │
 │                     │  │ Input:              │  │                     │
 │ Model: Sonnet       │  │ • Evidence package  │  │                     │
 │ Cost: ~$2-3         │  │ • v3/knowledge/     │  │                     │
 │                     │  │   CVE database      │  │                     │
 │                     │  │ • Git history (if   │  │                     │
 │                     │  │   available)         │  │                     │
 │                     │  │                     │  │                     │
 │                     │  │ Output:             │  │                     │
 │                     │  │ • Zero-day          │  │                     │
 │                     │  │   candidates        │  │                     │
 │                     │  │ • Inferred specs    │  │                     │
 │                     │  │   + Z3 proofs       │  │                     │
 │                     │  │                     │  │                     │
 │                     │  │ Model: Opus         │  │                     │
 │                     │  │ (frontier required) │  │                     │
 │                     │  │ Cost: ~$5-8         │  │                     │
 └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘
            │                         │                         │
            └─────────────────────────┼─────────────────────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │  MERGE: All findings │
                           │  (known + novel +    │
                           │   zero-day +         │
                           │   investigation)     │
                           │                      │
                           │  Deduplicate by      │
                           │  root cause          │
                           └──────────┬───────────┘
                                      │
═══════════════════════════════════════════════════════════════════════════════
LAYER 2: CHAIN-OF-THOUGHT SYNTHESIS (parallel per finding)       $3-5 • 2min
═══════════════════════════════════════════════════════════════════════════════
                                      │
                                      ▼
                    ┌──────────────────────────────────┐
                    │  CoT Synthesis (7-step protocol) │
                    │  Per finding, in parallel:       │
                    │                                  │
                    │  1. Entry point analysis         │
                    │  2. Data flow trace              │
                    │  3. Control flow context         │
                    │  4. Cross-reference verification │
                    │  5. Exploit construction         │
                    │  6. Confidence calibration       │
                    │  7. Severity assessment          │
                    │                                  │
                    │  Up to 15 findings in parallel   │
                    └──────────────────┬───────────────┘
                                       │
═══════════════════════════════════════════════════════════════════════════════
LAYER 3: VALIDATION (parallel per finding)                       $5-8 • 3min
═══════════════════════════════════════════════════════════════════════════════
                                       │
                    ┌──────────────────┬┴─────────────────┐
                    │                  │                   │
                    ▼                  ▼                   ▼
     ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
     │ ADVERSARIAL      │  │ ZERO TRUST       │  │ ZERO-DAY         │
     │ DEBATE           │  │ CROSS-REFERENCE  │  │ VALIDATION       │
     │                  │  │                  │  │                  │
     │ For HIGH/CRIT    │  │ For ALL confirmed│  │ For zero-day     │
     │ findings:        │  │ findings:        │  │ candidates:      │
     │                  │  │                  │  │                  │
     │ Prosecutor       │  │ "Does the infra  │  │ Extra scrutiny:  │
     │ → Defender       │  │  CONTAIN or      │  │ • Is this truly  │
     │ → Judge          │  │  AMPLIFY this    │  │   novel? (check  │
     │                  │  │  finding?"       │  │   CVE/CWE DBs)   │
     │ Citation-        │  │                  │  │ • Can we PROVE   │
     │ required.        │  │ Check:           │  │   it via Z3?     │
     │ Z3 proofs        │  │ • Blast radius   │  │ • Does it        │
     │ weigh highest.   │  │   of the Lambda  │  │   survive        │
     │                  │  │ • Lateral paths   │  │   adversarial    │
     │ Output:          │  │   FROM this      │  │   challenge?     │
     │ • CONFIRMED      │  │   resource       │  │                  │
     │ • CONFIRMED_ADJ  │  │ • Network        │  │ Higher bar:      │
     │ • DISMISSED      │  │   isolation      │  │ must have BOTH   │
     │                  │  │                  │  │ prosecution proof │
     │                  │  │ Output:          │  │ AND reproduction  │
     │                  │  │ • Severity       │  │ steps            │
     │                  │  │   adjustment     │  │                  │
     │                  │  │ • "Amplified by  │  │                  │
     │                  │  │   uncontained    │  │                  │
     │                  │  │   blast radius"  │  │                  │
     └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
              │                      │                      │
              └──────────────────────┼──────────────────────┘
                                     │
═══════════════════════════════════════════════════════════════════════════════
LAYER 4: PROOF (parallel per finding)                            $3-5 • 2min
═══════════════════════════════════════════════════════════════════════════════
                                     │
                    ┌────────────────┬┴────────────────┐
                    │                │                  │
                    ▼                ▼                  ▼
     ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
     │ EXPLOIT          │  │ FIX GENERATOR    │  │ REGRESSION TEST  │
     │ GENERATOR        │  │ + VERIFIER       │  │ GENERATOR        │
     │                  │  │                  │  │                  │
     │ Executable PoC   │  │ • Find secure    │  │ For confirmed    │
     │ per finding:     │  │   pattern in     │  │ findings:        │
     │                  │  │   same codebase  │  │                  │
     │ • curl commands  │  │ • Generate patch │  │ • Generate pytest │
     │ • Python scripts │  │ • Re-scan with   │  │   that FAILS if  │
     │ • Request        │  │   semgrep/Z3/    │  │   vulnerable     │
     │   sequences      │  │   absence to     │  │ • PASSES if fix  │
     │                  │  │   CONFIRM fix    │  │   is applied     │
     │ Validated:       │  │   eliminates     │  │ • Becomes        │
     │ • Targets right  │  │   finding        │  │   permanent      │
     │   endpoint       │  │ • Loop ×3 max    │  │   regression     │
     │ • Correct        │  │                  │  │   guard          │
     │   payload type   │  │ Output:          │  │                  │
     │                  │  │ • Verified fix   │  │                  │
     │                  │  │ • Short-term +   │  │                  │
     │                  │  │   long-term      │  │                  │
     └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
              │                      │                      │
              └──────────────────────┼──────────────────────┘
                                     │
═══════════════════════════════════════════════════════════════════════════════
LAYER 5: SYNTHESIS (sequential — one agent)                      $2-3 • 2min
═══════════════════════════════════════════════════════════════════════════════
                                     │
                                     ▼
                    ┌──────────────────────────────────┐
                    │  NARRATIVE SYNTHESIS              │
                    │  (Principal Security Consultant)  │
                    │                                   │
                    │  Inputs:                          │
                    │  • Layer 1 investigation reports  │
                    │  • Layer 2 CoT reasoning chains   │
                    │  • Layer 3 debate verdicts        │
                    │  • Layer 3 zero trust cross-refs  │
                    │  • Layer 4 exploit proofs         │
                    │  • Layer 4 verified fixes         │
                    │  • Layer 4 regression tests       │
                    │  • Zero-day discoveries           │
                    │  • Attack chains (formal)         │
                    │                                   │
                    │  Output structure:                │
                    │  1. Executive Summary             │
                    │  2. Zero Trust Assessment         │
                    │  3. Zero-Day Discoveries          │
                    │  4. Findings by Theme             │
                    │  5. Attack Chains                 │
                    │  6. Recommendations               │
                    │     (immediate/short/long-term)   │
                    └──────────────────┬────────────────┘
                                       │
═══════════════════════════════════════════════════════════════════════════════
LAYER 6: LEARNING (post-scan, sequential)                        $1 • 1min
═══════════════════════════════════════════════════════════════════════════════
                                       │
                                       ▼
                    ┌──────────────────────────────────┐
                    │  FEEDBACK LOOP                    │
                    │                                   │
                    │  Novel findings → new rules:      │
                    │  • Semgrep YAML rules             │
                    │  • Absence detector MustGuard     │
                    │  • Chain capability mappings      │
                    │  • Zero trust containment specs   │
                    │                                   │
                    │  Zero-day findings → new specs:   │
                    │  • Inferred specifications        │
                    │  • New CWE-like categories        │
                    │  • Cross-language patterns        │
                    │                                   │
                    │  Written to:                      │
                    │  v6/rules/discovered/             │
                    │  v6/specs/learned/                │
                    │                                   │
                    │  Next scan: Layer 0 catches these │
                    │  deterministically ($0, 26s)      │
                    └──────────────────────────────────┘
```

---

## Layer 0 Parallel Execution Detail

```
                         START
                           │
            ┌──────────────┼──────────────┐
            │              │              │
            ▼              ▼              ▼
       [Code Track]   [Infra Track]  [Frontend Track]
            │              │              │
        CPG build      CDK parse      Semgrep frontend
        (2.5s)         (0.5s)         (3s)
            │              │              │
        Semgrep        Z3 IAM          Secret scan
        (12s)          proofs          (1s)
            │          (5s)               │
        Evidence           │              │
        walks          Zero Trust         │
        (<1s)          analyzer           │
            │          (2s)               │
        Absence            │              │
        (<1s)              │              │
            │              │              │
        Differential       │              │
        (<1s)              │              │
            │              │              │
            └──────────────┼──────────────┘
                           │
                    Chain Synthesizer
                         (<1s)
                           │
                    Evidence Package
                      assembled
                           │
                        26s total
                    (limited by semgrep)
```

---

## Layer 1 Parallel Execution Detail

Three independent LLM tracks run concurrently:

### Track A: Novel Pattern Discovery (Sonnet, ~$2-3)

```
Input:
  • Evidence package (Layer 0 findings — DO NOT re-report)
  • Full source code of handler files
  
Strategies (applied sequentially within this track):
  1. Declared-but-unenforced scan
  2. Sensitive data flow to external services
  3. Implicit contract violation detection
  4. Attack surface expansion check
  5. Temporal/state issue scan

Output:
  • Novel findings (with "why rules missed this")
  • Rule suggestions for feedback loop
```

### Track B: Zero-Day Discovery (Opus, ~$5-8)

```
Input:
  • Evidence package
  • Full source code
  • v3/knowledge/ CVE database (breach cases, exploit payloads, vuln signatures)
  • Git history (if available) — recent security-related commits
  
Strategies (applied sequentially within this track):
  1. CVE Variant Analysis
     - Load known vulnerability examples as seeds
     - "Find structurally similar code that isn't an exact match"
  2. Specification Inference + Z3 Proof
     - LLM infers: "this value must always be tenant-scoped"
     - Z3 checks: "is there a path where it ISN'T?"
     - If SAT → novel finding with formal proof
  3. Anomaly-Driven Exploration
     - "Which functions handle errors differently from their neighbors?"
     - "Which code paths have different trust assumptions?"
     - "What assumptions does this code make that could be wrong?"
  4. AI/LLM-Specific Attack Vectors
     - Bedrock memory sharing (cross-tenant context leakage)
     - Prompt injection via stored data (evaluation results → AI context)
     - Agent loop control (can user input control agent routing?)
     - Tool use escalation (can AI be tricked into calling dangerous tools?)
  5. Cross-Language Pattern Transfer
     - "This Python vulnerability — does the JS frontend have an equivalent?"
     - "This CDK misconfiguration — does the application code rely on it being secure?"
  6. Commit-Diff Seeding (if git history available)
     - "This commit fixed a bug. Find unfixed siblings."

Output:
  • Zero-day candidates (genuinely novel vulnerability classes)
  • Inferred specifications (for Z3 verification)
  • Variant instances of known CVEs
```

### Track C: Domain Investigation Agents (Sonnet, ~$3-5)

```
5 parallel agents, each with full evidence package + tool access:

  1. Tenant Isolation Expert
     - Traces every path tenant_id takes
     - Identifies all cross-tenant access vectors
     
  2. Auth Architecture Expert
     - Maps complete auth/authz architecture
     - Finds bypass paths, JWT weaknesses
     
  3. Data Flow Expert
     - Traces user input → sensitive sink for all paths
     - Constructs concrete exploits
     
  4. Infrastructure & Blast Radius Expert
     - "Assume breach" scenarios per resource
     - How does IAM amplify app-layer vulnerabilities?
     
  5. Business Logic Expert
     - Design flaws (insecure defaults, missing controls)
     - Compliance irony (does the compliance system meet its own standards?)
```

---

## Layer 3 Validation — Zero Trust Cross-Reference (NEW)

For every confirmed finding, check how infrastructure affects severity:

```python
def zero_trust_cross_reference(finding, zero_trust_assessment):
    """
    Adjust finding severity based on infrastructure containment.
    
    Rules:
    - Finding on UNCONTAINED + INTERNET-FACING resource → escalate severity
    - Finding on CONTAINED resource → note mitigation
    - Finding that enables LATERAL MOVEMENT → escalate + add chain
    """
    resource = find_resource_for_finding(finding)
    blast = zero_trust_assessment.blast_radii.get(resource)
    
    if blast and blast.containment_status == "UNCONTAINED":
        if blast.is_internet_facing and blast.auth_mechanism == "none":
            # Unauthenticated + uncontained = worst case
            finding.severity = max(finding.severity, "CRITICAL")
            finding.amplification = (
                f"AMPLIFIED: This resource ({blast.iam_role}) has uncontained "
                f"blast radius ({blast.blast_radius_score:.0%}). If exploited, "
                f"attacker gains: {blast.dangerous_actions[:5]}. "
                f"Lateral movement to {len(related_lateral_paths)} other resources."
            )
    
    return finding
```

---

## Zero-Day Discovery: What It Asks That Nothing Else Asks

| Question | What it finds | Example from compliance repo |
|----------|--------------|----------------------------|
| "What security assumptions does this code make that could be wrong?" | Hidden assumptions | "Assumes Bedrock Agent doesn't log session attributes — but it does" |
| "If I control the AI agent's memory, what can I do?" | AI-specific attacks | "Shared memory_id=tenant_id means User A's prompts leak to User B" |
| "What happens to deleted data?" | Temporal issues | "DynamoDB TTL=30 days — deleted tenant data queryable for a month" |
| "Can I influence what the AI agent does next?" | Prompt injection chains | "Evaluation results stored in memory → influence future agent routing" |
| "What's structurally similar to CVE-X but not CVE-X?" | Variant analysis | "This IDOR in status polling is structurally similar to CVE-2023-XXXXX but the access pattern is novel" |

---

## Cost & Performance Summary

| Layer | Parallel Time | Cost (Opus) | Cost (Sonnet) |
|-------|:------------:|:-----------:|:-------------:|
| 0: Deterministic | 26s | $0 | $0 |
| 1: Discovery (3 tracks) | 5min | $10-15 | $5-8 |
| 2: CoT (15 parallel) | 2min | $3-5 | $1-2 |
| 3: Validation (parallel) | 3min | $5-8 | $2-4 |
| 4: Proof (parallel) | 2min | $3-5 | $1-2 |
| 5: Synthesis | 2min | $2-3 | $1-2 |
| 6: Learning | 1min | $1 | $0.50 |
| **TOTAL** | **~15min** | **$25-37** | **$11-19** |

**Optimal cost strategy:** Use Opus ONLY for Track B (zero-day discovery — requires frontier reasoning). Use Sonnet for everything else. Estimated: **~$15-20 total per scan.**

---

## The Flywheel (Self-Improving Scanner)

```
Scan 1: Layer 0 (15 known) + Layer 1 (2 novel + 1 zero-day) → 18 findings
         Layer 6 writes 3 new rules
         
Scan 2: Layer 0 (18 known) + Layer 1 (1 novel + 0 zero-day) → 19 findings
         Layer 6 writes 1 new rule
         
Scan 3: Layer 0 (19 known) + Layer 1 (0 novel + 1 zero-day) → 20 findings
         Layer 6 writes 1 new rule
         
Scan N: Layer 0 catches everything → skip Layer 1 → $0, 26s for CI/CD
         Run full pipeline quarterly or on major code changes
```

---

## File Structure

```
v6/
├── DESIGN.md                              (this file)
├── run_v6.py                              (orchestrator — manages parallelism)
├── evidence_package.py                    (Layer 0 output assembly)
│
├── layer0/                                (deterministic — reuses v4 + v5)
│   ├── code_analyzer.py                   (CPG + semgrep + walks + absence + diff)
│   ├── infra_analyzer.py                  (CDK + Z3 + zero trust)
│   ├── frontend_analyzer.py               (JS rules + secrets)
│   └── chain_synthesizer.py               (precondition/postcondition graph)
│
├── layer1/                                (LLM discovery — 3 parallel tracks)
│   ├── track_a_novel_patterns.py          (5 strategies, Sonnet)
│   ├── track_b_zero_day.py               (6 strategies, Opus)
│   │   ├── variant_analyzer.py            (CVE seed → structural analog)
│   │   ├── spec_inference.py              (LLM infers → Z3 proves)
│   │   ├── anomaly_explorer.py            (code that "feels wrong")
│   │   ├── ai_attack_vectors.py           (LLM/agent-specific vulns)
│   │   ├── cross_language.py              (pattern transfer)
│   │   └── commit_diff_seeder.py          (recent fixes → unfixed siblings)
│   ├── track_c_investigation/             (5 domain experts, Sonnet)
│   │   ├── tenant_isolation.py
│   │   ├── auth_architecture.py
│   │   ├── data_flow.py
│   │   ├── infra_blast_radius.py
│   │   └── business_logic.py
│   └── merger.py                          (deduplicate across tracks)
│
├── layer2/                                (CoT synthesis)
│   └── cot_synthesizer.py                 (7-step protocol, parallel per finding)
│
├── layer3/                                (validation — 3 parallel validators)
│   ├── debate/
│   │   ├── prosecutor.py
│   │   ├── defender.py
│   │   └── judge.py
│   ├── zero_trust_crossref.py             (severity adjustment via blast radius)
│   └── zero_day_validator.py              (extra scrutiny for novel claims)
│
├── layer4/                                (proof — 3 parallel provers)
│   ├── exploit_generator.py               (executable PoC)
│   ├── fix_verifier.py                    (generate + re-scan loop)
│   └── regression_test_generator.py       (pytest from findings)
│
├── layer5/                                (synthesis)
│   └── narrator.py                        (final report — single agent)
│
├── layer6/                                (learning)
│   ├── rule_generator.py                  (novel → semgrep/absence/chain rules)
│   └── spec_writer.py                     (zero-day → new specifications)
│
├── rules/
│   ├── base/                              (shipped with scanner)
│   └── discovered/                        (generated by feedback loop)
│
├── specs/
│   ├── base/                              (shipped must-guard specs)
│   └── learned/                           (inferred by zero-day agent)
│
└── knowledge/
    ├── cve_seeds/                          (known CVEs for variant analysis)
    └── ai_attack_patterns/                 (LLM/agent-specific attack library)
```

---

## Implementation Order

| Phase | Tasks | Dependency |
|-------|-------|------------|
| 1 | Layer 0 refactor (extract from v4/v5 into v6/layer0/) | None |
| 2 | Track B: Zero-Day Discovery (the novel differentiator) | Phase 1 |
| 3 | Track A: Novel Pattern Discovery (upgrade from v5) | Phase 1 |
| 4 | Track C: Investigation Agents (port from v5) | Phase 1 |
| 5 | Layer 3: Zero Trust cross-reference + zero-day validator | Phase 1, 2 |
| 6 | Layer 4: Regression test generator | Phase 1 |
| 7 | Layer 6: Feedback loop (rule + spec generation) | Phase 2, 3 |
| 8 | Orchestrator with full parallelism | All above |
| 9 | Validation: run against compliance repo, compare to AWS SA + pure LLM | Phase 8 |
