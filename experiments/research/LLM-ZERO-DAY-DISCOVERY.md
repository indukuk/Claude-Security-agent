# LLM Zero-Day Bug Discovery: Research Survey

## Key Findings

### The Proven Architecture (converging across all successful systems)

```
[Seed Knowledge] → [LLM Generator] → [Deterministic Validator] → [LLM Verifier]
     CVEs              Hypotheses         AST/Execution/Fuzzer        FP Filtering
```

Every successful LLM vulnerability discovery system uses this 4-stage pattern.

---

## 1. Major Projects & Results

### Google Project Zero: Big Sleep (November 2024)

**First public AI-discovered zero-day in real-world software.** Collaboration between Project Zero and DeepMind using Gemini 1.5 Pro.

- Found: stack buffer underflow in SQLite's `seriesBestIndex` function
- Fixed same day, before any release
- Technique: **variant analysis** — received recent commit diffs as seeds, searched current HEAD for related unfixed issues
- Tools: `debugger_run`, `code_browser_source`, `report_success`
- Key insight: this bug eluded 150+ CPU-hours of AFL fuzzing because the corpus lacked inputs close enough to the crash trigger
- Over 40% of in-the-wild 0-days are variants of known bugs — natural LLM application

Predecessor: **Naptime framework** (June 2024) — improved performance on Meta's CyberSecEval2 benchmarks.

### Google OSS-Fuzz-Gen

- LLMs automatically generate fuzz targets for C/C++/Java/Python
- Results: valid fuzz targets for 160 C/C++ projects, up to 29% line coverage increase
- **30 new bugs discovered** including CVE-2024-9143 (OpenSSL OOB read/write)
- AI Cyber Defense Initiative: "coverage increases of up to 30% across 120+ projects"
- Used Gemini to "fix 15% of bugs discovered by sanitizer tools"

### DARPA AIxCC (AI Cyber Challenge) — DEF CON 2025 Finals

$29.5M competition for autonomous Cyber Reasoning Systems:

| Place | Team | Key Stats |
|-------|------|-----------|
| 1st ($4M) | Team Atlanta (Georgia Tech, KAIST, POSTECH, Samsung) | — |
| 2nd ($3M) | Trail of Bits "Buttercup" | Non-reasoning LLMs only, 100K+ LLM requests ($21.1k), 28 vulns found across 48 challenges in 23 OSS repos, 19 patches applied, 20/25 top CWEs covered |
| 3rd ($1.5M) | Theori | $11.5k LLM spend |

**Buttercup architecture:** LLM-augmented libFuzzer/Jazzer, tree-sitter static analysis, multi-agent patching with separation of concerns.

### FuzzGPT (2023, University of Illinois)

- Primes LLMs (Codex, CodeGen, ChatGPT) with historical bug-triggering programs
- Fine-tuning on rare/unusual programs guides generation toward bugs
- **76 bugs in PyTorch/TensorFlow** (49 previously unknown, 11 high-priority/security)

### LLM4Vuln (2024)

- Framework testing 6 LLMs across 3,528 vulnerability scenarios (Solidity/Java/C++)
- **14 zero-day vulnerabilities** found in bug bounty programs ($3,576 in bounties)
- Key contribution: decoupling LLM reasoning from external aids to measure each component's value

---

## 2. Techniques That Work

### Variant Analysis (most proven)

Given a known CVE commit as seed, LLM searches for analogous unfixed patterns. Big Sleep's primary technique.

**Why it works:** LLMs excel at pattern matching across different syntactic representations. A buffer overflow in C looks different in each codebase but the STRUCTURE is recognizable.

**Application to our scanner:** Feed the LLM discovery agent known CWE examples from `v3/knowledge/community_rules/` as seeds. Ask: "find code in this repo that has a similar structure."

### LLM-Guided Fuzzing

Two approaches:
1. LLM generates fuzz harnesses/targets (OSS-Fuzz-Gen) — scales better
2. LLM generates edge-case inputs directly (FuzzGPT)

### Specification Inference

LLM infers implicit contracts from code context ("this field should never be -1"), then checks violations. Big Sleep's success: inferred that `iColumn = -1` was a sentinel requiring special handling.

**Application:** This is our "implicit contract violation" discovery strategy. The LLM reads code and infers "what SHOULD be true" then checks if it IS true.

### Multi-Agent Debate for FP Reduction

All successful systems use some form of adversarial validation:
- Buttercup: multi-agent patching with separation of concerns
- Semgrep Assistant: AI reviewer triages AI-found matches
- Our V5: Prosecutor/Defender/Judge debate

### Tool-Augmented Agents

ALL successful systems give LLMs tools:
- Big Sleep: debugger, code browser
- Buttercup: tree-sitter, libFuzzer, Jazzer
- Our V5: read_file, query_cpg, query_z3, get_blast_radius

**Pure reasoning without tool access fails on real codebases.**

### Iterative Refinement

LLM proposes → environment validates → LLM adjusts:
- OSS-Fuzz-Gen: compile-test-refine loop
- Buttercup: multi-round LLM queries with feedback
- Our V5: fix verification re-scan loop (max 3 attempts)

---

## 3. What Makes LLMs Uniquely Effective

1. **Understanding developer INTENT** — Big Sleep inferred purpose of sentinel values and recognized missing edge-case handling. No static rule captures this.

2. **Reasoning about ABSENCE** — The SQLite bug was about what was NOT checked. LLMs naturally think "what's missing here?"

3. **Cross-commit temporal reasoning** — Using historical diffs as seeds to project forward to current code.

4. **Analogical transfer** — FuzzGPT leverages known bug patterns to generate novel triggering inputs in new contexts.

5. **Natural language specification understanding** — Can process commit messages, comments, documentation to understand intended behavior vs actual behavior.

---

## 4. Limitations

1. **Hallucinated vulnerabilities** — Without grounding tools, LLMs fabricate bugs. Must pair with deterministic validation.
2. **Context window vs codebase size** — Big Sleep worked on SQLite (one large file). Million-LOC codebases require chunking.
3. **Cannot execute** — All successful systems pair LLMs with execution environments.
4. **Cost at scale** — Buttercup: $21k for 48 challenges. Must optimize token usage.
5. **Frontier model dependency** — Autonomous hacking only worked with GPT-4/Gemini. Open-source models failed.
6. **Novel architectures** — Performance drops on patterns absent from training data.

---

## 5. Application to Our V5 Hybrid Scanner

### Direct Technique Mapping

| Proven Technique | Our V5 Equivalent | Enhancement Opportunity |
|-----------------|-------------------|------------------------|
| Variant analysis (Big Sleep) | Not implemented | Add CVE seed → "find similar" discovery strategy |
| LLM-guided fuzzing (OSS-Fuzz-Gen) | Not implemented | Generate test cases that trigger findings |
| Specification inference | Absence detector (deterministic) + LLM discovery | Combine: deterministic specs + LLM infers NEW specs |
| Multi-agent debate (Buttercup) | V5 Layer 3 debate | Already implemented — proven pattern |
| Tool-augmented agents (all) | V5 Layer 1 agents with tools | Already implemented |
| Iterative refinement | V5 fix verification loop | Already implemented |
| RAG with CVE database | v3/knowledge/ vulnerability DBs | Feed as context to discovery agent |

### New Strategies to Implement

**1. CVE Variant Analysis Agent**
```
Input: Known CVEs from v3/knowledge/ + community_rules/
Prompt: "Here are 50 known vulnerability patterns. Search this codebase 
         for code that has a SIMILAR structure but isn't an exact match."
```

**2. Commit-Diff Seed Analysis (Big Sleep approach)**
```
Input: Recent git commits (especially security-related fixes)
Prompt: "This commit fixed a bug. Find other places in the codebase 
         where the SAME class of bug might exist but hasn't been fixed."
```

**3. LLM-Generated Test Cases**
```
Input: Confirmed finding + exploit proof
Prompt: "Generate a pytest test case that would FAIL if this vulnerability 
         exists and PASS if the fix is applied. This becomes a regression test."
```

**4. Cross-Language Pattern Transfer**
```
Input: Known Python vulnerability pattern
Prompt: "This is a cross-tenant isolation bug in Python Lambda. 
         The frontend is JavaScript. Are there equivalent patterns 
         in the JS code where tenant_id is mishandled?"
```

**5. Historical CVE RAG**
```
Input: Target codebase summary + retrieved similar CVEs
Prompt: "These CVEs were found in similar applications (multi-tenant SaaS, 
         AWS Lambda, DynamoDB). Check if any analogous vulnerabilities 
         exist in THIS codebase."
```

---

## 6. Key References

| Reference | Year | Key Contribution |
|-----------|------|------------------|
| Google "From Naptime to Big Sleep" | 2024 | First AI-found real-world 0-day |
| Google AI Cyber Defense Initiative | 2024 | OSS-Fuzz-Gen, 30 new bugs |
| DARPA AIxCC DEF CON Finals | 2025 | Autonomous CRS competition results |
| FuzzGPT (Deng et al.) | 2023 | LLM-guided fuzzing, 76 bugs in ML frameworks |
| LLM4Vuln (Sun et al.) | 2024 | 14 zero-days via LLM reasoning |
| Fang et al. "LLM Agents Hack Websites" | 2024 | Autonomous SQL injection |
| Snyk DeepCode AI | 2024 | Hybrid symbolic + generative, 80% autofix |
| Semgrep Assistant | 2024 | Three-layer: AI writer → deterministic → AI reviewer |
| Trail of Bits Buttercup | 2025 | $21k, 28 vulns, non-reasoning LLMs + tools |
