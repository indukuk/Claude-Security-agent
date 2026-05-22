# Usage: Running the Security Scanner from Claude Code

## Quick Start

From any Claude Code session, run the scanner against a target repo:

```bash
# Clone the scanner (one-time setup)
git clone https://github.com/indukuk/Claude-Security-agent.git ~/security-agent
cd ~/security-agent && pip install -e .

# Install dependencies
pip install z3-solver semgrep

# Run against any repo
python3 ~/security-agent/v6/run_v6.py /path/to/target/repo
```

## What You Get (Layer 0 — free, ~20s, no LLM)

```
Layer 0 deterministic findings:
  • Enhanced CPG (inter-procedural data flow analysis)
  • Semgrep (custom taint rules for cross-tenant, path traversal, JWT, etc.)
  • Evidence walks (source → sink traces with missing-control annotations)
  • Absence detection (missing audit logs, ownership checks, role verification)
  • Differential analysis (bypass paths — one handler has guards, another doesn't)
  • Z3 formal IAM verification (mathematically proven policy failures)
  • Zero trust assessment (blast radius, lateral movement, containment proofs)
  • Attack chain composition (multi-step exploits with composite severity)
```

## Running Deeper Analysis (Layer 1 — uses Claude in your session)

```bash
# Generate investigation prompts for Claude to execute in-session
python3 ~/security-agent/v6/run_v6.py /path/to/repo --layer 1
```

This outputs prompts to `.security-agent/v6-state/layer1_prompts/`. You can then:
1. Open `track_b_zero_day.md` — paste into your Claude session for zero-day hunting
2. Open `track_a_novel_patterns.md` — paste for novel pattern discovery
3. Open `track_c_investigation.md` — paste for deep domain investigation

Each prompt is self-contained with the evidence package embedded.

## Running with Bedrock API (full autonomous pipeline)

```bash
# Requires AWS credentials with Bedrock access
python3 ~/security-agent/v6/run_v6.py /path/to/repo --full --api
```

This runs all 7 layers autonomously (~15min, ~$15-20 in LLM costs).

## Output Location

All outputs go to `<target-repo>/.security-agent/v6-state/`:
```
v6-state/
├── summary.json                    # Layer 0 metrics
├── evidence_for_llm.md             # Full evidence package (for LLM input)
├── known_findings.json             # Exclusion list for Layer 1
├── layer1_prompts/                 # Investigation prompts
│   ├── track_a_novel_patterns.md   # Paste into Claude for novel findings
│   ├── track_b_zero_day.md         # Paste into Claude for zero-day hunting
│   └── track_c_investigation.md    # Paste for domain expert analysis
└── zero_trust_assessment.json      # Blast radius + lateral movement
```

## Supported Target Repos

The scanner works best on:
- **Python + AWS CDK/Lambda** — full coverage (CPG, semgrep, Z3, zero trust)
- **Python + CloudFormation** — good coverage (no CDK-specific patterns)
- **Any Python backend** — CPG + semgrep + absence + differential works
- **Frontend (JS/TS)** — XSS, secret detection, innerHTML

## Tips for Best Results

1. **Point at the repo root** (not a subdirectory) — scanner finds `src/` and `infra/` automatically
2. **If semgrep isn't in PATH**: `PATH="$HOME/Library/Python/3.9/bin:$PATH" python3 ...`
3. **Layer 0 is always free** — run it on every PR
4. **Layer 1 prompts are reusable** — run zero-day track once per quarter on unchanged code
5. **The scanner improves over time** — Layer 6 feedback loop adds rules from discoveries
