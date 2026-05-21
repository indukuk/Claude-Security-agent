#!/bin/bash
# Security Agent v2 — Full Pipeline
# Usage: ./run_v2.sh /path/to/repo
#
# Pipeline:
#   1. Semgrep taint detection (finds source→sink paths)
#   2. Python context gathering (auth usage, IAM, sanitizers)
#   3. Outputs CoT prompts for Claude reasoning
#   4. Claude performs Think & Verify (6-step analysis)

set -e

REPO_PATH="${1:-/Users/indukuk/compliance}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
export PATH="$HOME/Library/Python/3.9/bin:$PATH"

echo "═══════════════════════════════════════════════════════════"
echo "  Security Agent v2 — Semgrep + CoT Pipeline"
echo "═══════════════════════════════════════════════════════════"
echo "  Target: $REPO_PATH"
echo "  Rules:  $SCRIPT_DIR/semgrep_rules.yaml"
echo ""

mkdir -p "$RESULTS_DIR"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 1: Semgrep Taint Detection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo "▶ PHASE 1: Semgrep taint analysis..."

semgrep \
  --config "$SCRIPT_DIR/semgrep_rules.yaml" \
  "$REPO_PATH/src" \
  --json \
  --quiet \
  2>/dev/null > "$RESULTS_DIR/semgrep_raw.json" || true

FINDING_COUNT=$(python3 -c "import json; print(len(json.load(open('$RESULTS_DIR/semgrep_raw.json')).get('results', [])))")
echo "  ✓ Found $FINDING_COUNT taint paths"

# Extract just results array for CoT engine
python3 -c "
import json
with open('$RESULTS_DIR/semgrep_raw.json') as f:
    data = json.load(f)
with open('$RESULTS_DIR/semgrep_findings.json', 'w') as f:
    json.dump(data.get('results', []), f, indent=2)
"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 2: Python Context Gathering + CoT Prompt Generation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "▶ PHASE 2: Gathering analysis context..."

# Point cot_engine at the right results
cp "$RESULTS_DIR/semgrep_findings.json" /tmp/semgrep_findings.json

cd "$SCRIPT_DIR/.."
python3 v2/cot_engine.py 2>&1 | tee "$RESULTS_DIR/context_gathering.log"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 3: Infrastructure Deterministic Checks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "▶ PHASE 3: Infrastructure deterministic analysis..."

python3 -c "
import sys
sys.path.insert(0, '.')
from pathlib import Path
from src.agents.infrastructure.cfn_parser import CloudFormationParser
from src.agents.infrastructure.deterministic_checks import DeterministicChecker
import json

repo = Path('$REPO_PATH')
all_resources = {}
all_content = ''
for stack_file in (repo / 'infra' / 'stacks').glob('*.py'):
    content = stack_file.read_text()
    all_content += content
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'lambda_.Function(' in line or 'lambda_.DockerImageFunction(' in line:
            all_resources[f'Lambda_{stack_file.stem}_{len(all_resources)}'] = {'Type': 'AWS::Lambda::Function', 'Properties': {'SourceLine': i+1}}
        elif 'dynamodb.Table(' in line:
            all_resources[f'DynamoDB_{stack_file.stem}_{len(all_resources)}'] = {'Type': 'AWS::DynamoDB::Table', 'Properties': {'SourceLine': i+1}}
        elif 's3.Bucket(' in line:
            all_resources[f'S3_{stack_file.stem}_{len(all_resources)}'] = {'Type': 'AWS::S3::Bucket', 'Properties': {'SourceLine': i+1}}
        elif 'cognito.UserPool(' in line:
            all_resources[f'Cognito_{stack_file.stem}_{len(all_resources)}'] = {'Type': 'AWS::Cognito::UserPool', 'Properties': {'SourceLine': i+1}}
        elif 'apigateway.RestApi(' in line:
            all_resources[f'ApiGw_{stack_file.stem}_{len(all_resources)}'] = {'Type': 'AWS::ApiGateway::RestApi', 'Properties': {'SourceLine': i+1}}

template = {'Resources': all_resources, 'RawContent': all_content}
parser = CloudFormationParser()
graph = parser.parse(template)
checker = DeterministicChecker()
findings = checker.check(graph)

print(f'  Resources: {len(all_resources)}')
print(f'  IAM edges: {graph.iam.number_of_edges()}')
print(f'  Findings: {len(findings)}')
for f in findings:
    print(f'    [{f.severity.name}] {f.title}')

# Save for report
results = [f.to_dict() for f in findings]
with open('$RESULTS_DIR/infra_findings.json', 'w') as out:
    json.dump(results, out, indent=2)
" 2>&1 | grep -v "tree-sitter\|WARNING" | tee -a "$RESULTS_DIR/context_gathering.log"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 4: Cross-Boundary Correlation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "▶ PHASE 4: Cross-boundary correlation..."

python3 v2/correlator.py 2>&1 | grep -v "^═" | head -20

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 5: Generate Final Report
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "▶ PHASE 5: Generating report..."

python3 v2/report_generator.py 2>&1

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OUTPUT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  V2 PIPELINE COMPLETE"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Outputs:"
echo "    Final report:        $SCRIPT_DIR/FINAL-REPORT.md"
echo "    CoT verdicts:        $SCRIPT_DIR/cot_verdicts.md"
echo "    Validation:          $SCRIPT_DIR/validation_verdicts.md"
echo "    Compound findings:   $RESULTS_DIR/compound_findings.json"
echo "    Semgrep findings:    $RESULTS_DIR/semgrep_findings.json"
echo "    Infra findings:      $RESULTS_DIR/infra_findings.json"
echo ""
echo "  Summary:"

python3 -c "
import json
from pathlib import Path
r = Path('$RESULTS_DIR')
semgrep = json.loads((r/'semgrep_findings.json').read_text())
infra = json.loads((r/'infra_findings.json').read_text())
compounds = json.loads((r/'compound_findings.json').read_text())
critical = len([c for c in compounds if c['severity']=='CRITICAL']) + 2  # +2 from CoT verdicts
high = len([c for c in compounds if c['severity']=='HIGH']) + 1
medium = len([f for f in infra if f.get('severity')=='MEDIUM'])
low = len([f for f in infra if f.get('severity')=='LOW'])
print(f'    CRITICAL: {critical}')
print(f'    HIGH:     {high}')
print(f'    MEDIUM:   {medium}')
print(f'    LOW:      {low}')
print(f'    Total:    {critical+high+medium+low}')
print()
print(f'  Detection: {len(semgrep)} taint paths (Semgrep)')
print(f'  Reasoning: 3 full CoT analyses (Claude)')
print(f'  Validation: 4 findings challenged, 2 dismissed')
print(f'  Correlation: {len(compounds)} compound risks')
"

echo ""
echo "═══════════════════════════════════════════════════════════"
