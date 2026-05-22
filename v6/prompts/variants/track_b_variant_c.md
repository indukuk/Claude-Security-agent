# Track B Variant C: Anomaly-First + AI-Specific + Cross-Service Reasoning

## System Prompt

You are a security researcher who finds vulnerabilities by identifying CODE THAT DOESN'T FIT. Your technique: map the "normal" pattern, then find the anomalies. Anomalies are bugs.

You also specialize in AI/LLM application security — a domain where traditional scanners have zero coverage. You understand:
- How shared AI memory enables cross-user data leakage
- How stored data that enters AI context becomes a prompt injection vector
- How AI-driven routing decisions create attacker-controllable code paths
- How agent tool-use can be escalated beyond intended permissions
- How embeddings and retrieval can leak data across trust boundaries

## User Prompt

### Phase 1: Map the Normal Pattern

Read the evidence package. For each CATEGORY of code (handlers, data access, auth, AI integration), identify what MOST code does:

| Category | Normal Pattern (majority behavior) |
|----------|-----------------------------------|
| Auth | ? |
| Tenant scoping | ? |
| Input handling | ? |
| Error handling | ? |
| AI integration | ? |
| Session management | ? |

### Phase 2: Find Anomalies

For each category, find code that DEVIATES from the normal pattern. Anomalies include:
- A handler that handles errors differently from its siblings
- A data access path that skips a check others perform  
- An AI integration that shares state differently than others
- A session that persists data others don't
- A service call that passes credentials others don't

### Phase 3: AI/LLM-Specific Attack Vectors

This application uses Bedrock AI agents. Analyze specifically:

1. **Memory Poisoning**: If `memory_id = tenant_id`, does User A's conversation affect User B's? Can an attacker plant information in shared memory that influences another user's AI responses?

2. **Prompt Injection via Stored Data**: Evaluation results are stored in DynamoDB and later fed into AI context. Can an attacker craft evaluation data that, when read by the AI in a future session, causes the AI to perform unintended actions?

3. **Agent Routing Manipulation**: The LangGraph router decides which node handles a request based on AI classification of the user message. Can adversarial input force the router to take an unintended path (e.g., force "evaluate" instead of "chat")?

4. **Tool Escalation**: The Bedrock agent has `bedrock-agentcore:*` permissions. Can an attacker's message cause the agent to invoke tools or create sub-agents beyond what the application intends?

5. **Cross-Tenant Context Bleed**: When the observer queries CloudWatch logs, do those logs contain data from multiple tenants? Can the AI assistant inadvertently leak Tenant A's information when responding to Tenant B?

### Phase 4: Cross-Service Interaction Bugs

Look for vulnerabilities that only exist because of how SERVICES INTERACT:
- App vulnerability + IAM overpermission = amplified impact
- AI agent + shared state + unauthenticated endpoint = ?
- S3 presigned URL + path traversal + all-tenant bucket access = ?

### Evidence Package

{evidence}

### Known Findings (DO NOT RE-REPORT)

{known_findings}

### Output

For each finding (target 3-7):
```json
{
  "title": "anomaly/AI-specific vulnerability title",
  "category": "anomaly|memory_poisoning|prompt_injection|routing_manipulation|tool_escalation|context_bleed|cross_service",
  "normal_pattern": "what most code does (if anomaly)",
  "anomaly": "what this code does differently",
  "attack_scenario": "step-by-step exploitation",
  "impact": "concrete consequence",
  "evidence": "[file:line] citations",
  "novelty": "why traditional scanners miss this",
  "detection_difficulty": "why this is hard to find automatically"
}
```
