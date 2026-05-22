# CVE Seed: Cross-User Data Leakage via Shared AI Memory

## Vulnerable Pattern
```python
def invoke_agent(user_message, tenant_id, user_id):
    response = bedrock.invoke_agent(
        agentId=AGENT_ID,
        sessionId=session_id,
        memoryId=tenant_id,  # SHARED across all users in tenant
        inputText=user_message,
    )
    return response
```

## The Fix
```python
def invoke_agent(user_message, tenant_id, user_id):
    response = bedrock.invoke_agent(
        agentId=AGENT_ID,
        sessionId=session_id,
        memoryId=f"{tenant_id}#{user_id}",  # Per-user memory isolation
        inputText=user_message,
    )
    return response
```

## Structural Pattern
```
AI_MEMORY_SCOPE(tenant_level) WHERE USERS_SHARE_CONTEXT → CROSS_USER_DATA_LEAKAGE
```

## Variants to Search For
- memory_id / conversation_id scoped to organization rather than individual user
- Embedding store (pgvector, Pinecone) with shared namespace across users
- RAG retrieval that returns documents from other users in same tenant
- AI agent session attributes visible to all users sharing a session_id
- Mem0/LangMem scoped by tenant without user-level partition
- Shared context window across concurrent users of same agent
