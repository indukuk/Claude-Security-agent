# CVE Seed: JWT Decoded Without Signature Verification

## Vulnerable Pattern
```python
def get_claims(token):
    # "Authorizer already verified" — but is that always true?
    payload = token.split('.')[1]
    padded = payload + '=' * (4 - len(payload) % 4)
    claims = json.loads(base64.b64decode(padded))
    return claims  # attacker controls ALL claim values
```

## The Fix
```python
import jwt
from jwt import PyJWKClient

def get_claims(token, jwks_url):
    jwks_client = PyJWKClient(jwks_url)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(token, signing_key.key, algorithms=["RS256"],
                       audience=CLIENT_ID, issuer=ISSUER)
    return claims  # cryptographically verified
```

## Structural Pattern
```
SOURCE(bearer_token) → OPERATION(base64_decode OR split_by_dot) WITHOUT GATE(signature_verification_library)
```

## Variants to Search For
- Base64 decode of JWT payload without jwt.decode() call
- Comment says "already verified" but authorizer not attached to route
- Function URL path bypasses API Gateway authorizer
- Fallback code that decodes when authorizer context is empty
- Token split by '.' and payload section extracted manually
