# CVE Seed: Multi-Tenant IDOR via User-Controlled Resource Identifier

## Vulnerable Pattern
```python
def get_resource(event):
    resource_id = event['body']['resource_id']  # user-controlled
    item = table.get_item(Key={'id': resource_id})  # no tenant filter
    return item['Item']  # returns any tenant's data
```

## The Fix
```python
def get_resource(event):
    resource_id = event['body']['resource_id']
    tenant_id = event['requestContext']['authorizer']['tenant_id']  # trusted
    item = table.get_item(Key={'id': resource_id})
    if item['Item'].get('tenant_id') != tenant_id:  # ownership check
        raise Forbidden("Access denied")
    return item['Item']
```

## Structural Pattern
```
SOURCE(user_controlled_id) → SINK(database_read_by_id) WITHOUT GATE(ownership_verification)
```

## Variants to Search For
- Session ID used as DynamoDB key without tenant filter
- Job ID / task ID polled without verifying requester owns it
- File path constructed from user input without tenant prefix validation
- API endpoint accepts resource identifier from body instead of deriving from auth context
