# CVE Seed: Path Traversal in Cloud Storage Key Construction

## Vulnerable Pattern
```python
def upload_file(tenant_id, body):
    filename = body.get('filename')  # user-controlled, unsanitized
    s3_key = f"{tenant_id}/{framework}/{control}/{filename}"
    url = s3.generate_presigned_url('put_object',
        Params={'Bucket': BUCKET, 'Key': s3_key}, ExpiresIn=300)
    return url
```

## The Fix
```python
import os

def _sanitize(val):
    return val.replace('/', '_').replace('\\', '_').replace('..', '_').strip('._')

def upload_file(tenant_id, body):
    filename = _sanitize(body.get('filename', 'file'))
    framework = _sanitize(body.get('framework', 'default'))
    control = _sanitize(body.get('control', 'general'))
    s3_key = f"{tenant_id}/{framework}/{control}/{filename}"
    # Validate final key starts with tenant prefix
    assert s3_key.startswith(f"{tenant_id}/")
    url = s3.generate_presigned_url('put_object',
        Params={'Bucket': BUCKET, 'Key': s3_key}, ExpiresIn=300)
    return url
```

## Structural Pattern
```
SOURCE(user_controlled_path_component) → SINK(cloud_storage_key_construction) WITHOUT GATE(path_sanitization)
```

## Variants to Search For
- Filename from request body used in S3/GCS/Azure key without stripping /, .., \
- Framework/category/folder params in key construction without validation
- Document ID or evidence ID used in path without sanitization
- Presigned URL generated with user-controlled key components
- One handler sanitizes but an equivalent handler doesn't (differential)
