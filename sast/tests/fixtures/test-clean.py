import hashlib
import os
import secrets
from pathlib import Path

# Safe: password from environment variable, not hardcoded
db_password = os.environ.get('DB_PASSWORD')

# Safe: cryptographically secure random
auth_token = secrets.token_urlsafe(32)
session_id = secrets.token_hex(32)

# Safe: strong hashing
content_hash = hashlib.sha256(b'data').hexdigest()


# Safe: parameterized query (no string concatenation, no f-string)
def find_user(cursor, user_id):
    return cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))


# Safe: sanitized input before MongoDB query
def find_users(collection, name):
    sanitized = str(name).replace('$', '')
    return collection.find({'name': sanitized})


# Safe: validated file path inside an allowed directory
def read_file(base_dir, filename):
    base = Path(base_dir).resolve()
    resolved = (base / filename).resolve()
    if base not in resolved.parents and resolved != base:
        raise ValueError('Path traversal detected')
    return resolved.read_text()


# Safe: host from config, not hardcoded
db_host = os.environ.get('DB_HOST', 'localhost')

# Safe: no sensitive data in logs
print('Server started')
print('Ready to accept connections')

# Regular TODO (not security-related) — should not trigger SECURITY_TODO
# TODO: add pagination to user list