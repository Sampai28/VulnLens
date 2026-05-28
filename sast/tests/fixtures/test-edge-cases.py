# EDGE CASE FILE: Mix of tricky patterns that test scanner accuracy
# Some lines LOOK suspicious but are safe. Some are actually vulnerable.

import hashlib
import os
import pickle
import subprocess
from flask import request, send_file

# Stubs for undefined identifiers — this file is a pattern-matching fixture,
# not executable code. Stubs exist only to silence linter "undefined name" warnings.
def get_user_input(): return ''
def lookup_precomputed_hash(_data): return ''
def authenticate(_data): return None
request_id = 0
data = b''

# ─── FALSE POSITIVE BAIT (should NOT trigger) ───

# Variable named "password" but no string-literal assignment
password = get_user_input()

# String contains "api_key" but inside a comment, not an assignment
# This documents the api_key format for reference

# eval is a dict key, not a function call
config = {'eval': True, 'mode': 'strict'}

# render_template_string is a variable holding a string, not a call
render_template_string_name = 'render_template_string'

# "SELECT" in a string but not in execute()
message = "SELECT a plan that works for you"

# print without sensitive keywords
print('Application started successfully')
print('Processing request', request_id)

# MD5 in a variable name, not a hashlib call
md5_hash = lookup_precomputed_hash(data)

# Version string that doesn't look like an IP
version = '2.1.0'

# run() on a custom object, not subprocess
class QueryBuilder:
    def run(self):
        return None


# os.system referenced but not called (assignment of the function itself is unusual but possible)
# We accept this would still flag — comment is for human reviewers

# ─── ACTUAL VULNERABILITIES (should trigger) ───

# Hardcoded secret buried in a longer line
config2 = {'debug': False, 'api_key': 'ABCDEFGHIJKLMNOP1234', 'timeout': 30}


# SQL injection with extra whitespace and line break
def search_users(cursor, term):
    return cursor.execute("SELECT * FROM users WHERE name LIKE '%" +
                          term + "%'")


# eval called through a wrapper
def process_template(template):
    return eval(template)


# subprocess shell=True with extra spacing
def run_legacy(cmd):
    return subprocess.run(cmd, shell = True)


# Weak crypto in a helper function
def quick_hash(data):
    return hashlib.md5(data).hexdigest()


# Hardcoded IP in a config object
db_config = {
    'host': '10.0.1.50',
    'port': 5432,
    'database': 'vulnlens'
}


# Sensitive data logged with f-string interpolation
def debug_auth(token):
    print(f'auth token received: {token}')


# Path traversal in nested function
def serve_file(filename):
    file_path = os.path.join('/public', request.args[filename])
    return send_file(file_path)


# FIXME: security — need to add rate limiting
def login_handler():
    return authenticate(request.form)


# pickle.loads used for "trusted" data — still flags as unsafe
def restore_cache(blob):
    return pickle.loads(blob)