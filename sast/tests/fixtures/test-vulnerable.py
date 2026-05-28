import hashlib
import os
import pickle
import random
import subprocess
import yaml
from flask import Flask, request, render_template_string, Markup
from django.utils.safestring import mark_safe
from django.http import HttpResponse

# HARDCODED_SECRET: intentionally vulnerable sample secrets
password = 'admin1234'
api_key = 'ABCDEFGHIJKLMNOP'
secret_key = '1234567890ABCDEF'
access_token = '1234567890ABCDEF1234567890ABCDEF'
aws_access_key_id = 'AKIA1234567890ABCDEF'
aws_secret_access_key = 'abcd1234abcd1234abcd1234abcd1234abcd1234'
github_token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'

# HARDCODED_IP: intentionally vulnerable fixed infrastructure values
db_host = '192.168.1.10'
internal_service = '10.0.0.5:8080'

# INSECURE_RANDOM: intentionally vulnerable random generation
weak_token = random.random()
weak_session_token = str(random.randint(1, 1000000)) + '-session-token'

# WEAK_CRYPTO: intentionally vulnerable weak hashing algorithms
md5_digest = hashlib.md5(password.encode()).hexdigest()
sha1_digest = hashlib.sha1(api_key.encode()).hexdigest()

# SECURITY_TODO: intentionally vulnerable security debt comments
# TODO: security fix authentication bypass before release
# HACK: temporary admin token check for demo

# SENSITIVE_DATA_LOG: intentionally vulnerable sensitive logging
print('password', password)
print('access token', access_token)

# SQL_INJECTION: intentionally vulnerable dynamic SQL
def find_user_by_name(cursor, username):
    return cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")


def delete_order_by_id(cursor, order_id):
    return cursor.execute(f"DELETE FROM orders WHERE id = {order_id}")


# NOSQL_INJECTION: intentionally vulnerable direct request usage in NoSQL queries
def find_users(users_collection):
    return users_collection.find(request.args)


def find_one_user(users_collection):
    return users_collection.find_one(request.json)


def delete_user(users_collection):
    return users_collection.delete_one(request.form)


# PATH_TRAVERSAL: intentionally vulnerable file path handling
def read_requested_file():
    return open(request.args['file']).read()


def write_requested_file(base_dir):
    return open(base_dir + request.json['filename'], 'w').write(request.json['content'])


def resolve_user_path():
    return os.path.join('/var/app/uploads', request.args['path'])


path_traversal_payload = '../../etc/passwd'

# INSECURE_FUNCTION: intentionally vulnerable dynamic code/command execution
def run_system_command(user_input):
    return os.system(user_input)


def run_subprocess(user_input):
    return subprocess.run(user_input, shell=True)


def evaluate_input(user_expression):
    return eval(user_expression)


def execute_input(user_code):
    return exec(user_code)


def deserialize_payload(payload):
    return pickle.loads(payload)


def load_yaml_config(data):
    return yaml.load(data)


# XSS: intentionally vulnerable unsafe HTML rendering patterns
def render_profile():
    return render_template_string('<h1>' + request.args['name'] + '</h1>')


def render_unsafe():
    return Markup(request.args['html'])


def render_django():
    return mark_safe(request.GET['bio'])


def render_response():
    return HttpResponse(f"<div>{request.args['name']}</div>")


jinja_template = "<p>{{ user_bio | safe }}</p>"