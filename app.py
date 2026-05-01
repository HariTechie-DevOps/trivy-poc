"""
Trivy POC - Vulnerable Python Flask Application
intentionally contains security issues for scanning demo
"""

from flask import Flask, request, render_template_string
import sqlite3
import subprocess
import pickle
import os
import hashlib

app = Flask(__name__)

# ============================================================
# VULNERABILITY 1: Hardcoded Secret / Credentials
# Trivy Secret Scanner will catch this
# ============================================================
SECRET_KEY       = "hardcoded-super-secret-key-12345"
DB_PASSWORD      = "admin123"
AWS_ACCESS_KEY   = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN     = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
JWT_SECRET       = "my_jwt_secret_token_never_share"


# ============================================================
# VULNERABILITY 2: SQL Injection
# Not a Trivy scan target but shows insecure code
# ============================================================
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # BAD: Direct string formatting → SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return str(cursor.fetchall())


# ============================================================
# VULNERABILITY 3: Command Injection
# ============================================================
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # BAD: User input directly in shell command → RCE
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()


# ============================================================
# VULNERABILITY 4: Insecure Deserialization
# ============================================================
@app.route('/load', methods=['POST'])
def load_data():
    data = request.get_data()
    # BAD: pickle.loads on user input → Remote Code Execution
    obj = pickle.loads(data)
    return str(obj)


# ============================================================
# VULNERABILITY 5: Weak Hashing (MD5)
# ============================================================
@app.route('/hash')
def make_hash():
    password = request.args.get('password')
    # BAD: MD5 is cryptographically broken
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


# ============================================================
# VULNERABILITY 6: XSS - Cross Site Scripting
# ============================================================
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # BAD: User input directly rendered in HTML → XSS
    template = f"<h1>Hello {name}</h1>"
    return render_template_string(template)


# ============================================================
# VULNERABILITY 7: Debug mode ON in production
# ============================================================
@app.route('/')
def index():
    return {
        "status": "running",
        "version": "1.0.0",
        "environment": os.environ.get("ENV", "production")
    }


if __name__ == '__main__':
    # BAD: debug=True in production, host='0.0.0.0' exposes to all
    app.run(debug=True, host='0.0.0.0', port=5000)
