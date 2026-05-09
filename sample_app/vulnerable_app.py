"""
Sample vulnerable Python application for demonstration purposes.
This file intentionally contains security vulnerabilities for testing.
"""

import sqlite3
import subprocess
import hashlib
import os

# VULNERABILITY 1: Hardcoded credentials (Secret Exposure)
DATABASE_PASSWORD = "admin123"
SECRET_API_KEY = "sk-1234567890abcdef"
JWT_SECRET = "mysecretkey"

# VULNERABILITY 2: SQL Injection
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Dangerous: user input directly in query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

# VULNERABILITY 3: Command Injection
def ping_host(host):
    # Dangerous: user input passed to shell
    result = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return result.stdout

# VULNERABILITY 4: Weak Hashing (MD5)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY 5: Path Traversal
def read_file(filename):
    base_path = "/var/www/files/"
    # Dangerous: no path validation
    with open(base_path + filename, "r") as f:
        return f.read()

# VULNERABILITY 6: Insecure Deserialization
import pickle
def load_user_data(data):
    # Dangerous: deserializing untrusted data
    return pickle.loads(data)

# VULNERABILITY 7: XSS (in template rendering)
def render_profile(user_input):
    # Dangerous: no escaping of user input
    html = f"<h1>Welcome {user_input}</h1>"
    return html

# VULNERABILITY 8: Insecure random
import random
def generate_token():
    # Dangerous: not cryptographically secure
    return str(random.randint(100000, 999999))
