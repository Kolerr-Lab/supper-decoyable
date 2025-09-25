import re

content = """import os
import subprocess
import pickle
import hashlib
import random

# SQL injection vulnerability
def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id  # Vulnerable to SQL injection
    return query

# Command injection vulnerability
def run_command(cmd):
    result = subprocess.call(cmd, shell=True)  # Dangerous shell=True
    return result

# Weak hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is weak

# Pickle deserialization (dangerous)
def load_data(data):
    return pickle.loads(data)  # Can execute arbitrary code

# Hardcoded secret
password = "supersecretpassword123456789"  # Exposed secret

# Insecure random
def get_random_number():
    return random.randint(1, 100)  # Insecure random

# Debug enabled
DEBUG = True

if __name__ == "__main__":
    print("Test file with vulnerabilities")"""

# Test patterns
patterns = [
    (r'(?:md5|sha1)\s*\(', "Weak crypto"),
    (r'(?:password|secret|key|token)\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded secret"),
    (r'debug\s*=\s*True', "Debug enabled"),
    (r'(?:pickle|cPickle)\.loads?\s*\(', "Insecure deserialization"),
    (r'import\s+random\n.*random\.(?:randint|choice|sample)', "Insecure random"),
]

for pattern, name in patterns:
    compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    matches = compiled.findall(content)
    print(f"{name}: {len(matches)} matches - {matches}")