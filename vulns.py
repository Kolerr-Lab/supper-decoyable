import os
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
    print("Test file with vulnerabilities")