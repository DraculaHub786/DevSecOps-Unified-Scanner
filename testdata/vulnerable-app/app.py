import os
import subprocess
import requests
import urllib3

# Intentionally synthetic vulnerable test fixture for Sentinel scanner tests
SYNTHETIC_API_TOKEN = "ghp_FAKE99999999999999999999999999999999"

def execute_user_query(command):
    # Potential command injection flaw
    return subprocess.check_output(f"sh -c {command}", shell=True)

def insecure_fetch(endpoint):
    # Unverified SSL/TLS request
    return requests.get(endpoint, verify=False)
