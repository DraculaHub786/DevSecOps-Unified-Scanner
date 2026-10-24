import subprocess
import requests

# TP 4: Secret
API_KEY = "ghp_111122223333444455556666777788889999"

# TP 5: Command Injection
def run_script(user_input):
    return subprocess.run(f"python {user_input}", shell=True)

# TP 6: Insecure TLS
def fetch_unverified(url):
    return requests.get(url, verify=False)
