import os
import requests

def fetch_data():
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return None
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get("https://api.github.com/user", headers=headers, timeout=10)
    return resp.json()
