import requests

def safe_fetch(url):
    return requests.get(url, timeout=10)
