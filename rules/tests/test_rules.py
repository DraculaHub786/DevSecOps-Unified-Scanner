import os
import subprocess
import requests
import hashlib
import random
import pickle
import yaml
from flask import redirect, request

def test_py(cursor, user_input):
    # ruleid: org-python-sql-injection-format
    cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")

    # ruleid: org-python-command-injection-shell
    subprocess.run(user_input, shell=True)

    # ruleid: org-python-code-injection-eval
    eval(user_input)

    # ruleid: org-python-requests-verify-false
    requests.get("https://example.com", verify=False)

    # ruleid: org-python-weak-crypto-md5-sha1
    hashlib.md5(b"test")

    # ruleid: org-python-insecure-random
    random.random()

    # ruleid: org-python-path-traversal-open
    open(os.path.join("/base", user_input))

    # ruleid: org-python-unsafe-pickle
    pickle.loads(user_input)

    # ruleid: org-python-unsafe-yaml-load
    yaml.load(user_input)

    # ruleid: org-python-open-redirect
    redirect(request.args.get("next"))

    # ruleid: org-python-ssrf-requests
    requests.get(request.args.get("target"))

    # ruleid: org-python-xxe-processing
    etree.XMLParser(resolve_entities=True)

    # ruleid: org-python-ssti-jinja2
    render_template_string(user_input)

