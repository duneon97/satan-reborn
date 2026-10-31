"""DO NOT RUN OR DEPLOY. Intentionally vulnerable scanner fixtures.

All credential-shaped values below are FAKE, nonfunctional placeholders.
This file is scanned as text, never imported by SATAN Reborn.
"""

# Fail closed if someone ignores the fixture warnings. The unsafe examples below
# remain visible to static analysis, but this module must never become an app.
raise SystemExit("FAKE scanner fixture only. Scan this folder; do not run or import it.")

import hashlib
import pickle
import subprocess

import yaml
from flask import Flask

app = Flask(__name__)
DEBUG = True

# FAKE DEMO ONLY: not credentials issued by any service.
AWS_ACCESS_KEY_ID = "AKIAEXAMPLEFAKE00000"
GITHUB_TOKEN = "ghp_FAKEPLACEHOLDER0000000000000000000000"
API_SECRET = "FAKE-only-placeholder-9x7Q2m8R4v6T"
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nFAKE-PLACEHOLDER-NOT-A-KEY"


def summon(user_input, payload):
    eval(user_input)
    exec(user_input)
    subprocess.run(user_input, shell=True)
    return pickle.loads(payload)


def read_haunted_yaml(document):
    return yaml.load(document, Loader=yaml.Loader)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def legacy_password(password):
    return hashlib.sha1(password.encode()).hexdigest()


if __name__ == "__main__":
    app.run(debug=True)
