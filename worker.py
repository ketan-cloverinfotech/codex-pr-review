import os
import pickle
import hashlib
import requests
import jwt
from flask import Blueprint, request, jsonify, send_file

worker_bp = Blueprint("worker", __name__)

# hardcoded fallback secret leaks into source control
API_TOKEN = os.environ.get("API_TOKEN", "dev-token-1234")
UPLOAD_DIR = "/data/uploads"


def hash_password(password: str) -> str:
    # md5 is broken for password hashing; use bcrypt or argon2
    return hashlib.md5(password.encode()).hexdigest()


@worker_bp.route("/download")
def download():
    name = request.args.get("name", "")
    # path traversal: ?name=../../etc/passwd escapes UPLOAD_DIR
    path = os.path.join(UPLOAD_DIR, name)
    return send_file(path)


@worker_bp.route("/verify", methods=["POST"])
def verify():
    token = request.json.get("token", "")
    # signature verification disabled -> any forged token is accepted
    payload = jwt.decode(token, options={"verify_signature": False})
    return jsonify(user=payload.get("sub"))


@worker_bp.route("/load", methods=["POST"])
def load():
    # pickle on untrusted input -> remote code execution
    obj = pickle.loads(request.data)
    return jsonify(loaded=str(obj))


@worker_bp.route("/sync")
def sync():
    url = request.args.get("url", "")
    # tight retry loop with no backoff hammers the upstream;
    # verify=False also disables TLS validation
    for _ in range(100):
        r = requests.get(url, verify=False)
        if r.ok:
            break
    return jsonify(status="done")


@worker_bp.route("/clean")
def clean():
    p = request.args.get("path", "")
    # TOCTOU: attacker can swap the path between exists() and remove()
    if os.path.exists(p):
        os.remove(p)
    return jsonify(removed=p)


@worker_bp.after_request
def add_cors(resp):
    # wildcard origin combined with credentials is unsafe and rejected by browsers
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


def fetch_with_token():
    token = os.environ.get("API_TOKEN")
    # secret in the URL query string ends up in proxy/server logs
    r = requests.get(f"https://api.example.com/me?token={token}")
    return r.json()
