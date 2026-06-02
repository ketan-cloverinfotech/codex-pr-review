import os
import logging
import requests
import bcrypt
import jwt
from pathlib import Path
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from flask import Blueprint, request, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)
worker_bp = Blueprint("worker", __name__)


def _required_env(name: str) -> str:
    """Read a required secret from the environment; fail fast at startup."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required env var {name} is not set")
    return value


# Secrets and config come from the environment, never the source tree
API_TOKEN = _required_env("API_TOKEN")
JWT_SECRET = _required_env("JWT_SECRET")
JWT_ALG = "HS256"
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/data/uploads")).resolve()
HTTP_TIMEOUT = (5, 30)  # connect, read

# CORS allowlist parsed once at startup, e.g. "https://app.example.com,https://admin.example.com"
ALLOWED_CORS_ORIGINS = {
    o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()
}


def _build_session() -> requests.Session:
    """HTTP session with TLS verification ON and bounded retries with backoff."""
    s = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=0.5,                          # 0.5s, 1s, 2s, 4s, 8s
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


_session = _build_session()


def hash_password(password: str) -> str:
    """Hash a password with bcrypt (cost 12)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time bcrypt verification."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def _safe_join(base: Path, untrusted: str) -> Path:
    """Resolve a user filename inside base; refuse anything that escapes."""
    cleaned = secure_filename(untrusted)
    if not cleaned:
        abort(400, description="invalid filename")
    candidate = (base / cleaned).resolve()
    if base != candidate and base not in candidate.parents:
        abort(400, description="invalid path")
    return candidate


@worker_bp.route("/download")
def download():
    name = request.args.get("name", "").strip()
    if not name:
        abort(400, description="name is required")
    safe_path = _safe_join(UPLOAD_DIR, name)
    if not safe_path.is_file():
        abort(404)
    # send_from_directory does its own containment check; as_attachment avoids inline render
    return send_from_directory(UPLOAD_DIR, safe_path.name, as_attachment=True)


@worker_bp.route("/verify", methods=["POST"])
def verify():
    body = request.get_json(silent=True) or {}
    token = body.get("token", "")
    if not token:
        abort(400, description="token is required")
    try:
        # Signature verified against JWT_SECRET; algorithm pinned to HS256
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.InvalidTokenError:
        abort(401, description="invalid token")
    return jsonify(user=payload.get("sub"))


@worker_bp.route("/load", methods=["POST"])
def load():
    # JSON only — never pickle untrusted bytes
    data = request.get_json(silent=True)
    if data is None:
        abort(400, description="invalid JSON")
    return jsonify(loaded=data)


@worker_bp.route("/sync")
def sync():
    url = request.args.get("url", "").strip()
    if not url.startswith("https://"):
        abort(400, description="https URL required")
    try:
        # TLS verified (default), retries with exponential backoff, hard timeout
        r = _session.get(url, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        logger.warning("sync failed: %s", type(e).__name__)
        abort(502, description="upstream error")
    return jsonify(status=r.status_code)


@worker_bp.route("/clean", methods=["POST"])
def clean():
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    if not name:
        abort(400, description="name is required")
    target = _safe_join(UPLOAD_DIR, name)
    try:
        target.unlink()                              # no exists()/remove() race
    except FileNotFoundError:
        abort(404)
    return jsonify(removed=target.name)


@worker_bp.after_request
def add_cors(resp):
    origin = request.headers.get("Origin", "")
    # Wildcard with credentials is unsafe; only echo the origin when it's allowlisted
    if origin and origin in ALLOWED_CORS_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
    return resp


def fetch_with_token() -> dict:
    # Bearer header keeps the secret out of URLs and access logs
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    r = _session.get("https://api.example.com/me", headers=headers, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()