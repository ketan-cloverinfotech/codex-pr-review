import ipaddress
import logging
import os
import socket
import sqlite3
import subprocess
from urllib.parse import urlparse

import requests
from flask import Flask, abort, jsonify, request

from worker import worker_bp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.register_blueprint(worker_bp)

HTTP_TIMEOUT = (5, 30)                       # connect, read
DB_PATH = os.environ.get("APP_DB", "app.db")


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/lookup")
def lookup():
    user_id = request.args.get("id", "").strip()
    if not user_id:
        abort(400, description="id is required")
    # Parameterized query: user_id is bound as a value, never inlined into SQL
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, name FROM users WHERE id = ?", (user_id,)
        ).fetchall()
    return jsonify(rows=[{"id": r[0], "name": r[1]} for r in rows])


def _is_safe_host(host: str) -> bool:
    """Allow only plain hostnames (no shell metachars, no leading dash) or numeric IPs."""
    if not host or len(host) > 253 or host.startswith("-"):
        return False
    if all(c.isalnum() or c in ".-_" for c in host):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not _is_safe_host(host):
        abort(400, description="invalid host")
    try:
        # List args + shell=False (default) + `--` guard = no command injection
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "--", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        abort(504, description="ping timed out")
    return jsonify(rc=result.returncode, stdout=result.stdout)


def _resolves_to_internal(hostname: str) -> bool:
    """SSRF guard: reject hostnames resolving to private/loopback/link-local IPs."""
    if hostname.lower() in {
        "localhost",
        "metadata.google.internal",
        "metadata.aws.internal",
    }:
        return True
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True                          # fail closed on unresolvable
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True
    return False


@app.route("/proxy")
def proxy():
    url = request.args.get("url", "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        abort(400, description="https URL with hostname required")
    if _resolves_to_internal(parsed.hostname):
        abort(400, description="internal hosts not allowed")
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        logger.warning("proxy failed: %s", type(e).__name__)
        abort(502, description="upstream error")
    # Never log secrets — status only
    logger.info("proxy ok status=%s", resp.status_code)
    return jsonify(status=resp.status_code)


if __name__ == "__main__":
    # debug=True exposes the Werkzeug debugger (RCE). Default off; never on a public bind.
    debug = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    host = "127.0.0.1" if debug else os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=int(os.environ.get("PORT", "8000")), debug=debug)