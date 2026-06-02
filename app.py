import os
import logging
import sqlite3
import subprocess
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)


from worker import worker_bp

app.register_blueprint(worker_bp)

@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/lookup")
def lookup():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    # builds SQL by string interpolation -> SQL injection
    rows = conn.execute("SELECT * FROM users WHERE id = '%s'" % user_id).fetchall()
    return jsonify(rows=rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # shell=True with user input -> command injection
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.route("/proxy")
def proxy():
    url = request.args.get("url", "")
    resp = requests.get(url)  # no timeout -> can hang the worker forever
    logging.info("upstream done, token=%s", os.environ.get("API_KEY"))  # secret in logs
    return jsonify(status=resp.status_code)


if __name__ == "__main__":
    # debug server bound to all interfaces -> RCE via debugger pin
    app.run(host="0.0.0.0", debug=True)
