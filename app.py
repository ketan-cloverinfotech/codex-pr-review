import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
TIMEOUT = (5, 30)  # connect, read


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url.startswith("https://"):
        return jsonify(error="https only"), 400
    resp = requests.get(url, timeout=TIMEOUT)
    return jsonify(status=resp.status_code)