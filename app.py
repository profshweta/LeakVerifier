from flask import Flask, render_template, jsonify, request, send_file
import json
import os
import csv
from datetime import datetime
import re


app = Flask(__name__, template_folder="templates")

LOG_FILE = "sdk_logs.json"

DECODE_TAG_RE = re.compile(r"\(decoded:")
PLAINTEXT_AND_DECODED_RE = re.compile(r"\(plaintext;\s*decoded:")


def _load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _apply_filters(logs, search: str, sdk_filter: str):
    search = (search or "").lower().strip()
    sdk_filter = (sdk_filter or "").strip()

    if search:
        logs = [
            d for d in logs
            if search in str(d.get('App Domain', '')).lower()
            or any(search in str(key).lower() for key in (d.get("Data Sent", {}) or {}).keys())
        ]

    if sdk_filter and sdk_filter != "All":
        logs = [d for d in logs if d.get('App Domain') == sdk_filter]

    return logs


def compute_pii_summary(logs):
    """
    Aggregate per PII type:
    - total_packets: number of packets (log entries) where this pii_type appears
    - plaintext_packets: packets where any value is plaintext
    - encoded_packets: packets where any value is encoded/decoded
    """
    summary = {}  # pii_type -> dict

    for entry in logs:
        data_sent = entry.get("Data Sent") or {}
        if not isinstance(data_sent, dict):
            continue

        for pii_type, values in data_sent.items():
            if pii_type not in summary:
                summary[pii_type] = {
                    "pii_type": pii_type,
                    "total_packets": 0,
                    "plaintext_packets": 0,
                    "encoded_packets": 0
                }

            vals = values if isinstance(values, list) else [values]
            vals = [str(v) for v in vals]

            has_encoded = any(DECODE_TAG_RE.search(v) for v in vals)
            has_plaintext = any((not DECODE_TAG_RE.search(v)) for v in vals)


            if any(PLAINTEXT_AND_DECODED_RE.search(v) for v in vals):
                has_plaintext = True
                has_encoded = True

            summary[pii_type]["total_packets"] += 1
            if has_plaintext:
                summary[pii_type]["plaintext_packets"] += 1
            if has_encoded:
                summary[pii_type]["encoded_packets"] += 1

    return sorted(summary.values(), key=lambda x: (-x["total_packets"], x["pii_type"]))

@app.route("/")
def index():
    logs = _load_logs()
    for item in logs:
        if "Timestamp" not in item:
            item["Timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    search = request.args.get("search", "").lower()
    sdk_filter = request.args.get("sdk", "")

    logs = _apply_filters(logs, search, sdk_filter)

    sdk_list = sorted(set(d['App Domain'] for d in logs))

    return render_template("index.html", logs=logs, sdk_list=sdk_list, search=search, sdk_filter=sdk_filter)


@app.route("/api/logs")
def api_logs():
    return jsonify(_load_logs())


@app.route("/api/pii_summary")
def api_pii_summary():
    logs = _load_logs()

    search = request.args.get("search", "")
    sdk_filter = request.args.get("sdk", "")
    logs = _apply_filters(logs, search, sdk_filter)
    return jsonify(compute_pii_summary(logs))


@app.route("/download")
def download():
    return send_file(LOG_FILE, as_attachment=True)


@app.route("/export")
def export():
    export_file = "sdk_export.csv"
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            data = json.load(f)
        with open(export_file, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["App Domain", "Data Sent", "Timestamp"])
            for item in data:
                writer.writerow([
                    item.get("App Domain", ""),
                    ", ".join([f"{k}: {v}" for k, v in item.get("Data Sent", {}).items()]),
                    item.get("Timestamp", "")
                ])
    return send_file(export_file, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=5050)



