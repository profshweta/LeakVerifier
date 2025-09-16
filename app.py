from flask import Flask, render_template, jsonify, request, send_file
import json
import os
import csv
from datetime import datetime

app = Flask(__name__)
LOG_FILE = "sdk_logs.json"


@app.route("/")
def index():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
                for item in logs:
                    if "Timestamp" not in item:
                        item["Timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            except:
                logs = []

    search = request.args.get("search", "").lower()
    sdk_filter = request.args.get("sdk", "")

    if search:
        logs = [
            d for d in logs
            if search in d['App Domain'].lower()
            or any(search in key.lower() for key in d.get("Data Sent", {}).keys())
        ]

    if sdk_filter and sdk_filter != "All":
        logs = [d for d in logs if d['App Domain'] == sdk_filter]

    sdk_list = sorted(set(d['App Domain'] for d in logs))

    return render_template("index.html", logs=logs, sdk_list=sdk_list, search=search, sdk_filter=sdk_filter)


@app.route("/api/logs")
def api_logs():
    with open(LOG_FILE, "r") as f:
        return jsonify(json.load(f))


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


