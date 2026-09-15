"""Flask web UI for the vulnerability scanner agent."""

import json
import queue
import threading

from flask import Flask, Response, jsonify, render_template, request, send_file
from pathlib import Path
from scanner import scan_repo, REPORTS_DIR

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    repo_url = (data.get("repo_url") or "").strip()
    if not repo_url:
        return jsonify({"success": False, "error": "Repository URL is required."}), 400

    result = scan_repo(repo_url)
    return jsonify(result)


@app.route("/scan/stream", methods=["GET"])
def scan_stream():
    """SSE endpoint: streams real-time progress then the final result."""
    repo_url = (request.args.get("repo_url") or "").strip()
    if not repo_url:
        return jsonify({"success": False, "error": "Repository URL is required."}), 400

    progress_queue: queue.Queue[str | None] = queue.Queue()
    result_holder: list[dict] = []

    def _on_progress(message: str):
        progress_queue.put(message)

    def _run_scan():
        try:
            result = scan_repo(repo_url, progress_callback=_on_progress)
            result_holder.append(result)
        except Exception as exc:
            result_holder.append({"success": False, "error": str(exc)})
        finally:
            progress_queue.put(None)  # sentinel: scan complete

    thread = threading.Thread(target=_run_scan, daemon=True)
    thread.start()

    def _generate():
        while True:
            try:
                msg = progress_queue.get(timeout=120)
            except queue.Empty:
                # Timeout – send a keepalive comment
                yield ": keepalive\n\n"
                continue

            if msg is None:
                # Scan finished – send the final result
                data = result_holder[0] if result_holder else {"success": False, "error": "Unknown error"}
                yield f"event: result\ndata: {json.dumps(data)}\n\n"
                break
            else:
                yield f"event: progress\ndata: {json.dumps({'message': msg})}\n\n"

    return Response(
        _generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/download/<filename>")
def download(filename):
    filepath = REPORTS_DIR / filename
    if not filepath.exists():
        return jsonify({"error": "Report not found."}), 404
    return send_file(filepath, as_attachment=True, download_name=filename)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
