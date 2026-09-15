"""Flask web UI for the vulnerability scanner agent."""

import json
import queue
import threading

from flask import Flask, Response, jsonify, render_template, request, send_file
from pathlib import Path
from scanner import scan_repo, scan_local_repo, clone_repo_to, REPORTS_DIR
from fixReport import fix_repo, apply_patch, apply_patch_local, _create_pr_branch_and_push, _ACTIVE_PATCHES, cleanup_patch

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


@app.route("/clone", methods=["POST"])
def clone_to_local():
    """Clone a repo to a user-specified local directory."""
    data = request.get_json(force=True)
    repo_url = (data.get("repo_url") or "").strip()
    clone_path = (data.get("clone_path") or "").strip()

    if not repo_url:
        return jsonify({"success": False, "error": "Repository URL is required."}), 400
    if not clone_path:
        return jsonify({"success": False, "error": "Clone path is required."}), 400

    try:
        result_path = clone_repo_to(repo_url, clone_path)
        return jsonify({"success": True, "local_path": str(result_path)})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/scan/local/stream", methods=["GET"])
def scan_local_stream():
    """SSE endpoint: scan an already-cloned local repo."""
    local_path = (request.args.get("local_path") or "").strip()
    if not local_path:
        return jsonify({"success": False, "error": "Local path is required."}), 400

    progress_queue: queue.Queue[str | None] = queue.Queue()
    result_holder: list[dict] = []

    def _on_progress(message: str):
        progress_queue.put(message)

    def _run_scan():
        try:
            result = scan_local_repo(local_path, progress_callback=_on_progress)
            result_holder.append(result)
        except Exception as exc:
            result_holder.append({"success": False, "error": str(exc)})
        finally:
            progress_queue.put(None)

    thread = threading.Thread(target=_run_scan, daemon=True)
    thread.start()

    def _generate():
        while True:
            try:
                msg = progress_queue.get(timeout=120)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            if msg is None:
                data = result_holder[0] if result_holder else {"success": False, "error": "Unknown error"}
                yield f"event: result\ndata: {json.dumps(data)}\n\n"
                break
            else:
                yield f"event: progress\ndata: {json.dumps({'message': msg})}\n\n"

    return Response(_generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/fix/apply-local", methods=["POST"])
def fix_apply_local():
    """SSE endpoint: apply fixes on a local repo using scan report rows."""
    data = request.get_json(force=True)
    local_path = (data.get("local_path") or "").strip()
    ecosystem = (data.get("ecosystem") or "").strip()
    scan_rows = data.get("rows", [])

    if not local_path:
        return jsonify({"success": False, "error": "Local path is required."}), 400
    if not scan_rows:
        return jsonify({"success": False, "error": "No scan rows provided."}), 400
    if not ecosystem:
        return jsonify({"success": False, "error": "Ecosystem is required."}), 400

    progress_queue: queue.Queue[str | None] = queue.Queue()
    result_holder: list[dict] = []

    def _on_progress(message: str):
        progress_queue.put(message)

    def _run_patch():
        try:
            result = apply_patch_local(
                local_path=local_path,
                scan_rows=scan_rows,
                ecosystem=ecosystem,
                progress_callback=_on_progress,
            )
            result_holder.append(result)
        except Exception as exc:
            result_holder.append({"success": False, "error": str(exc)})
        finally:
            progress_queue.put(None)

    thread = threading.Thread(target=_run_patch, daemon=True)
    thread.start()

    def _generate():
        while True:
            try:
                msg = progress_queue.get(timeout=300)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            if msg is None:
                result = result_holder[0] if result_holder else {"success": False, "error": "Unknown error"}
                yield f"event: result\ndata: {json.dumps(result)}\n\n"
                break
            else:
                yield f"event: progress\ndata: {json.dumps({'message': msg})}\n\n"

    return Response(_generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/fix/stream", methods=["GET"])
def fix_stream():
    """SSE endpoint: clone → scan → fix → build → re-scan loop with live progress."""
    repo_url = (request.args.get("repo_url") or "").strip()
    if not repo_url:
        return jsonify({"success": False, "error": "Repository URL is required."}), 400

    progress_queue: queue.Queue[str | None] = queue.Queue()
    result_holder: list[dict] = []

    def _on_progress(message: str):
        progress_queue.put(message)

    def _run_fix():
        try:
            result = fix_repo(repo_url, progress_callback=_on_progress)
            result_holder.append(result)
        except Exception as exc:
            result_holder.append({"success": False, "error": str(exc)})
        finally:
            progress_queue.put(None)

    thread = threading.Thread(target=_run_fix, daemon=True)
    thread.start()

    def _generate():
        while True:
            try:
                msg = progress_queue.get(timeout=300)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue

            if msg is None:
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


@app.route("/fix/apply", methods=["POST"])
def fix_apply():
    """
    SSE endpoint: takes the scan report rows + repo URL as input,
    applies fixes from the report, builds, re-scans iteratively.
    Expects JSON body: { repo_url, ecosystem, rows: [[sev, label, fix], …] }
    """
    data = request.get_json(force=True)
    repo_url = (data.get("repo_url") or "").strip()
    ecosystem = (data.get("ecosystem") or "").strip()
    scan_rows = data.get("rows", [])

    if not repo_url:
        return jsonify({"success": False, "error": "Repository URL is required."}), 400
    if not scan_rows:
        return jsonify({"success": False, "error": "No scan rows provided."}), 400
    if not ecosystem:
        return jsonify({"success": False, "error": "Ecosystem is required."}), 400

    progress_queue: queue.Queue[str | None] = queue.Queue()
    result_holder: list[dict] = []

    def _on_progress(message: str):
        progress_queue.put(message)

    def _run_patch():
        try:
            result = apply_patch(
                repo_url=repo_url,
                scan_rows=scan_rows,
                ecosystem=ecosystem,
                progress_callback=_on_progress,
            )
            result_holder.append(result)
        except Exception as exc:
            result_holder.append({"success": False, "error": str(exc)})
        finally:
            progress_queue.put(None)

    thread = threading.Thread(target=_run_patch, daemon=True)
    thread.start()

    def _generate():
        while True:
            try:
                msg = progress_queue.get(timeout=300)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue

            if msg is None:
                result = result_holder[0] if result_holder else {"success": False, "error": "Unknown error"}
                yield f"event: result\ndata: {json.dumps(result)}\n\n"
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


@app.route("/fix/create-pr", methods=["POST"])
def create_pr():
    """
    Create a branch, commit changes, push, and open a PR for a held patch.
    Expects JSON: { patch_id, branch_name (optional), commit_message (optional) }
    """
    data = request.get_json(force=True)
    patch_id = (data.get("patch_id") or "").strip()

    if not patch_id or patch_id not in _ACTIVE_PATCHES:
        return jsonify({"success": False, "error": "Invalid or expired patch ID."}), 400

    repo_path = _ACTIVE_PATCHES[patch_id]
    branch_name = (data.get("branch_name") or "").strip() or f"fix/vuln-patch-{patch_id[:8]}"
    commit_message = (data.get("commit_message") or "").strip() or "fix: upgrade vulnerable dependencies to patched versions"

    result = _create_pr_branch_and_push(repo_path, branch_name, commit_message)

    # Clean up the repo after PR attempt
    cleanup_patch(patch_id)

    return jsonify(result)


@app.route("/fix/cleanup", methods=["POST"])
def cleanup():
    """Clean up a held patch repo without creating a PR."""
    data = request.get_json(force=True)
    patch_id = (data.get("patch_id") or "").strip()
    if patch_id:
        cleanup_patch(patch_id)
    return jsonify({"success": True})


@app.route("/download/<filename>")
def download(filename):
    filepath = REPORTS_DIR / filename
    if not filepath.exists():
        return jsonify({"error": "Report not found."}), 404
    return send_file(filepath, as_attachment=True, download_name=filename)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
