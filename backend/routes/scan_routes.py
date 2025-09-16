# backend/routes/scan_routes.py
from flask import Blueprint, jsonify, request
from services import jobs
from services import scanner
from utils.logger import logger

bp = Blueprint("scan", __name__)  # will be registered with url_prefix="/scan" in app.py


@bp.route("/local", methods=["POST"])
def scan_local():
    try:
        # run compact or full local checks depending on your desired function
        # here we call run_checks_compact for a quick run; change to run_all_extended if preferred
        job_id = jobs.submit_job(scanner.run_checks_compact, "local")
        if not job_id:
            raise RuntimeError("Job submission failed")
        return jsonify({"ok": True, "data": {"job_id": job_id}})
    except Exception as e:
        logger.exception("scan_local failed")
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/extended", methods=["POST"])
def scan_extended():
    try:
        include_isass = False
        if request.is_json:
            include_isass = bool(request.json.get("scan_isass") or request.json.get("include_isass", False))
        job_id = jobs.submit_job(scanner.run_all_extended, include_isass)
        if not job_id:
            raise RuntimeError("Job submission failed")
        return jsonify({"ok": True, "data": {"job_id": job_id}})
    except Exception as e:
        logger.exception("scan_extended failed")
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/remote", methods=["POST"])
def scan_remote():
    try:
        data = request.json or {}
        host = data.get("host")
        username = data.get("username")
        password = data.get("password")
        transport = data.get("transport", "ntlm")
        if not host or not username or not password:
            return jsonify({"ok": False, "error": "Missing host/username/password"}), 400

        job_id = jobs.submit_job(scanner.run_remote_scan, host, username, password, transport)
        if not job_id:
            raise RuntimeError("Job submission failed")
        return jsonify({"ok": True, "data": {"job_id": job_id}})
    except Exception as e:
        logger.exception("scan_remote failed")
        return jsonify({"ok": False, "error": str(e)}), 500
