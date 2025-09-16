# backend/routes/system_routes.py
from flask import Blueprint, jsonify, request, send_file
from services import jobs as job_service
from services import scanner
from utils.logger import logger
from pathlib import Path
import time

bp = Blueprint("system", __name__)  # registered with no prefix so routes appear at root

# In-memory hosts registry (replace with DB in production)
_HOSTS = {}

# -------------------------
# Health
# -------------------------
@bp.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "data": {"status": "ok"}})


# -------------------------
# Baseline
# -------------------------
@bp.route("/baseline", methods=["POST"])
def create_baseline():
    try:
        job_id = job_service.submit_job(scanner.create_baseline)
        if not job_id:
            raise RuntimeError("Job submission failed")
        return jsonify({"ok": True, "data": {"job_id": job_id}})
    except Exception as e:
        logger.exception("create_baseline failed")
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/baseline", methods=["GET"])
def get_baseline():
    # attempt to return baseline file if it exists
    from config import BASELINE_FILE
    p = Path(BASELINE_FILE)
    if p.exists():
        try:
            return send_file(str(p), as_attachment=True)
        except Exception as e:
            logger.exception("get_baseline send_file failed")
            return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify({"ok": False, "error": "baseline not found"}), 404


@bp.route("/compare-baseline", methods=["POST"])
def compare_baseline():
    try:
        res = scanner.compare_to_baseline()
        return jsonify(res)
    except Exception as e:
        logger.exception("compare_baseline failed")
        return jsonify({"ok": False, "error": str(e)}), 500


# -------------------------
# Jobs
# -------------------------
@bp.route("/jobs", methods=["GET"])
def list_jobs():
    jobs_list = []
    for jid, meta in job_service._jobs.items():
        jobs_list.append({
            "job_id": jid,
            "status": meta.get("status"),
            "created": meta.get("created"),
            "result_file": meta.get("result_file"),
        })
    return jsonify({"ok": True, "data": jobs_list})


@bp.route("/job/<job_id>", methods=["GET"])
def job_status(job_id):
    j = job_service.get_job(job_id)
    if not j:
        return jsonify({"ok": False, "error": "unknown job id"}), 404
    return jsonify({"ok": True, "data": j})


@bp.route("/job/<job_id>/download", methods=["GET"])
def download_job(job_id):
    j = job_service.get_job(job_id)
    if not j or not j.get("result_file"):
        return jsonify({"ok": False, "error": "no result available"}), 404
    try:
        return send_file(j["result_file"], as_attachment=True)
    except Exception as e:
        logger.exception("download_job failed")
        return jsonify({"ok": False, "error": str(e)}), 500


# -------------------------
# Hosts
# -------------------------
@bp.route("/hosts", methods=["GET", "POST"])
def hosts_list_create():
    if request.method == "GET":
        return jsonify({"ok": True, "data": list(_HOSTS.values())})

    body = request.json or {}
    host_id = body.get("id") or body.get("hostname")
    ip = body.get("ip")
    if not host_id or not ip:
        return jsonify({"ok": False, "error": "hostname/id and ip required"}), 400

    _HOSTS[host_id] = {
        "id": host_id,
        "hostname": host_id,
        "ip": ip,
        "agent_installed": bool(body.get("agent_installed", False)),
        "last_seen": None,
    }
    return jsonify({"ok": True, "data": _HOSTS[host_id]}), 201


@bp.route("/hosts/<host_id>", methods=["GET"])
def host_get(host_id):
    h = _HOSTS.get(host_id)
    if not h:
        return jsonify({"ok": False, "error": "host not found"}), 404
    return jsonify({"ok": True, "data": h})


@bp.route("/hosts/<host_id>/scan", methods=["POST"])
def host_scan(host_id):
    h = _HOSTS.get(host_id)
    if not h:
        return jsonify({"ok": False, "error": "unknown host id"}), 404

    body = request.json or {}
    username = body.get("username")
    password = body.get("password")
    transport = body.get("transport", "ntlm")
    if not username or not password:
        return jsonify({"ok": False, "error": "username and password required for remote scan"}), 400

    host_ip = h.get("ip")
    job_id = job_service.submit_job(scanner.run_remote_scan, host_ip, username, password, transport)
    if not job_id:
        return jsonify({"ok": False, "error": "Job submission failed"}), 500
    return jsonify({"ok": True, "data": {"job_id": job_id}})


# -------------------------
# Logs
# -------------------------
@bp.route("/logs", methods=["GET"])
def logs_query():
    limit = request.args.get("limit")
    try:
        limit_v = int(limit) if limit else 50
    except ValueError:
        limit_v = 50

    res = scanner.read_event_logs(limit_v)
    return jsonify(res)


# -------------------------
# Jobs cleanup
# -------------------------
@bp.route("/jobs/clear", methods=["POST"])
def clear_jobs():
    data = request.json or {}
    max_age = int(data.get("max_age_seconds", 0))  # 0 means ignore age

    removed_jobs = []
    now_ts = time.time()

    for jid, meta in list(job_service._jobs.items()):
        status = meta.get("status")
        created_str = meta.get("created")
        if not created_str:
            continue
        try:
            created_ts = time.mktime(time.strptime(created_str, "%Y-%m-%dT%H:%M:%S.%f"))
        except Exception:
            # fallback - don't remove if parse fails
            continue
        age_ok = (max_age == 0) or (now_ts - created_ts >= max_age)

        if status in ("done", "error") and age_ok:
            rf = meta.get("result_file")
            if rf:
                try:
                    Path(rf).unlink()
                except Exception:
                    pass
            removed_jobs.append(jid)
            del job_service._jobs[jid]

    return jsonify({"ok": True, "removed_jobs": removed_jobs})
