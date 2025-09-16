# backend/services/jobs.py
"""
Simple job runner using ThreadPoolExecutor.
Stores results in an in-memory dict and writes JSON result files to RESULTS_DIR.
Swap this for Celery/Redis in production.
"""
import uuid
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional
from pathlib import Path
from datetime import datetime
from utils.logger import logger
import config

executor = ThreadPoolExecutor(max_workers=4)
_jobs: Dict[str, Dict[str, Any]] = {}


def submit_job(fn, *args, **kwargs) -> str:
    """
    Submit a function to the thread pool and track its status/result.
    Returns a job_id (UUID string).
    """
    job_id = str(uuid.uuid4())

    def _callback(fut):
        try:
            res = fut.result()
            # write result to persistent file
            fname = Path(config.RESULTS_DIR) / f"{job_id}.json"
            try:
                with open(fname, "w", encoding="utf-8") as fh:
                    json.dump(res, fh, indent=2)
                _jobs[job_id]["result_file"] = str(fname)
            except Exception:
                logger.exception("failed to write result file for job %s", job_id)
                _jobs[job_id]["result_file"] = None

            _jobs[job_id]["status"] = "done"
            _jobs[job_id]["result"] = res
        except Exception as e:
            logger.exception("job %s failed", job_id)
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["result"] = {"ok": False, "error": str(e)}

    future = executor.submit(fn, *args, **kwargs)
    future.add_done_callback(_callback)

    _jobs[job_id] = {
        "future": future,
        "created": datetime.utcnow().isoformat(),
        "status": "running",
        "result_file": None,
    }

    return job_id


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve job info by job_id.
    Returns dict with status, result_file, and result (if completed).
    """
    j = _jobs.get(job_id)
    if not j:
        return None
    return {
        "job_id": job_id,
        "status": j.get("status"),
        "created": j.get("created"),
        "result_file": j.get("result_file"),
        "result": j.get("result") if j.get("status") == "done" else None,
    }
