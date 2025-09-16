# backend/utils/helpers.py
import os
import hashlib
import json
import subprocess
import logging
from datetime import datetime
from typing import Any, Dict

logger = logging.getLogger(__name__)
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)


# -------------------------
# JSON helpers
# -------------------------
def json_ok(data: Any = None) -> Dict[str, Any]:
    return {"ok": True, "data": data}


def json_err(error: str) -> Dict[str, Any]:
    return {"ok": False, "error": error}


# -------------------------
# File hash
# -------------------------
def sha256_of_file(path: str) -> str:
    if not os.path.exists(path):
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.warning(f"sha256_of_file failed for {path}: {e}")
        return None


# -------------------------
# Command runner
# -------------------------
def safe_run(cmd: list, timeout: int = 10) -> Dict[str, Any]:
    """Run a subprocess safely and return structured output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {"rc": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 1, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        return {"rc": 1, "stdout": "", "stderr": str(e)}


# -------------------------
# OS checks
# -------------------------
def is_windows() -> bool:
    return os.name == "nt"


# -------------------------
# Timestamp helpers
# -------------------------
def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


# -------------------------
# System info stub
# -------------------------
def get_systeminfo(target: str = "local") -> Dict[str, Any]:
    """
    Return basic system info for target host.
    Replace with full implementation if remote scanning is enabled.
    """
    try:
        import platform
        hostname = os.environ.get("COMPUTERNAME", "localhost")
        info = {
            "hostname": hostname,
            "os": platform.system(),
            "os_version": platform.version(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "target": target,
        }
        return info
    except Exception as e:
        logger.warning(f"get_systeminfo failed: {e}")
        return {"hostname": "unknown", "error": str(e)}


# -------------------------
# Text helpers
# -------------------------
def truncate_text(s: str, max_len: int = 200) -> str:
    if not s:
        return ""
    return s if len(s) <= max_len else s[:max_len] + "..."


# -------------------------
# Command existence
# -------------------------
def command_exists(cmd: str) -> bool:
    """Check if a command exists in PATH"""
    from shutil import which
    return which(cmd) is not None
