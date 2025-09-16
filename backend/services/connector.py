"""
Connector abstraction. For now we delegate to checks.run_remote_scan if available (WinRM path).
Later you can add agent communication and PSExec fallbacks here.
"""
from typing import Dict
from utils.logger import logger
import config


try:
    import checks
    HAS_CHECKS = True
except Exception:
    HAS_CHECKS = False




def run_remote_scan(host: str, username: str, password: str, transport: str = "ntlm") -> Dict:
    if not HAS_CHECKS:
        return {"ok": False, "error": "remote scan not available: checks module missing"}
    try:
        return checks.run_remote_scan(host, username, password, transport)
    except Exception as e:
        logger.exception("connector.run_remote_scan failed")
    return {"ok": False, "error": str(e)}