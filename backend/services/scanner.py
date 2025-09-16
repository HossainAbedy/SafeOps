# backend/services/scanner.py
"""
Scanner wrappers around checks.py functions. Import checks *safely* because checks.py may import Windows-only modules.
"""

from typing import Any, Dict
from utils.logger import logger

# Try to import checks; if not available, provide stubs that return errors
try:
    import checks
    CHECKS_AVAILABLE = True
except Exception as e:
    logger.warning("checks module not importable: %s", e)
    CHECKS_AVAILABLE = False
    checks = None


def run_all_extended(include_isass_scan: bool = False) -> Dict[str, Any]:
    if not CHECKS_AVAILABLE:
        return {"ok": False, "error": "checks module not available on this runtime"}
    try:
        return checks.run_all_extended(include_isass_scan)
    except Exception as e:
        logger.exception("run_all_extended failed")
        return {"ok": False, "error": str(e)}


def run_checks_compact(target: str = "local") -> Dict[str, Any]:
    if not CHECKS_AVAILABLE:
        return {"ok": False, "error": "checks module not available on this runtime"}
    try:
        return checks.run_checks_compact(target)
    except Exception as e:
        logger.exception("run_checks_compact failed")
        return {"ok": False, "error": str(e)}


def create_baseline() -> Dict[str, Any]:
    if not CHECKS_AVAILABLE:
        return {"ok": False, "error": "checks module not available"}
    try:
        return checks.create_baseline()
    except Exception as e:
        logger.exception("create_baseline failed")
        return {"ok": False, "error": str(e)}


def compare_to_baseline() -> Dict[str, Any]:
    if not CHECKS_AVAILABLE:
        return {"ok": False, "error": "checks module not available"}
    try:
        return checks.compare_to_baseline()
    except Exception as e:
        logger.exception("compare_to_baseline failed")
        return {"ok": False, "error": str(e)}


def read_event_logs(max_records: int = 50) -> Dict[str, Any]:
    if not CHECKS_AVAILABLE:
        return {"ok": False, "error": "checks module not available"}
    try:
        return checks.read_event_logs(max_records)
    except Exception as e:
        logger.exception("read_event_logs failed")
        return {"ok": False, "error": str(e)}


def scan_for_isass(limit: int = 50) -> Dict[str, Any]:
    if not CHECKS_AVAILABLE:
        return {"ok": False, "error": "checks module not available"}
    try:
        return checks.scan_for_isass(limit)
    except Exception as e:
        logger.exception("scan_for_isass failed")
        return {"ok": False, "error": str(e)}
