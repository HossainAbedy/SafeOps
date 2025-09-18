# backend/checks.py
"""
Core detection routines (pure functions) for SafeOps.
Designed to return JSON-serializable dicts:
{'ok': bool, 'data': ..., 'error': ...}
"""

import os
import psutil
import subprocess
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from utils import (
    get_systeminfo, now_iso, sha256_of_file, is_windows,
    safe_run, json_ok, json_err, logger, truncate_text, command_exists
)
from config import CRITICAL_FILES, BASELINE_FILE, MAX_ISASS_RESULTS

# Windows-specific imports
try:
    import win32security
    import win32api
    import win32con
    import pywintypes
    import win32evtlog
    import winreg
except ImportError:
    win32security = win32api = win32con = pywintypes = win32evtlog = winreg = None

# Optional remote scan helper
try:
    from remote_helpers import run_remote_scan as _remote_run_remote_scan
except Exception as _e:
    _remote_run_remote_scan = None
    try:
        logger.warning("remote_helpers.run_remote_scan not available: %s", _e)
    except Exception:
        pass

LOLBINS = [
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "wmic.exe", "schtasks.exe", "net.exe"
]

logger = logging.getLogger(__name__)

# -------------------------
# Privileges
# -------------------------
def enable_security_privilege() -> bool:
    if not is_windows() or not win32security:
        return False
    try:
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
        )
        priv_id = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
        win32security.AdjustTokenPrivileges(token, False, [(priv_id, win32con.SE_PRIVILEGE_ENABLED)])
        return True
    except Exception as e:
        logger.warning(f"Failed to enable SeSecurityPrivilege: {e}")
        return False

# -------------------------
# Process enumeration
# -------------------------
def check_processes() -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    suspicious: List[Dict[str, Any]] = []

    try:
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "ppid"]):
            try:
                info = p.info
                name = (info.get("name") or "").lower()
                exe = info.get("exe") or ""
                cmd = " ".join(info.get("cmdline") or [])
                entry = {
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": name,
                    "exe": exe,
                    "cmdline": cmd,
                    "username": info.get("username"),
                }
                results.append(entry)

                exe_l = exe.lower()
                # heuristics
                if name == "svchost.exe" and exe and not (exe_l.startswith(r"c:\windows\system32") or exe_l.startswith(r"c:\windows\syswow64")):
                    suspicious.append({"type": "svchost_path", "detail": entry})
                if name == "rundll32.exe" and any(x in cmd.lower() for x in ("appdata", "temp", "users")):
                    suspicious.append({"type": "rundll32_untrusted_dll", "detail": entry})
                if name in ("powershell.exe", "pwsh.exe"):
                    if "-encodedcommand" in cmd.lower() or "-enc" in cmd.lower() or len(cmd) > 200:
                        suspicious.append({"type": "powershell_encoded_command", "detail": entry})
                    if any(binname in cmd.lower() for binname in LOLBINS):
                        suspicious.append({"type": "powershell_lolbin_usage", "detail": entry})
                if name == "isass.exe":
                    suspicious.append({"type": "isass_process", "detail": entry})
                if name == "lsass.exe" and exe and not exe_l.startswith(r"c:\windows\system32"):
                    suspicious.append({"type": "lsass_path", "detail": entry})
                if "certutil -urlcache" in cmd.lower() or "bitsadmin" in cmd.lower() or "downloadfile" in cmd.lower():
                    suspicious.append({"type": "file_download_lolbin", "detail": entry})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logger.exception("check_processes error")
        return json_err(f"process enumeration failed: {e}")

    return json_ok({"all_processes": results, "suspicious": suspicious})

# -------------------------
# File integrity
# -------------------------
def file_integrity_check(files: Optional[List[str]] = None) -> Dict[str, Any]:
    files = files or CRITICAL_FILES
    out = {}
    for f in files:
        try:
            out[f] = {
                "sha256": sha256_of_file(f),
                "size": os.path.getsize(f) if os.path.exists(f) else None,
                "present": os.path.exists(f)
            }
        except Exception:
            out[f] = {"sha256": None, "size": None, "present": False}
    return json_ok(out)

def create_baseline() -> Dict[str, Any]:
    res = file_integrity_check()
    if not res.get("ok"):
        return res
    data = {"meta": {"created": now_iso()}, "baseline": res.get("data")}
    try:
        with open(BASELINE_FILE, "w") as fh:
            json.dump(data, fh, indent=2)
        return json_ok({"meta": data["meta"], "path": BASELINE_FILE})
    except Exception as e:
        logger.exception("create_baseline failed")
        return json_err(f"could not write baseline: {e}")

def compare_to_baseline() -> Dict[str, Any]:
    if not os.path.exists(BASELINE_FILE):
        return json_err("baseline not found")
    try:
        with open(BASELINE_FILE, "r") as fh:
            old = json.load(fh)
    except Exception as e:
        logger.exception("compare_to_baseline read failed")
        return json_err(f"cannot read baseline: {e}")

    current = file_integrity_check()
    if not current.get("ok"):
        return current

    diffs = {}
    baseline = old.get("baseline", {})
    curdata = current.get("data", {})
    for k, v in baseline.items():
        cur = curdata.get(k, {})
        if v.get("sha256") != cur.get("sha256"):
            diffs[k] = {"baseline": v, "current": cur}
    return json_ok({"baseline_file": BASELINE_FILE, "differences": diffs})

# -------------------------
# Registry / startup / services
# -------------------------
def check_registry_run_keys() -> Dict[str, Any]:
    if not is_windows() or not winreg:
        return json_err("not windows")
    hits = []
    try:
        keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive, path in keys:
            try:
                k = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                        hits.append({"hive": str(hive), "path": path, "name": name, "value": val})
                        i += 1
                    except OSError:
                        break
            except FileNotFoundError:
                continue
    except Exception as e:
        logger.exception("check_registry_run_keys failed")
        return json_err(f"could not enumerate registry: {e}")
    return json_ok(hits)

def check_startup_folders() -> Dict[str, Any]:
    hits = []
    try:
        user_start = os.path.join(os.path.expanduser("~"), r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        all_start = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        for p in (user_start, all_start):
            if os.path.exists(p):
                for f in os.listdir(p):
                    hits.append({"startup_folder": p, "file": f})
        return json_ok(hits)
    except Exception as e:
        logger.exception("check_startup_folders failed")
        return json_err(str(e))

def check_autostart_services() -> Dict[str, Any]:
    if not is_windows():
        return json_err("not windows")
    svcs = []
    try:
        for svc in psutil.win_service_iter():
            try:
                svcs.append(svc.as_dict())
            except Exception:
                continue
        return json_ok(svcs)
    except Exception as e:
        logger.exception("check_autostart_services failed")
        return json_err(str(e))

# -------------------------
# Windows Event Logs
# -------------------------
def read_event_logs(max_records: int = 50) -> Dict[str, Any]:
    if not is_windows() or not win32evtlog:
        return json_err("not windows or win32evtlog not available")
    logs = []
    try:
        server = "localhost"
        log_types = ["System", "Security", "Application"]
        for log_type in log_types:
            hand = win32evtlog.OpenEventLog(server, log_type)
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            count = 0
            for e in events:
                logs.append({"log_type": log_type, "event_id": e.EventID, "source": e.SourceName, "time": str(e.TimeGenerated), "category": e.EventCategory})
                count += 1
                if count >= max_records:
                    break
        return json_ok(logs)
    except Exception as e:
        logger.exception("read_event_logs failed")
        return json_err(str(e))

# -------------------------
# Scan for ISASS
# -------------------------
def scan_for_isass(limit: int = 50) -> Dict[str, Any]:
    suspicious = []
    try:
        for p in psutil.process_iter(["pid", "name"]):
            if p.info.get("name", "").lower() == "isass.exe":
                suspicious.append({"pid": p.info["pid"], "name": p.info["name"]})
                if len(suspicious) >= limit:
                    break
        return json_ok(suspicious)
    except Exception as e:
        logger.exception("scan_for_isass failed")
        return json_err(str(e))

# -------------------------
# Performance / network
# -------------------------
def check_performance(short_interval: int = 1) -> Dict[str, Any]:
    try:
        perf = {"cpu_percent": psutil.cpu_percent(interval=short_interval)}
        mem = psutil.virtual_memory()
        perf["memory"] = {"total": mem.total, "available": mem.available, "percent": mem.percent}
        perf["disk_usage"] = {"c": psutil.disk_usage("C:\\")._asdict()} if os.path.exists("C:\\") else {}
        return json_ok(perf)
    except Exception as e:
        logger.exception("check_performance failed")
        return json_err(str(e))

def check_network_connections() -> Dict[str, Any]:
    try:
        conns = []
        remote_counts = {}
        for c in psutil.net_connections(kind="inet"):
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            conns.append({"fd": getattr(c, "fd", None), "laddr": laddr, "raddr": raddr, "status": getattr(c, "status", None), "pid": getattr(c, "pid", None)})
            if c.raddr:
                remote_counts[c.raddr.ip] = remote_counts.get(c.raddr.ip, 0) + 1
        top_remote = sorted(remote_counts.items(), key=lambda x: x[1], reverse=True)[:50]
        return json_ok({"connections": conns, "top_remote": top_remote})
    except Exception as e:
        logger.exception("check_network_connections failed")
        return json_err(str(e))

# -------------------------
# Composite runners
# -------------------------
def run_checks_compact(target: str = "local") -> Dict[str, Any]:
    try:
        system_info = get_systeminfo(target)
        return json_ok({"ts": now_iso(), "system_info": system_info})
    except Exception as e:
        return json_err(f"run_checks_compact failed: {e}")

def run_all_extended(include_isass_scan: bool = False) -> Dict[str, Any]:
    try:
        out = {
            "ts": now_iso(),
            "process_checks": check_processes().get("data"),
            "file_integrity": file_integrity_check().get("data"),
            "baseline_exists": os.path.exists(BASELINE_FILE),
            "persistence": {
                "registry_run": check_registry_run_keys().get("data"),
                "startup_folders": check_startup_folders().get("data"),
                "autostart_services": check_autostart_services().get("data"),
            },
            "performance": check_performance().get("data"),
            "network": check_network_connections().get("data"),
        }
        if include_isass_scan:
            out["isass_scan"] = scan_for_isass().get("data")
        return json_ok(out)
    except Exception as e:
        logger.exception("run_all_extended failed")
        return json_err(str(e))

# -------------------------
# Remote scan wrapper
# -------------------------
def run_remote_scan(host: str, username: str, password: str, transport: str = "ntlm") -> Dict[str, Any]:
    if _remote_run_remote_scan is None:
        return json_err("remote scan not available")
    try:
        return _remote_run_remote_scan(host, username, password, transport)
    except Exception as e:
        logger.exception("run_remote_scan wrapper failed")
        return json_err(str(e))
