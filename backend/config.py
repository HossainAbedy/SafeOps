# config.py - SafeOps configuration & constants
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


# Files used by checks.py; keep defaults but allow env override
CRITICAL_FILES = os.environ.get("CRITICAL_FILES", "," ).split(",") if os.environ.get("CRITICAL_FILES") else [
    r"C:\\Windows\\System32\\kernel32.dll",
    r"C:\\Windows\\System32\\ntdll.dll",
    r"C:\Windows\System32\sethc.exe",
    r"C:\Windows\System32\utilman.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\rundll32.exe",
    r"C:\Windows\System32\explorer.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
]
BASELINE_FILE = os.environ.get("BASELINE_FILE", str(BASE_DIR / "baseline.json"))
MAX_ISASS_RESULTS = int(os.environ.get("MAX_ISASS_RESULTS", "50"))


# JWT / secrets
JWT_SECRET = os.environ.get("SAFEOPS_JWT_SECRET", "change-this-secret-in-prod")
JWT_ALGO = os.environ.get("SAFEOPS_JWT_ALGO", "HS256")


# WinRM support flag (will be set if pywinrm is importable)
try:
    import winrm # type: ignore
    WINRM_AVAILABLE = True
except Exception:
    WINRM_AVAILABLE = False


# Other runtime settings
HOST = os.environ.get("SAFEOPS_HOST", "127.0.0.1")
PORT = int(os.environ.get("SAFEOPS_PORT", "5000"))
DEBUG = os.environ.get("SAFEOPS_DEBUG", "1") == "1"


# Storage for result JSONs (local path for MVP; swap to S3/MinIO in prod)
RESULTS_DIR = os.environ.get("SAFEOPS_RESULTS_DIR", str(BASE_DIR / "results"))
os.makedirs(RESULTS_DIR, exist_ok=True)