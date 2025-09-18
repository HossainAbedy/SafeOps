# backend/services/__init__.py
"""
Services package initialization.
Provides easy imports for scanner, jobs, and connector modules.
"""

from . import scanner
from . import jobs
from . import connector

# Optional: re-export common functions for convenience
__all__ = [
    "scanner",
    "jobs",
    "connector",
]
