"""
RICO Services Layer

Provides programmatic access to RICO functionality without CLI dependencies.
"""

from rico.services.scan_service import run_scan, ScanResult

__all__ = ["run_scan", "ScanResult"]
