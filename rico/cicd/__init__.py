"""
CI/CD Integration Module for RICO

Provides DevSecOps capabilities:
- Pipeline blocking based on severity thresholds
- SARIF report generation for GitHub integration
- Exit code management for CI/CD systems
"""

from rico.cicd.pipeline_enforcer import PipelineEnforcer, should_fail_build
from rico.cicd.sarif_exporter import SARIFExporter

__all__ = [
    "PipelineEnforcer",
    "should_fail_build",
    "SARIFExporter",
]
