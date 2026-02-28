"""
Report Builder - Orchestrates the enterprise reporting system

This is the main entry point for generating security reports.
It coordinates:
- Vulnerability enrichment with compliance mappings
- Risk aggregation and scoring
- Multi-format export (JSON, Markdown, HTML)
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

from rico.reporting.compliance_mapper import ComplianceMapper
from rico.reporting.risk_aggregator import RiskAggregator
from rico.reporting.json_exporter import JSONExporter
from rico.reporting.markdown_exporter import MarkdownExporter
from rico.reporting.html_exporter import HTMLExporter

logger = logging.getLogger("rico.reporting")


class ReportBuilder:
    """
    Main report builder class.
    
    Orchestrates the entire reporting pipeline:
    1. Enriches vulnerabilities with compliance mappings
    2. Aggregates risk metrics
    3. Generates executive summary
    4. Exports to multiple formats
    """
    
    def __init__(self, vulnerabilities: List[Dict[str, Any]], target_url: str = None, 
                 scan_timestamp: str = None, additional_metadata: Dict[str, Any] = None):
        """
        Initialize report builder.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            target_url: Target URL that was scanned
            scan_timestamp: Timestamp of the scan
            additional_metadata: Additional metadata to include
        """
        self.raw_vulnerabilities = vulnerabilities
        self.target_url = target_url or "Unknown"
        self.scan_timestamp = scan_timestamp or datetime.utcnow().isoformat()
        self.additional_metadata = additional_metadata or {}
        
        # Enrich vulnerabilities
        self.enriched_vulnerabilities = self._enrich_vulnerabilities()
        
        # Initialize aggregator
        self.aggregator = RiskAggregator(self.enriched_vulnerabilities)
        
        # Generate summary stats
        self.summary_stats = self.aggregator.get_summary_statistics()
        
        # Generate executive summary
        self.executive_summary = self.aggregator.generate_executive_summary(self.target_url)
        
        # Prepare metadata
        self.metadata = {
            "target_url": self.target_url,
            "scan_timestamp": self.scan_timestamp,
            **self.additional_metadata
        }
        
        logger.info(f"Report builder initialized: {len(self.enriched_vulnerabilities)} vulnerabilities")
    
    def _enrich_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Enrich vulnerabilities with compliance mappings.
        
        Returns:
            List of enriched vulnerabilities
        """
        enriched = []
        
        for idx, vuln in enumerate(self.raw_vulnerabilities, 1):
            # Ensure vulnerability has required fields
            if "id" not in vuln:
                vuln["id"] = f"RICO-{idx:03d}"
            
            # Enrich with OWASP and CWE mappings
            enriched_vuln = ComplianceMapper.enrich_vulnerability(vuln.copy())
            enriched.append(enriched_vuln)
        
        return enriched
    
    def export_json(self, filepath: str) -> None:
        """
        Export report to JSON file.
        
        Args:
            filepath: Output file path
        """
        logger.info(f"Exporting JSON report to: {filepath}")
        exporter = JSONExporter(self.enriched_vulnerabilities, self.metadata)
        exporter.export_to_file(filepath, self.summary_stats)
        logger.info("JSON report exported successfully")
    
    def export_markdown(self, filepath: str) -> None:
        """
        Export report to Markdown file.
        
        Args:
            filepath: Output file path
        """
        logger.info(f"Exporting Markdown report to: {filepath}")
        exporter = MarkdownExporter(self.enriched_vulnerabilities, self.metadata)
        exporter.export_to_file(filepath, self.summary_stats, self.executive_summary)
        logger.info("Markdown report exported successfully")
    
    def export_html(self, filepath: str) -> None:
        """
        Export report to HTML file.
        
        Args:
            filepath: Output file path
        """
        logger.info(f"Exporting HTML report to: {filepath}")
        exporter = HTMLExporter(self.enriched_vulnerabilities, self.metadata)
        exporter.export_to_file(filepath, self.summary_stats, self.executive_summary)
        logger.info("HTML report exported successfully")
    
    def export_all(self, output_dir: str = "reports", base_filename: str = "report") -> Dict[str, str]:
        """
        Export reports in all formats.
        
        Args:
            output_dir: Output directory
            base_filename: Base filename (without extension)
            
        Returns:
            Dictionary mapping format to filepath
        """
        from pathlib import Path
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        filepaths = {
            "json": str(output_path / f"{base_filename}.json"),
            "markdown": str(output_path / f"{base_filename}.md"),
            "html": str(output_path / f"{base_filename}.html")
        }
        
        self.export_json(filepaths["json"])
        self.export_markdown(filepaths["markdown"])
        self.export_html(filepaths["html"])
        
        logger.info(f"All reports exported to: {output_dir}")
        return filepaths
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics.
        
        Returns:
            Summary statistics dictionary
        """
        return self.summary_stats
    
    def get_executive_summary(self) -> str:
        """
        Get executive summary text.
        
        Returns:
            Executive summary string
        """
        return self.executive_summary
    
    def print_summary(self) -> None:
        """Print summary to console."""
        print("\n" + "=" * 70)
        print("RICO SECURITY ASSESSMENT SUMMARY")
        print("=" * 70)
        print(f"\nTarget: {self.target_url}")
        print(f"Scan Date: {self.scan_timestamp}")
        print(f"\nTotal Vulnerabilities: {self.summary_stats['total_vulnerabilities']}")
        print(f"Risk Score: {self.summary_stats['risk_score']:.1f}/100")
        print(f"Risk Level: {self.summary_stats['risk_level']}")
        print(f"Highest Severity: {self.summary_stats['highest_severity']}")
        
        print("\nSeverity Distribution:")
        for severity, count in self.summary_stats['severity_distribution'].items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        print(f"\nExecutive Summary:")
        print(f"{self.executive_summary}")
        print("\n" + "=" * 70 + "\n")


def create_report(vulnerabilities: List[Dict[str, Any]], 
                 target_url: str = None,
                 output_formats: List[str] = None,
                 output_dir: str = "reports",
                 base_filename: str = "report") -> ReportBuilder:
    """
    Convenience function to create and export reports.
    
    Args:
        vulnerabilities: List of detected vulnerabilities
        target_url: Target URL that was scanned
        output_formats: List of formats to export ('json', 'markdown', 'html', 'all')
        output_dir: Output directory
        base_filename: Base filename
        
    Returns:
        ReportBuilder instance
    """
    builder = ReportBuilder(vulnerabilities, target_url=target_url)
    
    if output_formats:
        if 'all' in output_formats:
            builder.export_all(output_dir, base_filename)
        else:
            from pathlib import Path
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            if 'json' in output_formats:
                builder.export_json(str(output_path / f"{base_filename}.json"))
            if 'markdown' in output_formats:
                builder.export_markdown(str(output_path / f"{base_filename}.md"))
            if 'html' in output_formats:
                builder.export_html(str(output_path / f"{base_filename}.html"))
    
    return builder
