import os
import csv
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
from src.utils.logger import Logger
from src.utils.cis_benchmark_library import CIS_BENCHMARK_LIBRARY
from src.modules.scanner import Finding

class Reporter:
    def __init__(self, config_manager: Any):
        """Initialize the reporter with configuration."""
        self.config = config_manager
        self.logger = None  # Will be initialized when needed
        self.base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    def _get_logger(self):
        """Get or initialize logger."""
        if self.logger is None:
            self.logger = Logger.get_logger(__name__)
        return self.logger

    def _ensure_output_dir(self, output_dir: str) -> None:
        """Ensure output directory exists."""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def _print_table(self, findings: List[Dict[str, Any]]) -> None:
        """Print findings in a table format."""
        if not findings:
            print("\nNo security findings detected.")
            return

        # Define column widths
        widths = {
            "Resource": 30,
            "Risk Level": 12,
            "Finding": 50,
            "CIS ID": 8
        }

        # Print header
        header = "│ {:<{w[Resource]}} │ {:<{w[Risk Level]}} │ {:<{w[Finding]}} │ {:<{w[CIS ID]}} │".format(
            "Resource", "Risk Level", "Finding", "CIS ID", w=widths
        )
        separator = "├" + "─" * (widths["Resource"] + 2) + "┼" + "─" * (widths["Risk Level"] + 2) + "┼" + "─" * (widths["Finding"] + 2) + "┼" + "─" * (widths["CIS ID"] + 2) + "┤"
        top_border = "┌" + "─" * (widths["Resource"] + 2) + "┬" + "─" * (widths["Risk Level"] + 2) + "┬" + "─" * (widths["Finding"] + 2) + "┬" + "─" * (widths["CIS ID"] + 2) + "┐"
        bottom_border = "└" + "─" * (widths["Resource"] + 2) + "┴" + "─" * (widths["Risk Level"] + 2) + "┴" + "─" * (widths["Finding"] + 2) + "┴" + "─" * (widths["CIS ID"] + 2) + "┘"

        print("\nSecurity Findings:")
        print(top_border)
        print(header)
        print(separator)

        # Print findings
        for finding in findings:
            resource = f"{finding['resource_type']}: {finding['resource_id']}"
            if len(resource) > widths["Resource"]:
                resource = resource[:widths["Resource"]-3] + "..."

            description = finding["description"]
            if len(description) > widths["Finding"]:
                description = description[:widths["Finding"]-3] + "..."

            row = "│ {:<{w[Resource]}} │ {:<{w[Risk Level]}} │ {:<{w[Finding]}} │ {:<{w[CIS ID]}} │".format(
                resource,
                finding["risk_level"],
                description,
                finding["cis_id"],
                w=widths
            )
            print(row)

        print(bottom_border)
        print(f"\nTotal findings: {len(findings)}")
        print(f"Report saved to: {self.base_dir}/reports/")

    def _save_csv_report(self, findings: List[Dict[str, Any]], timestamp: str) -> str:
        """Save report in CSV format."""
        logger = self._get_logger()
        try:
            output_dir = os.path.join(self.base_dir, 'reports')
            self._ensure_output_dir(output_dir)
            filepath = os.path.join(output_dir, f"compliance_report_{timestamp}.csv")
            
            headers = [
                "Finding Description", "CIS Control ID", "Profile Applicability",
                "Risk Level", "Resource ID", "Resource Type", "Remediation Steps",
                "Impact", "Details"
            ]
            
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                
                for finding in findings:
                    cis_mapping = CIS_BENCHMARK_LIBRARY[finding["cis_id"]]
                    writer.writerow({
                        "Finding Description": finding["description"],
                        "CIS Control ID": cis_mapping["id"],
                        "Profile Applicability": cis_mapping["profile_applicability"],
                        "Risk Level": finding["risk_level"],
                        "Resource ID": finding["resource_id"],
                        "Resource Type": finding["resource_type"],
                        "Remediation Steps": cis_mapping["remediation"],
                        "Impact": cis_mapping["impact"],
                        "Details": str(finding["details"]) if finding["details"] else ""
                    })
            
            logger.info(f"CSV report saved successfully to {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Failed to save CSV report: {str(e)}")
            raise

    def generate_report(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate a complete security audit report."""
        logger = self._get_logger()
        try:
            logger.info("Generating security audit report")
            
            # Create timestamp for the report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create detailed findings
            detailed_findings = []
            compliance_summary = []
            
            for finding in findings:
                detailed_finding = {
                    "description": finding.description,
                    "cis_id": finding.cis_id,
                    "risk_level": finding.risk_level,
                    "status": finding.status,
                    "resource_id": finding.resource_id,
                    "resource_type": finding.resource_type,
                    "details": finding.details
                }
                detailed_findings.append(detailed_finding)
                
                # Add to compliance summary
                compliance_summary.append({
                    "cis_id": finding.cis_id,
                    "title": CIS_BENCHMARK_LIBRARY[finding.cis_id]["title"],
                    "compliant": finding.status == "Compliant",
                    "risk_level": finding.risk_level,
                    "remediation_status": "Remediated" if finding.status == "Compliant" else "Pending"
                })
            
            # Print findings table
            self._print_table(detailed_findings)
            
            # Create report object
            report = {
                "timestamp": timestamp,
                "project_id": self.config['gcp']['project_id'],
                "executive_summary": {
                    "total_findings": len(findings),
                    "risk_levels": {
                        "Critical": len([f for f in findings if f.risk_level == "Critical"]),
                        "High": len([f for f in findings if f.risk_level == "High"]),
                        "Medium": len([f for f in findings if f.risk_level == "Medium"]),
                        "Low": len([f for f in findings if f.risk_level == "Low"])
                    }
                },
                "detailed_findings": detailed_findings,
                "compliance_summary": compliance_summary
            }
            
            # Save CSV report
            csv_path = self._save_csv_report(detailed_findings, timestamp)
            report["csv_report_path"] = csv_path
            
            logger.info("Report generation completed successfully")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate report: {str(e)}")
            raise
