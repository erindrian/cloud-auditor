import os
import csv
import yaml
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
from src.utils.logger import Logger
from src.modules.scanner import Finding

class Reporter:
    def __init__(self, config_manager: Any):
        """Initialize the reporter with configuration."""
        self.config = config_manager
        self.logger = None  # Will be initialized when needed
        self.base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        # Load CIS benchmarks
        self.benchmarks = self._load_cis_benchmarks()

    def _load_cis_benchmarks(self) -> Dict[str, Any]:
        """Load CIS benchmarks from YAML file."""
        try:
            benchmarks_file = os.path.join(self.base_dir, 'src/config/cis_benchmarks.yaml')
            with open(benchmarks_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading CIS benchmarks: {str(e)}")
            raise

    def _get_logger(self):
        """Get or initialize logger."""
        if self.logger is None:
            self.logger = Logger.get_logger(__name__)
        return self.logger

    def _ensure_output_dir(self, output_dir: str) -> None:
        """Ensure output directory exists."""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def _print_findings_table(self, findings: List[Dict[str, Any]]) -> None:
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

    def _print_compliance_table(self, benchmarks: List[Dict[str, Any]], findings: List[Finding]) -> None:
        """Print CIS benchmark compliance status table."""
        # Define column widths
        widths = {
            "CIS ID": 8,
            "Title": 50,
            "Level": 10,
            "Status": 12
        }

        # Print header
        header = "│ {:<{w[CIS ID]}} │ {:<{w[Title]}} │ {:<{w[Level]}} │ {:<{w[Status]}} │".format(
            "CIS ID", "Title", "Level", "Status", w=widths
        )
        separator = "├" + "─" * (widths["CIS ID"] + 2) + "┼" + "─" * (widths["Title"] + 2) + "┼" + "─" * (widths["Level"] + 2) + "┼" + "─" * (widths["Status"] + 2) + "┤"
        top_border = "┌" + "─" * (widths["CIS ID"] + 2) + "┬" + "─" * (widths["Title"] + 2) + "┬" + "─" * (widths["Level"] + 2) + "┬" + "─" * (widths["Status"] + 2) + "┐"
        bottom_border = "└" + "─" * (widths["CIS ID"] + 2) + "┴" + "─" * (widths["Title"] + 2) + "┴" + "─" * (widths["Level"] + 2) + "┴" + "─" * (widths["Status"] + 2) + "┘"

        print("\nCIS Benchmark Compliance Status:")
        print(top_border)
        print(header)
        print(separator)

        # Get list of non-compliant CIS IDs
        non_compliant_ids = {f.cis_id for f in findings}

        # Print status for each benchmark
        for benchmark in benchmarks:
            title = benchmark["title"]
            if len(title) > widths["Title"]:
                title = title[:widths["Title"]-3] + "..."

            status = "Non-Compliant" if benchmark["id"] in non_compliant_ids else "Compliant"
            status_color = "\033[91m" if status == "Non-Compliant" else "\033[92m"  # Red for non-compliant, green for compliant

            row = "│ {:<{w[CIS ID]}} │ {:<{w[Title]}} │ {:<{w[Level]}} │ {}{:<{w[Status]}}\033[0m │".format(
                benchmark["id"],
                title,
                benchmark["profile_applicability"],
                status_color,
                status,
                w=widths
            )
            print(row)

        print(bottom_border)
        print(f"\nReport saved to: {self.base_dir}/reports/")

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
                "Details"
            ]
            
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                
                for finding in findings:
                    benchmark = next((b for b in self.benchmarks['cis_benchmarks'] if b['id'] == finding['cis_id']), None)
                    if benchmark:
                        writer.writerow({
                            "Finding Description": finding["description"],
                            "CIS Control ID": benchmark["id"],
                            "Profile Applicability": benchmark["profile_applicability"],
                            "Risk Level": finding["risk_level"],
                            "Resource ID": finding["resource_id"],
                            "Resource Type": finding["resource_type"],
                            "Remediation Steps": "\n".join(benchmark["remediation"]["steps"]),
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
                benchmark = next((b for b in self.benchmarks['cis_benchmarks'] if b['id'] == finding.cis_id), None)
                if benchmark:
                    compliance_summary.append({
                        "cis_id": finding.cis_id,
                        "title": benchmark['title'],
                        "compliant": finding.status == "Compliant",
                        "risk_level": finding.risk_level,
                        "remediation_status": "Remediated" if finding.status == "Compliant" else "Pending"
                    })
            
            # Print findings and compliance tables
            self._print_findings_table(detailed_findings)
            self._print_compliance_table(self.benchmarks['cis_benchmarks'], findings)
            
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
