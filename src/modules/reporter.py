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

        # Define column widths (total: 120 chars)
        widths = {
            "Resource": 30,
            "Risk Level": 15,
            "Finding": 65,
            "CIS ID": 10
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
        # Pre-compute data for better performance
        non_compliant_ids = {f.cis_id for f in findings}
        total_benchmarks = len(benchmarks)
        compliant_count = total_benchmarks - len(non_compliant_ids)
        compliance_score = (compliant_count / total_benchmarks) * 100 if total_benchmarks > 0 else 0
        score_color = "\033[92m" if compliance_score >= 80 else "\033[93m" if compliance_score >= 50 else "\033[91m"

        # Pre-format strings for better performance
        widths = {"CIS ID": 10, "Title": 65, "Level": 15, "Status": 30}
        borders = {
            "top": "┌" + "─" * (widths["CIS ID"] + 2) + "┬" + "─" * (widths["Title"] + 2) + "┬" + "─" * (widths["Level"] + 2) + "┬" + "─" * (widths["Status"] + 2) + "┐",
            "sep": "├" + "─" * (widths["CIS ID"] + 2) + "┼" + "─" * (widths["Title"] + 2) + "┼" + "─" * (widths["Level"] + 2) + "┼" + "─" * (widths["Status"] + 2) + "┤",
            "bottom": "└" + "─" * (widths["CIS ID"] + 2) + "┴" + "─" * (widths["Title"] + 2) + "┴" + "─" * (widths["Level"] + 2) + "┴" + "─" * (widths["Status"] + 2) + "┘"
        }

        # Pre-format header
        header = "│ {:<{w[CIS ID]}} │ {:<{w[Title]}} │ {:<{w[Level]}} │ {:<{w[Status]}} │".format(
            "CIS ID", "Title", "Level", "Status", w=widths
        )

        # Pre-process benchmarks for display
        rows = []
        for benchmark in benchmarks:
            title = benchmark["title"][:widths["Title"]-3] + "..." if len(benchmark["title"]) > widths["Title"] else benchmark["title"]
            status = "Non-Compliant" if benchmark["id"] in non_compliant_ids else "Compliant"
            status_color = "\033[91m" if status == "Non-Compliant" else "\033[92m"
            rows.append("│ {:<{w[CIS ID]}} │ {:<{w[Title]}} │ {:<{w[Level]}} │ {}{:<{w[Status]}}\033[0m │".format(
                benchmark["id"], title, benchmark["profile_applicability"],
                status_color, status, w=widths
            ))

        # Print all at once for better performance
        print("\nCIS Benchmark Compliance Status:")
        print(borders["top"])
        print(header)
        print(borders["sep"])
        print("\n".join(rows))
        print(borders["bottom"])
        
        print("\nCompliance Summary:")
        print(f"Score: {score_color}{compliance_score:.1f}%\033[0m")
        print(f"Status: {compliant_count} compliant, {len(non_compliant_ids)} non-compliant out of {total_benchmarks} benchmarks")
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
            if detailed_findings:
                self._print_findings_table(detailed_findings)
            if self.benchmarks['cis_benchmarks']:
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
