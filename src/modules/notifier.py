import os
import smtplib
import aiohttp
import asyncio
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional
# Optional imports for ticketing systems
JIRA = None
pysnow = None
from src.utils.logger import Logger
from src.utils.cis_benchmark_library import CIS_BENCHMARK_LIBRARY

class NotificationTemplate:
    """Templates for different notification formats."""
    
    @staticmethod
    def generate_email_subject(report: Dict[str, Any]) -> str:
        """Generate email subject based on findings."""
        total_findings = report["executive_summary"]["total_findings"]
        risk_levels = report["executive_summary"]["risk_levels"]
        
        if total_findings == 0:
            return "Security Audit Report - No Issues Found"
            
        critical = risk_levels.get("Critical", 0)
        high = risk_levels.get("High", 0)
        
        if critical > 0:
            return f"CRITICAL: Security Audit Report - {critical} Critical Issues Found"
        elif high > 0:
            return f"WARNING: Security Audit Report - {high} High Risk Issues Found"
        else:
            return f"Security Audit Report - {total_findings} Issues Found"

    @staticmethod
    def generate_email_body(report: Dict[str, Any]) -> str:
        """Generate detailed email body with findings."""
        total_findings = report["executive_summary"]["total_findings"]
        risk_levels = report["executive_summary"]["risk_levels"]
        findings = report["detailed_findings"]
        
        body = [
            "<html><body>",
            "<h2>Security Audit Report</h2>",
            f"<p>Total findings: {total_findings}</p>",
            "<h3>Risk Level Summary:</h3>",
            "<ul>"
        ]
        
        for level, count in risk_levels.items():
            if count > 0:
                body.append(f"<li>{level}: {count}</li>")
        
        body.append("</ul>")
        
        if findings:
            body.append("<h3>Critical and High Risk Findings:</h3>")
            body.append("<ul>")
            for finding in findings:
                if finding["risk_level"] in ["Critical", "High"]:
                    cis_mapping = CIS_BENCHMARK_LIBRARY[finding["cis_id"]]
                    body.append(f"""
                        <li>
                            <strong>{finding["description"]}</strong><br>
                            Risk Level: {finding["risk_level"]}<br>
                            Resource: {finding["resource_type"]} ({finding["resource_id"]})<br>
                            Remediation: {cis_mapping["remediation"]}
                        </li>
                    """)
            body.append("</ul>")
            
            body.append("<h3>Other Findings:</h3>")
            body.append("<ul>")
            for finding in findings:
                if finding["risk_level"] not in ["Critical", "High"]:
                    body.append(f"""
                        <li>
                            <strong>{finding["description"]}</strong><br>
                            Risk Level: {finding["risk_level"]}<br>
                            Resource: {finding["resource_type"]} ({finding["resource_id"]})
                        </li>
                    """)
            body.append("</ul>")
        
        body.append("</body></html>")
        return "\n".join(body)

    @staticmethod
    def generate_slack_message(report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Slack message with findings."""
        total_findings = report["executive_summary"]["total_findings"]
        risk_levels = report["executive_summary"]["risk_levels"]
        findings = report["detailed_findings"]
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Security Audit Report"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Total findings:* {total_findings}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Risk Level Summary:*\n" + "\n".join([
                        f"• {level}: {count}" for level, count in risk_levels.items() if count > 0
                    ])
                }
            }
        ]
        
        if findings:
            critical_high = [f for f in findings if f["risk_level"] in ["Critical", "High"]]
            if critical_high:
                blocks.append({
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "Critical and High Risk Findings"
                    }
                })
                
                for finding in critical_high:
                    cis_mapping = CIS_BENCHMARK_LIBRARY[finding["cis_id"]]
                    blocks.append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"""
*{finding["description"]}*
• Risk Level: {finding["risk_level"]}
• Resource: {finding["resource_type"]} ({finding["resource_id"]})
• Remediation: {cis_mapping["remediation"]}
"""
                        }
                    })
        
        return {
            "blocks": blocks
        }

    @staticmethod
    def generate_jira_issue(finding: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JIRA issue fields for a finding."""
        benchmark = next((b for b in finding.get('benchmarks', []) if b['id'] == finding['cis_id']), None)
        
        description = f"""
h2. Security Finding Details
* Description: {finding['description']}
* Risk Level: {finding['risk_level']}
* Resource: {finding['resource_type']} ({finding['resource_id']})
* CIS Benchmark: {finding['cis_id']}

h2. Remediation Steps
{chr(10).join(['* ' + step for step in finding.get('remediation_steps', [])])}

h2. Technical Details
{str(finding.get('details', 'No additional details'))}
"""

        return {
            'project': {'key': config['project_key']},
            'summary': f"[Security] {finding['description']}",
            'description': description,
            'issuetype': {'name': config['issue_type']},
            config['priority_field']: {'name': config['priority_mapping'].get(finding['risk_level'], 'Medium')},
            'labels': config['labels'].split(',') if isinstance(config['labels'], str) else config['labels']
        }

    @staticmethod
    def generate_servicenow_ticket(finding: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ServiceNow ticket fields for a finding."""
        description = f"""
Security Finding Details
-----------------------
Description: {finding['description']}
Risk Level: {finding['risk_level']}
Resource: {finding['resource_type']} ({finding['resource_id']})
CIS Benchmark: {finding['cis_id']}

Remediation Steps
----------------
{chr(10).join(['- ' + step for step in finding.get('remediation_steps', [])])}

Technical Details
---------------
{str(finding.get('details', 'No additional details'))}
"""

        return {
            'short_description': f"[Security] {finding['description']}",
            'description': description,
            'assignment_group': config['assignment_group'],
            'category': config['category'],
            'urgency': config['urgency_mapping'].get(finding['risk_level'], 3),
            'impact': config['urgency_mapping'].get(finding['risk_level'], 3)
        }

class Notifier:
    def __init__(self, config_manager: Any):
        """Initialize the notifier with configuration."""
        self.config = config_manager
        self.logger = None  # Will be initialized when needed

    def _get_logger(self):
        """Get or initialize logger."""
        if self.logger is None:
            self.logger = Logger.get_logger(__name__)
        return self.logger

    async def _send_email(self, subject: str, body: str) -> None:
        """Send email notification."""
        logger = self._get_logger()
        try:
            smtp_config = self.config['notifications']['smtp']
            if not smtp_config['enabled']:
                logger.info("SMTP notifications are disabled")
                return
                
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = smtp_config['sender_email']
            msg['To'] = smtp_config['receiver_email']
            msg.attach(MIMEText(body, 'html'))
            
            with smtplib.SMTP(smtp_config['server'], smtp_config['port']) as server:
                server.starttls()
                server.login(smtp_config['username'], smtp_config['password'])
                server.send_message(msg)
                
            logger.info("Email notification sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {str(e)}",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            raise

    async def _send_slack(self, message: Dict[str, Any]) -> None:
        """Send Slack notification."""
        logger = self._get_logger()
        try:
            slack_config = self.config['notifications']['slack']
            if not slack_config['enabled']:
                logger.info("Slack notifications are disabled")
                return
                
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    slack_config['webhook_url'],
                    json=message
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"Slack API error: {error_text}")
                        
            logger.info("Slack notification sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {str(e)}",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            raise

    async def _create_jira_issues(self, findings: List[Dict[str, Any]]) -> None:
        """Create JIRA issues for findings."""
        logger = self._get_logger()
        try:
            jira_config = self.config['notifications']['jira']
            if not jira_config['enabled']:
                logger.info("JIRA integration is disabled")
                return

            # Import JIRA only when needed
            try:
                from jira import JIRA
            except ImportError:
                logger.warning("JIRA package not installed. Install with: pip install jira")
                return

            jira = JIRA(
                server=jira_config['url'],
                basic_auth=(jira_config['username'], jira_config['api_token'])
            )

            for finding in findings:
                issue_fields = NotificationTemplate.generate_jira_issue(finding, jira_config)
                issue = jira.create_issue(fields=issue_fields)
                logger.info(f"Created JIRA issue: {issue.key}")

            logger.info("JIRA issues created successfully")

        except ImportError:
            logger.warning("JIRA integration skipped - package not installed")
        except Exception as e:
            logger.error(f"Failed to create JIRA issues: {str(e)}",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            raise

    async def _create_servicenow_tickets(self, findings: List[Dict[str, Any]]) -> None:
        """Create ServiceNow tickets for findings."""
        logger = self._get_logger()
        try:
            snow_config = self.config['notifications']['servicenow']
            if not snow_config['enabled']:
                logger.info("ServiceNow integration is disabled")
                return

            # Import pysnow only when needed
            try:
                import pysnow
            except ImportError:
                logger.warning("pysnow package not installed. Install with: pip install pysnow")
                return

            client = pysnow.Client(
                instance=snow_config['instance_url'],
                user=snow_config['username'],
                password=snow_config['password']
            )

            incident = client.resource(api_path=f"/table/{snow_config['table']}")
            
            for finding in findings:
                ticket_data = NotificationTemplate.generate_servicenow_ticket(finding, snow_config)
                result = incident.create(payload=ticket_data)
                logger.info(f"Created ServiceNow ticket: {result['number']}")

            logger.info("ServiceNow tickets created successfully")

        except ImportError:
            logger.warning("ServiceNow integration skipped - package not installed")
        except Exception as e:
            logger.error(f"Failed to create ServiceNow tickets: {str(e)}",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            raise

    async def send_notifications(self, report: Dict[str, Any]) -> None:
        """Send notifications through configured channels."""
        logger = self._get_logger()
        try:
            # Generate notification content
            email_subject = NotificationTemplate.generate_email_subject(report)
            email_body = NotificationTemplate.generate_email_body(report)
            slack_message = NotificationTemplate.generate_slack_message(report)
            
            # Send notifications concurrently
            tasks = []
            
            if self.config['notifications']['smtp']['enabled']:
                tasks.append(self._send_email(email_subject, email_body))
                
            if self.config['notifications']['slack']['enabled']:
                tasks.append(self._send_slack(slack_message))

            if self.config['notifications']['jira']['enabled']:
                tasks.append(self._create_jira_issues(report['detailed_findings']))

            if self.config['notifications']['servicenow']['enabled']:
                tasks.append(self._create_servicenow_tickets(report['detailed_findings']))
                
            if tasks:
                await asyncio.gather(*tasks)
                logger.info("All notifications sent successfully")
            else:
                logger.info("No notification channels enabled")
                
        except Exception as e:
            logger.error("Error sending notifications",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            raise
