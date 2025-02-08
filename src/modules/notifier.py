import os
import smtplib
import aiohttp
import asyncio
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional
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
                
            if tasks:
                await asyncio.gather(*tasks)
                logger.info("All notifications sent successfully")
            else:
                logger.info("No notification channels enabled")
                
        except Exception as e:
            logger.error("Error sending notifications",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            raise
