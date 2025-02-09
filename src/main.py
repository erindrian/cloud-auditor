#!/usr/bin/env python3
import os
import sys
import asyncio
import traceback
from typing import Any, Dict, Optional
from src.utils.logger import Logger
from src.modules.scanner import Scanner
from src.modules.reporter import Reporter
from src.modules.notifier import Notifier
from src.utils.config_manager import ConfigManager
from google.oauth2 import service_account

class CloudSecurityAuditor:
    def __init__(self, config_path: str):
        """Initialize the Cloud Security Auditor."""
        self.config_manager = ConfigManager(config_path)
        self.logger = None
        self.scanner = None
        self.reporter = None
        self.notifier = None

    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        try:
            Logger.setup(self.config_manager)
            self.logger = Logger.get_logger(__name__)
            self.logger.info("Logging initialized successfully")
        except Exception as e:
            raise RuntimeError(f"Error setting up logging: {str(e)}")

    def _setup_credentials(self) -> Any:
        """Set up GCP credentials."""
        try:
            credentials_path = self.config_manager['gcp']['service_account_key_path']
            credentials = service_account.Credentials.from_service_account_file(
                credentials_path,
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
            self.logger.info("GCP credentials initialized successfully")
            return credentials
        except Exception as e:
            self.logger.error(f"Error setting up GCP credentials: {str(e)}")
            raise

    async def run(self) -> None:
        """Run the Cloud Security Auditor."""
        try:
            self.logger.info("Starting Cloud Security Auditor")
            
            # Run security scan
            findings = await self.scanner.scan()
            self.logger.info(f"Scanning completed. Found {len(findings)} findings.")
            
            # Generate report
            report = self.reporter.generate_report(findings)
            self.logger.info("Report generated successfully")
            
            # Send notifications
            await self.notifier.send_notifications(report)
            self.logger.info("Notifications sent successfully")
            
            self.logger.info("Cloud Security Auditor completed successfully")
            
        except Exception as e:
            self.logger.error("Error in main execution",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            raise

def main():
    """Main entry point."""
    try:
        # Get config path
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            os.getenv('CONFIG_PATH', 'src/config/config.yaml')
        )
        
        # Initialize auditor
        auditor = CloudSecurityAuditor(config_path)
        
        # Setup components
        auditor._setup_logging()
        credentials = auditor._setup_credentials()
        
        # Initialize components
        auditor.scanner = Scanner(auditor.config_manager, credentials)
        auditor.reporter = Reporter(auditor.config_manager)
        auditor.notifier = Notifier(auditor.config_manager)
        
        # Run auditor
        asyncio.run(auditor.run())
        
    except Exception as e:
        sys.exit(1)

if __name__ == "__main__":
    main()
