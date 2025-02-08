#!/usr/bin/env python3
import os
import sys
import asyncio
import traceback
from typing import Any, Dict, Optional
from pathlib import Path
from dotenv import load_dotenv
from src.utils.logger import Logger
from src.modules.scanner import Scanner
from src.modules.reporter import Reporter
from src.modules.notifier import Notifier
from src.utils.config_manager import ConfigManager
from google.oauth2 import service_account

class CloudSecurityAuditor:
    def __init__(self, config_path: str):
        """Initialize the Cloud Security Auditor."""
        print("Initializing with config path:", config_path)
        self.config_manager = ConfigManager(config_path)
        self.logger = None
        self.scanner = None
        self.reporter = None
        self.notifier = None

    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        print("Setting up logging...")
        try:
            Logger.setup(self.config_manager)
            self.logger = Logger.get_logger(__name__)
            self.logger.info("Logging initialized successfully")
        except Exception as e:
            print(f"Error setting up logging: {str(e)}")
            raise

    def _setup_credentials(self) -> Any:
        """Set up GCP credentials."""
        print("Setting up GCP credentials...")
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
            print("\nStarting security scan...")
            
            # Run security scan
            findings = await self.scanner.scan()
            self.logger.info(f"Scanning completed. Found {len(findings)} findings.")
            print(f"Scanning completed. Found {len(findings)} findings.")
            
            # Generate report
            print("\nGenerating report...")
            report = self.reporter.generate_report(findings)
            self.logger.info("Report generated successfully")
            print("Report generated successfully")
            
            # Send notifications
            print("\nSending notifications...")
            await self.notifier.send_notifications(report)
            self.logger.info("Notifications sent successfully")
            print("Notifications sent successfully")
            
            self.logger.info("Cloud Security Auditor completed successfully")
            print("\nCloud Security Auditor completed successfully")
            
        except Exception as e:
            self.logger.error("Error in main execution",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            print(f"\nError in main execution: {str(e)}")
            print("Stack trace:")
            print(traceback.format_exc())
            raise

def main():
    """Main entry point."""
    print("Starting Cloud Security Auditor...")
    print("Starting main function...")
    
    try:
        # Load environment variables from .env file
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
        if os.path.exists(env_path):
            load_dotenv(env_path)
            print("Loaded environment variables from .env")
        # Get config path
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            os.getenv('CONFIG_PATH', 'src/config/config.yaml')
        )
        print("Using config path:", config_path)
        
        # Initialize auditor
        auditor = CloudSecurityAuditor(config_path)
        
        # Setup components
        auditor._setup_logging()
        credentials = auditor._setup_credentials()
        
        print("Initializing components...")
        auditor.scanner = Scanner(auditor.config_manager, credentials)
        auditor.reporter = Reporter(auditor.config_manager)
        auditor.notifier = Notifier(auditor.config_manager)
        print("Components initialized")
        
        # Run auditor
        asyncio.run(auditor.run())
        
    except Exception as e:
        print(f"Error in initialization: {str(e)}")
        print("Stack trace:")
        print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
