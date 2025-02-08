# Cloud Security Auditor

A Python-based tool for auditing cloud security configurations in GCP environments. The tool scans cloud resources for security misconfigurations, generates detailed reports, and sends notifications through multiple channels.

## Features

- **Security Scanning**
  - Storage bucket access controls
  - IAM role configurations
  - Parallel scanning with configurable batch sizes
  - Rate limiting and retry mechanisms

- **Reporting**
  - Detailed findings with CIS benchmark mappings
  - Risk level categorization
  - CSV and JSON report formats
  - Executive summaries

- **Notifications**
  - Email notifications with HTML formatting
  - Slack notifications for critical findings
  - Rate-limited notification delivery
  - Customizable message templates

## Prerequisites

- Python 3.x
- GCP Service Account with appropriate permissions
- SMTP server (for email notifications)
- Slack webhook URL (for Slack notifications)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cloud-security-auditor.git
cd cloud-security-auditor
```

2. Install dependencies:
```bash
pip3 install -r requirements.txt
```

3. Set up environment variables:
```bash
# Copy the example .env file
cp .env.example .env

# Edit the .env file with your configuration
nano .env
```

## Configuration

The tool uses a YAML configuration file (`src/config/config.yaml`) with environment variable support:

```yaml
gcp:
  service_account_key_path: ${GCP_SERVICE_ACCOUNT_KEY_PATH}

logging:
  level: ${LOG_LEVEL:-INFO}
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: ${LOG_FILE:-app.log}
  max_size: ${LOG_MAX_SIZE:-10485760}  # 10MB
  backup_count: ${LOG_BACKUP_COUNT:-5}

notifications:
  smtp:
    enabled: ${SMTP_ENABLED:-false}
    sender_email: ${SMTP_SENDER_EMAIL}
    receiver_email: ${SMTP_RECEIVER_EMAIL}
    server: ${SMTP_SERVER}
    port: ${SMTP_PORT:-587}
    username: ${SMTP_USERNAME}
    password: ${SMTP_PASSWORD}
    
  slack:
    enabled: ${SLACK_ENABLED:-false}
    webhook_url: ${SLACK_WEBHOOK_URL}
    channel: ${SLACK_CHANNEL}

scanner:
  max_workers: ${SCANNER_MAX_WORKERS:-3}
  timeout: ${SCANNER_TIMEOUT:-30}
  batch_size: ${SCANNER_BATCH_SIZE:-100}
```

### Environment Variables

Required environment variables:
- `GCP_SERVICE_ACCOUNT_KEY_PATH`: Path to GCP service account key file
- `SMTP_SENDER_EMAIL`: Sender email address (if SMTP enabled)
- `SMTP_RECEIVER_EMAIL`: Receiver email address (if SMTP enabled)
- `SMTP_SERVER`: SMTP server hostname (if SMTP enabled)
- `SMTP_USERNAME`: SMTP username (if SMTP enabled)
- `SMTP_PASSWORD`: SMTP password (if SMTP enabled)
- `SLACK_WEBHOOK_URL`: Slack webhook URL (if Slack enabled)
- `SLACK_CHANNEL`: Slack channel name (if Slack enabled)

Optional environment variables with defaults:
- `LOG_LEVEL`: Logging level (default: INFO)
- `LOG_FILE`: Log file path (default: app.log)
- `LOG_MAX_SIZE`: Maximum log file size in bytes (default: 10MB)
- `LOG_BACKUP_COUNT`: Number of log file backups (default: 5)
- `SMTP_ENABLED`: Enable SMTP notifications (default: false)
- `SMTP_PORT`: SMTP server port (default: 587)
- `SLACK_ENABLED`: Enable Slack notifications (default: false)
- `SCANNER_MAX_WORKERS`: Maximum concurrent workers (default: 3)
- `SCANNER_TIMEOUT`: API request timeout in seconds (default: 30)
- `SCANNER_BATCH_SIZE`: Number of resources to process in each batch (default: 100)

## Usage

1. Run the script:
```bash
./run.sh
```

2. Check the logs:
```bash
tail -f logs/app.log
```

3. Review the reports in the `reports` directory.

## Project Structure

```
cloud-security-auditor/
├── src/
│   ├── config/
│   │   └── config.yaml
│   ├── modules/
│   │   ├── scanner.py
│   │   ├── reporter.py
│   │   └── notifier.py
│   ├── utils/
│   │   ├── config_manager.py
│   │   ├── logger.py
│   │   └── cis_benchmark_library.py
│   └── main.py
├── tests/
│   ├── test_scanner.py
│   ├── test_reporter.py
│   └── test_notifier.py
├── logs/
├── reports/
├── requirements.txt
└── README.md
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
