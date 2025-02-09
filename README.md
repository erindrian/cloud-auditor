# Cloud Auditor

A comprehensive security auditing tool for Google Cloud Platform resources.

## Author

**Ghariza Erindrian**  
Cloud Security Engineer  
[GitHub](https://github.com/gharizaerindrian)

## Features

- Automated security scanning of GCP resources
- CIS Benchmark compliance checks
- Detailed security findings reports
- Multiple notification channels (Email, Slack)
- Integration with ticketing systems (JIRA, ServiceNow)
- Color-coded compliance scoring
- Progress tracking with visual indicators

## Prerequisites

- Docker installed on your system
- GCP Service Account with required permissions
- Environment variables configured in `.env` file

## Quick Start with Docker

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cloud-auditor.git
cd cloud-auditor
```

2. Create necessary directories:
```bash
mkdir -p credentials logs reports
```

3. Set up credentials:
   - Place your GCP service account key in `credentials/` directory
   - Create `.env` file with required environment variables (see below)

4. Build the Docker image:
```bash
docker build -t cloud-auditor .
```

5. Run the container:
```bash
docker run -v $(pwd)/credentials:/app/credentials \
          -v $(pwd)/logs:/app/logs \
          -v $(pwd)/reports:/app/reports \
          --env-file .env \
          cloud-auditor
```

## Container Management

Common Docker commands for managing the application:

```bash
# View running containers
docker ps

# View container logs
docker logs <container_id>

# Stop the container
docker stop <container_id>

# Remove the container
docker rm <container_id>

# Remove the image
docker rmi cloud-auditor

# Rebuild and run (useful during development)
docker build -t cloud-auditor . && docker run -v $(pwd)/credentials:/app/credentials -v $(pwd)/logs:/app/logs -v $(pwd)/reports:/app/reports --env-file .env cloud-auditor
```

## Environment Variables

Create an `.env` file with the following variables:

```bash
# Required: GCP Configuration
GCP_SERVICE_ACCOUNT_KEY_PATH=credentials/your-key.json
GCP_PROJECT_ID=your-project-id

# Optional: Email Notifications
SMTP_ENABLED=true
SMTP_SENDER_EMAIL=your-email@example.com
SMTP_RECEIVER_EMAIL=recipient@example.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password

# Optional: Slack Notifications
SLACK_ENABLED=true
SLACK_WEBHOOK_URL=your-webhook-url
SLACK_CHANNEL=your-channel

# Optional: JIRA Integration
JIRA_ENABLED=true
JIRA_URL=your-jira-url
JIRA_USERNAME=your-username
JIRA_API_TOKEN=your-token
JIRA_PROJECT_KEY=your-project

# Optional: ServiceNow Integration
SERVICENOW_ENABLED=true
SERVICENOW_INSTANCE_URL=your-instance-url
SERVICENOW_USERNAME=your-username
SERVICENOW_PASSWORD=your-password
```

## Directory Structure

```
cloud-auditor/
├── credentials/     # GCP service account keys
├── logs/           # Application logs
├── reports/        # Generated security reports
├── src/           
│   ├── config/     # Configuration files
│   ├── modules/    # Core modules
│   └── utils/      # Utility functions
├── .env            # Environment variables
├── Dockerfile      # Docker configuration
└── README.md       # Documentation
```

## Output

The application generates:
- Security findings in tabular format
- Compliance status for CIS benchmarks
- Color-coded compliance score
- Detailed CSV reports in the `reports` directory
- Log files in the `logs` directory

## Troubleshooting

1. **Permission Issues**:
   - Ensure proper permissions on mounted volumes
   - Verify GCP service account has required permissions

2. **Container Access**:
   - Use `docker exec -it <container_id> /bin/bash` to access the container
   - Check logs with `docker logs <container_id>`

3. **Volume Mounts**:
   - Ensure directories exist before running container
   - Check directory permissions

4. **Environment Variables**:
   - Verify `.env` file is properly formatted
   - Check for missing required variables

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
