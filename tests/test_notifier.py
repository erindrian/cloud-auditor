import pytest
from unittest.mock import Mock, patch, mock_open, MagicMock
from src.modules.notifier import Notifier

@pytest.fixture
def mock_config():
    return {
        "notifications": {
            "smtp": {
                "enabled": True,
                "server": "smtp.test.com",
                "port": 587,
                "username": "test@example.com",
                "password": "password123",
                "sender_email": "sender@example.com",
                "receiver_email": "receiver@example.com"
            },
            "slack": {
                "enabled": True,
                "webhook_url": "https://hooks.slack.com/test",
                "channel": "#security"
            }
        }
    }

@pytest.fixture
def mock_report():
    return {
        "executive_summary": {
            "total_findings": 2,
            "risk_levels": {
                "Critical": 1,
                "High": 1,
                "Medium": 0,
                "Low": 0
            }
        },
        "detailed_findings": [
            {
                "finding_description": "Critical vulnerability found",
                "risk_level": "Critical",
                "cis_mapping": {"id": "1.1"},
                "impact": "High impact",
                "remediation_steps": "Fix immediately"
            },
            {
                "finding_description": "High risk issue detected",
                "risk_level": "High",
                "cis_mapping": {"id": "1.2"},
                "impact": "Medium impact",
                "remediation_steps": "Fix soon"
            }
        ]
    }

class TestNotifier:
    def test_validate_config_missing_notifications(self, mock_config):
        del mock_config["notifications"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required configuration field: notifications" in str(excinfo.value)

    def test_validate_config_missing_slack(self, mock_config):
        del mock_config["notifications"]["slack"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required notifications configuration field: slack" in str(excinfo.value)

    def test_validate_config_missing_smtp(self, mock_config):
        del mock_config["notifications"]["smtp"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required notifications configuration field: smtp" in str(excinfo.value)

    def test_validate_config_missing_slack_enabled(self, mock_config):
        del mock_config["notifications"]["slack"]["enabled"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required Slack configuration field: enabled" in str(excinfo.value)

    def test_validate_config_missing_slack_webhook_url(self, mock_config):
        del mock_config["notifications"]["slack"]["webhook_url"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required Slack configuration field: webhook_url" in str(excinfo.value)

    def test_validate_config_missing_slack_channel(self, mock_config):
        del mock_config["notifications"]["slack"]["channel"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required Slack configuration field: channel" in str(excinfo.value)

    def test_validate_config_missing_smtp_enabled(self, mock_config):
        del mock_config["notifications"]["smtp"]["enabled"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required SMTP configuration field: enabled" in str(excinfo.value)

    def test_validate_config_missing_smtp_sender_email(self, mock_config):
        del mock_config["notifications"]["smtp"]["sender_email"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required SMTP configuration field: sender_email" in str(excinfo.value)

    def test_validate_config_missing_smtp_receiver_email(self, mock_config):
        del mock_config["notifications"]["smtp"]["receiver_email"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required SMTP configuration field: receiver_email" in str(excinfo.value)

    def test_validate_config_missing_smtp_server(self, mock_config):
        del mock_config["notifications"]["smtp"]["server"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required SMTP configuration field: server" in str(excinfo.value)

    def test_validate_config_missing_smtp_port(self, mock_config):
        del mock_config["notifications"]["smtp"]["port"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required SMTP configuration field: port" in str(excinfo.value)

    def test_validate_config_missing_smtp_username(self, mock_config):
        del mock_config["notifications"]["smtp"]["username"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required SMTP configuration field: username" in str(excinfo.value)

    def test_validate_config_missing_smtp_password(self, mock_config):
        del mock_config["notifications"]["smtp"]["password"]
        notifier = Notifier(mock_config)
        with pytest.raises(ValueError) as excinfo:
            notifier.validate_config()
        assert "Missing required SMTP configuration field: password" in str(excinfo.value)

    def test_slack_notification_success(self, mock_config, mock_report):
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            
            notifier = Notifier(mock_config)
            notifier.send_slack_notification("Test message")
            
            mock_post.assert_called_once()
            assert mock_post.call_args[1]["headers"]["Content-Type"] == "application/json"
            assert mock_post.call_args[1]["timeout"] == 10

    def test_slack_notification_disabled(self, mock_config, mock_report):
        mock_config["notifications"]["slack"]["enabled"] = False
        
        with patch('requests.post') as mock_post:
            notifier = Notifier(mock_config)
            notifier.send_slack_notification("Test message")
            
            mock_post.assert_not_called()

    def test_slack_notification_failure(self, mock_config):
        with patch('requests.post') as mock_post:
            mock_post.side_effect = Exception("Connection error")
            
            notifier = Notifier(mock_config)
            with pytest.raises(Exception):
                notifier.send_slack_notification("Test message")

    def test_email_notification_success(self, mock_config, mock_report):
        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp_instance = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_smtp_instance
            
            notifier = Notifier(mock_config)
            notifier.send_email_notifications(mock_report)
            
            mock_smtp_instance.starttls.assert_called_once()
            mock_smtp_instance.login.assert_called_once_with(
                mock_config["notifications"]["smtp"]["username"],
                mock_config["notifications"]["smtp"]["password"]
            )
            mock_smtp_instance.send_message.assert_called_once()

    def test_email_notification_disabled(self, mock_config, mock_report):
        mock_config["notifications"]["smtp"]["enabled"] = False
        
        with patch('smtplib.SMTP') as mock_smtp:
            notifier = Notifier(mock_config)
            notifier.send_email_notifications(mock_report)
            
            mock_smtp.assert_not_called()

    def test_email_notification_with_attachment(self, mock_config, mock_report):
        mock_file_content = b"test,data\n1,2\n"
        
        with patch('smtplib.SMTP') as mock_smtp, \
             patch('builtins.open', mock_open(read_data=mock_file_content)), \
             patch('os.path.exists') as mock_exists:
            
            mock_exists.return_value = True
            mock_smtp_instance = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_smtp_instance
            
            notifier = Notifier(mock_config)
            notifier.send_email_notifications(mock_report)
            
            # Verify email was sent with attachment
            call_args = mock_smtp_instance.send_message.call_args[0][0]
            assert len(call_args.get_payload()) == 2  # HTML content + CSV attachment
            assert call_args.get_payload()[1].get_content_type() == "application/csv"
            assert call_args.get_payload()[1].get_payload(decode=True) == mock_file_content

    def test_email_html_content(self, mock_config, mock_report):
        notifier = Notifier(mock_config)
        html_content = notifier._generate_email_html(mock_report)
        
        # Verify HTML content includes key information
        assert "Security Audit Report" in html_content
        assert "Total Findings: " in html_content
        assert "Critical: 1" in html_content
        assert "High: 1" in html_content
        assert "Critical vulnerability found" in html_content
        assert "High risk issue detected" in html_content

    def test_send_notifications_integration(self, mock_config, mock_report):
        with patch('smtplib.SMTP') as mock_smtp, \
             patch('requests.post') as mock_post:
            
            mock_smtp_instance = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_smtp_instance
            
            mock_response = Mock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            
            notifier = Notifier(mock_config)
            notifier.send_notifications(mock_report)
            
            # Verify both email and Slack notifications were sent
            mock_smtp_instance.send_message.assert_called_once()
            mock_post.assert_called_once()

    def test_error_handling_and_retries(self, mock_config):
        with patch('requests.post') as mock_post:
            # Simulate two failures followed by a success
            mock_post.side_effect = [
                Exception("First failure"),
                Exception("Second failure"),
                Mock(status_code=200)
            ]
            
            notifier = Notifier(mock_config)
            notifier.send_slack_notification("Test message")
            
            assert mock_post.call_count == 3  # Two retries + final success
