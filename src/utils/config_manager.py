import os
import yaml
from typing import Any, Dict, Optional

class ConfigManager:
    """Configuration manager for the application."""
    
    def __init__(self, config_path: str):
        """Initialize with configuration file path."""
        print(f"Loading config from: {config_path}")
        self.config_path = config_path
        self.config = self._load_config()
        print(f"Loaded config: {self.config}")
        self._validate_config()
        self._process_env_vars()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config if config else {}
        except Exception as e:
            print(f"Failed to load config from {self.config_path}: {str(e)}")
            raise RuntimeError(f"Failed to load config from {self.config_path}: {str(e)}")

    def _validate_config(self) -> None:
        """Validate required configuration settings."""
        required_sections = ['gcp', 'logging', 'notifications', 'scanner', 'reporter']
        for section in required_sections:
            if section not in self.config:
                self.config[section] = {}

        # Validate GCP config
        gcp_config = self.config['gcp']
        if 'service_account_key_path' not in gcp_config:
            raise ValueError("GCP service account key path not configured")
        
        # Get absolute path for service account key
        if not os.path.isabs(gcp_config['service_account_key_path']):
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            gcp_config['service_account_key_path'] = os.path.join(
                base_dir,
                gcp_config['service_account_key_path']
            )
        
        if not os.path.exists(gcp_config['service_account_key_path']):
            raise ValueError(f"GCP service account key file not found: {gcp_config['service_account_key_path']}")

        # Set default logging config
        logging_config = self.config['logging']
        logging_config.setdefault('level', 'INFO')
        logging_config.setdefault('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logging_config.setdefault('file', 'logs/app.log')
        logging_config.setdefault('max_size', 10485760)  # 10MB
        logging_config.setdefault('backup_count', 5)

        # Set default scanner config
        scanner_config = self.config['scanner']
        scanner_config.setdefault('max_workers', 3)
        scanner_config.setdefault('timeout', 30)
        scanner_config.setdefault('batch_size', 100)

        # Set default reporter config
        reporter_config = self.config['reporter']
        reporter_config.setdefault('output_dir', 'reports')
        reporter_config.setdefault('formats', ['csv', 'json'])

        # Set default notification config
        notifications_config = self.config['notifications']
        if 'smtp' not in notifications_config:
            notifications_config['smtp'] = {'enabled': False}
        if 'slack' not in notifications_config:
            notifications_config['slack'] = {'enabled': False}

    def _process_env_vars(self) -> None:
        """Process environment variables in configuration."""
        def process_value(value: Any) -> Any:
            if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
                env_var = value[2:-1]
                if ':' in env_var:
                    env_var, default = env_var.split(':', 1)
                    return os.getenv(env_var, default)
                return os.getenv(env_var)
            elif isinstance(value, dict):
                return {k: process_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [process_value(item) for item in value]
            return value

        self.config = process_value(self.config)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        return self.config.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """Get configuration value by key."""
        return self.config[key]

    def __contains__(self, key: str) -> bool:
        """Check if key exists in configuration."""
        return key in self.config
