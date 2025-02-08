print("Testing imports...")

try:
    import os
    print("✓ os module imported")
except ImportError as e:
    print(f"✗ Failed to import os: {e}")

try:
    import yaml
    print("✓ yaml module imported")
except ImportError as e:
    print(f"✗ Failed to import yaml: {e}")

try:
    from google.oauth2 import service_account
    print("✓ google.oauth2.service_account module imported")
except ImportError as e:
    print(f"✗ Failed to import google.oauth2.service_account: {e}")

try:
    from google.cloud import storage, iam
    print("✓ google.cloud.storage and google.cloud.iam modules imported")
except ImportError as e:
    print(f"✗ Failed to import google cloud modules: {e}")

print("\nTesting environment variables...")
print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', 'Not set')}")
print(f"Current working directory: {os.getcwd()}")

print("\nTesting file access...")
config_path = "src/config/config.yaml"
if os.path.exists(config_path):
    print(f"✓ Config file exists at {config_path}")
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            print("✓ Config file loaded successfully")
    except Exception as e:
        print(f"✗ Failed to load config file: {e}")
else:
    print(f"✗ Config file not found at {config_path}")

credentials_path = os.environ.get('GCP_SERVICE_ACCOUNT_KEY_PATH')
if credentials_path and os.path.exists(credentials_path):
    print(f"✓ Credentials file exists at {credentials_path}")
else:
    print(f"✗ Credentials file not found at {credentials_path}")
