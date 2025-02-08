import os
import sys
print("Starting minimal test...")
print(f"Python path: {sys.path}")
print(f"Current working directory: {os.getcwd()}")

try:
    print("\nTrying to import config_manager...")
    from src.utils.config_manager import ConfigManager
    print("✓ ConfigManager imported")

    print("\nTrying to import logger...")
    from src.utils.logger import Logger
    print("✓ Logger imported")

    print("\nTrying to create ConfigManager instance...")
    config_manager = ConfigManager("src/config/config.yaml")
    print("✓ ConfigManager instance created")

    print("\nTrying to initialize logger...")
    Logger.initialize(config_manager['logging'])
    logger = Logger.get_logger(__name__)
    print("✓ Logger initialized")

    print("\nTrying to log a message...")
    logger.info("Test message")
    print("✓ Message logged")

except Exception as e:
    print(f"\n❌ Error occurred: {str(e)}")
    import traceback
    traceback.print_exc()
