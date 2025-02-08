import sys
import os

print(f"Python version: {sys.version}")
print(f"Python path: {sys.path}")
print(f"Current working directory: {os.getcwd()}")

def try_import(module_name):
    try:
        print(f"\nTrying to import {module_name}...")
        __import__(module_name)
        print(f"✓ Successfully imported {module_name}")
    except ImportError as e:
        print(f"✗ Failed to import {module_name}: {e}")
        import traceback
        traceback.print_exc()

# Try importing our modules
modules_to_test = [
    'src',
    'src.utils',
    'src.utils.config_manager',
    'src.utils.logger',
    'src.modules',
    'src.modules.scanner',
    'src.modules.reporter',
    'src.modules.notifier'
]

for module in modules_to_test:
    try_import(module)
