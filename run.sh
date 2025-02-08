#!/bin/bash

# Export environment variables from .env file
set -a
source .env
set +a

# Set PYTHONPATH and run the script with error output
PYTHONPATH=. python3 src/main.py 2>&1
