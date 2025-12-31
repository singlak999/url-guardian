#!/bin/bash

# URL Guardian - Headless Startup Script
# Runs the proxy without the interactive UI (for background/service use)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
fi

PORT=${PORT:-1234}
ML_ENABLED=${ML_ENABLED:-false}

echo "Starting URL Guardian (headless) on port $PORT..."

CMD="mitmdump"
ARGS="-s proxy_addon.py -p $PORT"

if [ "$ML_ENABLED" = true ]; then
    ARGS="$ARGS --set phishing_ml=true"
fi

# Run mitmdump (headless version)
$CMD $ARGS
