#!/bin/bash

# URL Guardian - Startup Script
# This script starts the phishing detection proxy

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              URL Guardian - Phishing Proxy               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Default settings
PORT=${PORT:-1234}
MODE=${MODE:-regular}  # regular, transparent, or upstream
ML_ENABLED=${ML_ENABLED:-false}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        --ml)
            ML_ENABLED=true
            shift
            ;;
        --transparent)
            MODE="transparent"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -p, --port PORT    Set proxy port (default: 8080)"
            echo "  --ml               Enable ML-based detection (slower)"
            echo "  --transparent      Run in transparent proxy mode"
            echo "  -h, --help         Show this help"
            echo ""
            echo "After starting, configure your browser/system to use:"
            echo "  HTTP Proxy:  localhost:PORT"
            echo "  HTTPS Proxy: localhost:PORT"
            echo ""
            echo "For HTTPS interception, install the mitmproxy CA certificate:"
            echo "  Visit http://mitm.it after configuring the proxy"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check if mitmproxy is installed
if ! command -v mitmproxy &> /dev/null; then
    echo -e "${RED}Error: mitmproxy is not installed${NC}"
    echo "Install it with: pip install mitmproxy"
    exit 1
fi

# Build mitmproxy command
CMD="mitmproxy"
ARGS="-s proxy_addon.py -p $PORT"

if [ "$ML_ENABLED" = true ]; then
    ARGS="$ARGS --set phishing_ml=true"
    echo -e "${YELLOW}ML-based detection: ENABLED (slower but more accurate)${NC}"
else
    echo -e "${GREEN}Pattern-based detection: ENABLED (fast)${NC}"
fi

if [ "$MODE" = "transparent" ]; then
    ARGS="$ARGS --mode transparent"
    echo -e "${YELLOW}Mode: Transparent Proxy${NC}"
else
    echo -e "${GREEN}Mode: Regular Proxy${NC}"
fi

echo ""
echo -e "${GREEN}Starting proxy on port ${PORT}...${NC}"
echo ""
echo -e "${BLUE}Configure your browser/system proxy settings:${NC}"
echo "  HTTP Proxy:  localhost:$PORT"
echo "  HTTPS Proxy: localhost:$PORT"
echo ""
echo -e "${YELLOW}For HTTPS inspection, install the CA certificate:${NC}"
echo "  1. Configure proxy in browser"
echo "  2. Visit http://mitm.it"
echo "  3. Download and install certificate for your OS/browser"
echo ""
echo -e "${BLUE}Press 'q' to quit the proxy${NC}"
echo ""

# Run mitmproxy
$CMD $ARGS
