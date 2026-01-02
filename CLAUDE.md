# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

URL Guardian is a transparent HTTP/HTTPS proxy that detects phishing URLs using pattern matching and ML-based detection. It intercepts browser requests via mitmproxy, checks URLs against phishing indicators, and displays warning pages for suspicious sites.

## Commands

### Running the Proxy

```bash
# Interactive mode (with mitmproxy TUI)
./start.sh                        # Default port 1234
./start.sh --port 8080 --ml       # Custom port + ML detection

# Headless mode (for background/service use)
./start-headless.sh
PORT=8080 ML_ENABLED=true ./start-headless.sh
```

### Development

```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Test phishing checker directly
python phishing_checker.py
```

### Training/Updating the ML Model

The ML model files are in `phishing_detector/`. To use a newly trained model, ensure `phishing_detector/phishing_model_optimized.pkl` exists - it will be automatically loaded by `phishing_checker.py`.

## Architecture

### Core Flow

1. **proxy_addon.py** - Mitmproxy addon that intercepts HTTP/HTTPS requests
   - `URLGuardian` class handles request interception
   - Checks URLs via `phishing_checker.get_checker()`
   - Returns warning pages for detected phishing (403 response with HTML)
   - Handles user "proceed anyway" via internal `urlguardian.local` domain

2. **phishing_checker.py** - URL checking logic with layered detection
   - Whitelist check (trusted domains like google.com, github.com)
   - Pattern-based detection (URL shorteners, suspicious keywords, IP addresses in URLs)
   - ML-based detection (optional, uses XGBoost model with 30 URL features)
   - Results are cached by domain hash

3. **phishing_detector/** - Git submodule containing ML model and feature extraction
   - `feature.py` - Extracts 30 features from URLs (domain age, WHOIS data, page content, etc.)
   - `phishing_model_optimized.pkl` - Trained XGBoost model (preferred)
   - Uses 0/1 labels (0=phishing, 1=safe) unlike legacy -1/1 format

### Model Loading Priority

`phishing_checker.py` loads models in this order:
1. `phishing_detector/phishing_model_optimized.pkl` (XGBoost, 0/1 labels)
2. `models/phishing_model.pkl` (legacy GradientBoosting, -1/1 labels)
3. Train new model from `phishing_detector/phishing.csv`

### Key Configuration

- `--ml` / `phishing_ml=true` - Enable ML detection (slower, more accurate)
- Default port: 1234
- Allowed URL duration: 1 hour (after user clicks "proceed anyway")
