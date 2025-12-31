# URL Guardian - Phishing Detection Proxy

A transparent HTTP/HTTPS proxy that detects phishing URLs and warns users before they visit dangerous sites.

## Features

- **Real-time URL scanning** - Checks every URL before allowing access
- **Pattern-based detection** - Fast detection using known phishing patterns
- **ML-based detection** - Optional machine learning model for higher accuracy
- **Warning page** - Beautiful warning page with proceed/block options
- **User choice** - Users can proceed to sites at their own risk
- **Caching** - Remembers checked URLs to improve performance

## Installation

```bash
cd ~/url-guardian

# Install dependencies
pip install -r requirements.txt

# Train the ML model (optional, for ML mode)
python phishing_checker.py
```

## Usage

### Start the Proxy (Interactive Mode)

```bash
./start.sh
# or
./start.sh --port 8080 --ml  # Enable ML detection
```

### Start the Proxy (Headless/Background)

```bash
./start-headless.sh
# or
PORT=8080 ML_ENABLED=true ./start-headless.sh
```

### Configure Your Browser

1. Start the proxy
2. Set your browser's HTTP/HTTPS proxy to `localhost:1234`
3. For HTTPS inspection, visit `http://mitm.it` and install the CA certificate

### Browser Proxy Settings

**Firefox:**
- Settings → Network Settings → Manual proxy configuration
- HTTP Proxy: `localhost`, Port: `8080`
- Check "Also use this proxy for HTTPS"

**Chrome/Chromium:**
```bash
chromium --proxy-server="http://localhost:1234"
```

**System-wide (Linux):**
```bash
export http_proxy=http://localhost:1234
export https_proxy=http://localhost:1234
```

## How It Works

1. **Request Interception**: mitmproxy intercepts all HTTP/HTTPS requests
2. **URL Extraction**: The addon extracts the target URL
3. **Phishing Check**: URL is checked against:
   - Whitelist of trusted domains
   - Pattern-based detection (URL shorteners, suspicious keywords, etc.)
   - ML model (if enabled) - uses 30 features including domain age, WHOIS data, etc.
4. **Warning Display**: If phishing is detected, a warning page is shown
5. **User Choice**: User can go back or proceed at their own risk

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | 8080 | Proxy listen port |
| `--ml` | false | Enable ML-based detection |
| `--transparent` | false | Transparent proxy mode |

## Project Structure

```
url-guardian/
├── proxy_addon.py       # Main mitmproxy addon
├── phishing_checker.py  # URL checking logic
├── phishing_detector/   # ML model from PhishingURL repo
├── templates/
│   └── warning.html     # Warning page template
├── models/
│   └── phishing_model.pkl  # Trained ML model (auto-generated)
├── start.sh             # Interactive startup script
├── start-headless.sh    # Headless startup script
└── requirements.txt     # Python dependencies
```

## Credits

- ML model based on [PhishingURL](https://github.com/sinisterdaddy/PhishingURL)
- Proxy powered by [mitmproxy](https://mitmproxy.org/)
