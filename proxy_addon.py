"""
URL Guardian - Mitmproxy Addon
Intercepts HTTP/HTTPS requests and checks for phishing URLs
"""

import os
import re
import time
import hashlib
from urllib.parse import urlencode, parse_qs, urlparse, quote

from mitmproxy import http, ctx
from mitmproxy.script import concurrent

# Import our phishing checker
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from phishing_checker import get_checker


class URLGuardian:
    """
    Mitmproxy addon that checks URLs for phishing and shows warnings
    """

    def __init__(self):
        self.checker = None
        self.allowed_urls = set()  # URLs user has chosen to proceed with
        self.allowed_expiry = {}   # Expiry time for allowed URLs
        self.warning_template = None
        self.allow_duration = 3600  # 1 hour
        self.use_ml = False  # Disable ML by default (slow), use pattern matching

    def load(self, loader):
        """Called when addon is loaded"""
        loader.add_option(
            name="phishing_ml",
            typespec=bool,
            default=False,
            help="Enable ML-based phishing detection (slower but more accurate)"
        )
        loader.add_option(
            name="phishing_allow_duration",
            typespec=int,
            default=3600,
            help="How long (seconds) to remember user's 'proceed anyway' choice"
        )

    def configure(self, updates):
        """Called when configuration changes"""
        if "phishing_ml" in updates:
            self.use_ml = ctx.options.phishing_ml
            ctx.log.info(f"ML-based detection: {'enabled' if self.use_ml else 'disabled'}")

        if "phishing_allow_duration" in updates:
            self.allow_duration = ctx.options.phishing_allow_duration

    def running(self):
        """Called when proxy starts"""
        ctx.log.info("=" * 50)
        ctx.log.info("URL Guardian - Phishing Detection Proxy Started")
        ctx.log.info("=" * 50)

        # Initialize checker
        try:
            self.checker = get_checker()
            ctx.log.info("Phishing checker initialized successfully")
        except Exception as e:
            ctx.log.error(f"Failed to initialize phishing checker: {e}")

        # Load warning template
        template_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'templates', 'warning.html'
        )
        try:
            with open(template_path, 'r') as f:
                self.warning_template = f.read()
            ctx.log.info("Warning template loaded")
        except Exception as e:
            ctx.log.error(f"Failed to load warning template: {e}")
            self.warning_template = self._get_fallback_template()

    def _get_fallback_template(self):
        """Fallback warning template if main template fails to load"""
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Phishing Warning</title></head>
        <body style="font-family: sans-serif; padding: 50px; text-align: center;">
            <h1 style="color: #e74c3c;">⚠️ Phishing Warning</h1>
            <p>The URL <strong>{{URL}}</strong> has been flagged as potentially dangerous.</p>
            <p>Confidence: {{CONFIDENCE}}%</p>
            <p>Reason: {{REASON}}</p>
            <a href="{{PROCEED_URL}}" style="color: red;">Proceed Anyway</a> |
            <a href="javascript:history.back()">Go Back</a>
        </body>
        </html>
        """

    def _get_url_hash(self, url: str) -> str:
        """Generate hash for URL (for allow list)"""
        parsed = urlparse(url)
        # Hash just the domain + path, ignore query params
        key = f"{parsed.netloc}{parsed.path}"
        return hashlib.md5(key.encode()).hexdigest()

    def _is_url_allowed(self, url: str) -> bool:
        """Check if user has already allowed this URL"""
        url_hash = self._get_url_hash(url)
        if url_hash in self.allowed_urls:
            # Check if it hasn't expired
            if time.time() < self.allowed_expiry.get(url_hash, 0):
                return True
            else:
                # Expired, remove from set
                self.allowed_urls.discard(url_hash)
                self.allowed_expiry.pop(url_hash, None)
        return False

    def _allow_url(self, url: str):
        """Mark URL as allowed by user"""
        url_hash = self._get_url_hash(url)
        self.allowed_urls.add(url_hash)
        self.allowed_expiry[url_hash] = time.time() + self.allow_duration
        ctx.log.info(f"URL allowed by user: {url}")

    def _create_warning_response(self, url: str, confidence: float, reason: str) -> http.Response:
        """Create the warning page response"""
        # Create proceed URL - use our internal domain that the proxy intercepts
        encoded_url = quote(url, safe='')
        proceed_url = f"http://urlguardian.local/proceed?url={encoded_url}"

        # Replace placeholders in template
        html = self.warning_template.replace("{{URL}}", url)
        html = html.replace("{{CONFIDENCE}}", str(int(confidence * 100)))
        html = html.replace("{{REASON}}", reason)
        html = html.replace("{{PROCEED_URL}}", proceed_url)

        return http.Response.make(
            403,
            html.encode('utf-8'),
            {"Content-Type": "text/html; charset=utf-8"}
        )

    def request(self, flow: http.HTTPFlow) -> None:
        """Called for each HTTP request"""
        if self.checker is None:
            return

        # Get full URL
        url = flow.request.pretty_url

        # Handle proceed requests (urlguardian.local is our internal domain)
        if flow.request.host == "urlguardian.local":
            if flow.request.path.startswith("/proceed"):
                query = parse_qs(urlparse(flow.request.url).query)
                if 'url' in query:
                    original_url = query['url'][0]
                    self._allow_url(original_url)
                    # Redirect to the original URL
                    flow.response = http.Response.make(
                        302,
                        b"Redirecting...",
                        {"Location": original_url}
                    )
                    return
            # Block any other requests to our internal domain
            flow.response = http.Response.make(404, b"Not found")
            return

        # Skip if already allowed
        if self._is_url_allowed(url):
            return

        # Skip internal/local requests
        host = flow.request.host
        if host in ('localhost', '127.0.0.1', '::1') or host.endswith('.local'):
            return

        # Skip static resources to improve performance
        path = flow.request.path.lower()
        static_extensions = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg')
        if any(path.endswith(ext) for ext in static_extensions):
            return

        # Check the URL
        try:
            is_phishing, confidence, reason = self.checker.check_url(url, use_ml=self.use_ml)

            if is_phishing and confidence >= 0.5:
                ctx.log.warn(f"BLOCKED PHISHING: {url} (confidence: {confidence:.0%}, reason: {reason})")
                flow.response = self._create_warning_response(url, confidence, reason)
            else:
                ctx.log.info(f"ALLOWED: {url}")
        except Exception as e:
            ctx.log.error(f"Error checking URL {url}: {e}")


# Create addon instance
addons = [URLGuardian()]
