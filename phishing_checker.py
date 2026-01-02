"""
Phishing URL Checker Module
Uses ML model from PhishingURL repo for detection
"""

import os
import sys
import re
import pickle
import hashlib
from functools import lru_cache
from typing import Tuple, Optional

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import GradientBoostingClassifier

# Add phishing_detector to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'phishing_detector'))

# Known phishing patterns for quick check
SUSPICIOUS_PATTERNS = [
    r'bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly',  # URL shorteners
    r'login.*(?:paypal|apple|microsoft|google|amazon|bank)',  # Fake login pages
    r'(?:paypal|apple|microsoft|amazon|netflix).*(?:secure|verify|update|login|account)',  # Brand + suspicious word
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses in URL
    r'secure.*update|verify.*account|confirm.*identity',  # Phishing keywords
    r'@',  # @ symbol in URL (redirect trick)
    r'\.tk[/\s:]|\.tk$|\.ml[/\s:]|\.ml$|\.ga[/\s:]|\.ga$|\.cf[/\s:]|\.cf$|\.gq[/\s:]|\.gq$',  # Free domain TLDs often used in phishing
    r'-{2,}',  # Multiple hyphens
    r'\.com-|\.org-|\.net-',  # Domain lookalikes
]

# Trusted domains (whitelist)
TRUSTED_DOMAINS = {
    'google.com', 'github.com', 'stackoverflow.com', 'microsoft.com',
    'amazon.com', 'apple.com', 'cloudflare.com', 'mozilla.org',
    'wikipedia.org', 'reddit.com', 'youtube.com', 'twitter.com',
    'facebook.com', 'linkedin.com', 'netflix.com', 'localhost'
}


class PhishingChecker:
    def __init__(self):
        self.model = None
        self.feature_extractor = None
        self.use_xgb = False
        self._load_model()
        self._url_cache = {}  # Cache for checked URLs

    def _load_model(self):
        """Load or train the ML model"""
        # Prefer the optimized model in models folder
        optimized_model_path = os.path.join(os.path.dirname(__file__), 'models', 'phishing_model_optimized.pkl')
        legacy_model_path = os.path.join(os.path.dirname(__file__), 'models', 'phishing_model.pkl')

        if os.path.exists(optimized_model_path):
            self.model = joblib.load(optimized_model_path)
            self.use_xgb = True
        elif os.path.exists(legacy_model_path):
            with open(legacy_model_path, 'rb') as f:
                self.model = pickle.load(f)
            self.use_xgb = False
        else:
            self._train_model(legacy_model_path)

    def _train_model(self, save_path: str):
        """Train the model from CSV data"""
        csv_path = os.path.join(os.path.dirname(__file__), 'phishing_detector', 'phishing.csv')

        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Training data not found: {csv_path}")

        data = pd.read_csv(csv_path)
        data = data.drop(['Index'], axis=1)

        X = data.drop(['class'], axis=1)
        y = data['class']

        self.model = GradientBoostingClassifier(max_depth=4, learning_rate=0.7)
        self.model.fit(X, y)

        # Save the trained model
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'wb') as f:
            pickle.dump(self.model, f)

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        domain = re.findall(r"://([^/]+)/?", url)
        if domain:
            domain = domain[0]
            if domain.startswith('www.'):
                domain = domain[4:]
            # Remove port if present
            domain = domain.split(':')[0]
            return domain.lower()
        return url.lower()

    def _is_trusted(self, url: str) -> bool:
        """Check if URL is from a trusted domain"""
        domain = self._extract_domain(url)
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith('.' + trusted):
                return True
        return False

    def _quick_pattern_check(self, url: str) -> Tuple[bool, float]:
        """
        Quick pattern-based check before expensive ML inference
        Returns: (is_suspicious, confidence)
        """
        url_lower = url.lower()
        matches = 0

        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url_lower):
                matches += 1

        if matches >= 3:
            return True, 0.9
        elif matches >= 2:
            return True, 0.7
        elif matches >= 1:
            return True, 0.5
        return False, 0.0

    def _get_cache_key(self, url: str) -> str:
        """Generate cache key for URL"""
        domain = self._extract_domain(url)
        return hashlib.md5(domain.encode()).hexdigest()

    def check_url(self, url: str, use_ml: bool = True) -> Tuple[bool, float, str]:
        """
        Check if URL is phishing

        Returns:
            Tuple of (is_phishing, confidence, reason)
        """
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Check cache first
        cache_key = self._get_cache_key(url)
        if cache_key in self._url_cache:
            return self._url_cache[cache_key]

        # Check trusted domains
        if self._is_trusted(url):
            result = (False, 1.0, "Trusted domain")
            self._url_cache[cache_key] = result
            return result

        # Quick pattern check
        is_suspicious, pattern_confidence = self._quick_pattern_check(url)

        if is_suspicious and pattern_confidence >= 0.7:
            result = (True, pattern_confidence, "Suspicious URL pattern detected")
            self._url_cache[cache_key] = result
            return result

        # ML-based check (if enabled and pattern check isn't conclusive)
        if use_ml and self.model is not None:
            try:
                from phishing_detector.feature import generate_data_set
                features = np.array(generate_data_set(url)).reshape(1, 30)
                prediction = self.model.predict(features)[0]
                probabilities = self.model.predict_proba(features)[0]

                if self.use_xgb:
                    # XGBoost model uses 0/1 labels: 0 = phishing, 1 = safe
                    if prediction == 0:
                        confidence = probabilities[0]  # Probability of phishing
                        result = (True, confidence, "ML model detected phishing indicators")
                    else:
                        confidence = probabilities[1]  # Probability of safe
                        result = (False, confidence, "ML model: appears safe")
                else:
                    # Legacy model uses -1/1 labels: -1 = phishing, 1 = safe
                    if prediction == -1:
                        confidence = probabilities[0]  # Probability of phishing
                        result = (True, confidence, "ML model detected phishing indicators")
                    else:
                        confidence = probabilities[1]  # Probability of safe
                        result = (False, confidence, "ML model: appears safe")

                self._url_cache[cache_key] = result
                return result
            except Exception as e:
                # If ML check fails, fall back to pattern result
                if is_suspicious:
                    result = (True, pattern_confidence, f"Pattern-based detection (ML error: {str(e)[:50]})")
                else:
                    result = (False, 0.5, "Unable to fully verify")
                self._url_cache[cache_key] = result
                return result

        # Default: use pattern result
        if is_suspicious:
            result = (True, pattern_confidence, "Suspicious URL pattern")
        else:
            result = (False, 0.8, "No suspicious patterns detected")

        self._url_cache[cache_key] = result
        return result

    def clear_cache(self):
        """Clear the URL cache"""
        self._url_cache.clear()


# Singleton instance
_checker = None

def get_checker() -> PhishingChecker:
    """Get or create the phishing checker instance"""
    global _checker
    if _checker is None:
        _checker = PhishingChecker()
    return _checker


if __name__ == "__main__":
    # Test the checker
    checker = get_checker()

    test_urls = [
        "https://google.com",
        "https://paypal-login-verify.tk",
        "http://192.168.1.1/admin",
        "https://bit.ly/abc123",
        "https://github.com/user/repo",
    ]

    for url in test_urls:
        is_phishing, confidence, reason = checker.check_url(url, use_ml=False)
        status = "PHISHING" if is_phishing else "SAFE"
        print(f"{status} ({confidence:.0%}): {url} - {reason}")
