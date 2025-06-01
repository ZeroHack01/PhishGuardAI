#!/usr/bin/env python3
"""
PhishGuard AI - Feature Engineering Pipeline
Extracts sophisticated phishing detection features from URLs and web content
"""

import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs
import re
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import whois
from datetime import datetime
import logging
import time
import tldextract
import certifi
import urllib3

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class PhishingFeatureExtractor:
    def __init__(self):
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.top', '.work'}
        self.trusted_domains = {'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
                               'paypal.com', 'facebook.com', 'twitter.com', 'github.com'}
        self.phishing_keywords = {
            'urgent', 'verify', 'suspended', 'security', 'alert', 'confirm',
            'update', 'action', 'required', 'immediate', 'expires', 'limited'
        }

    def extract_all_features(self, url, fetch_content=True):
        """Extract comprehensive feature set from URL"""
        features = {}

        try:
            # URL-based features (fast, always available)
            features.update(self.extract_url_features(url))

            # Domain-based features (moderate speed)
            features.update(self.extract_domain_features(url))

            # Content-based features (slower, requires HTTP request)
            if fetch_content:
                features.update(self.extract_content_features(url))
                features.update(self.extract_ssl_features(url))

            # Mark as successfully processed
            features['extraction_successful'] = 1

        except Exception as e:
            logger.error(f"Feature extraction failed for {url}: {e}")
            features['extraction_successful'] = 0

        return features

    def extract_url_features(self, url):
        """Extract features from URL structure"""
        features = {}

        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)

            # Basic URL components
            features['url_length'] = len(url)
            features['domain_length'] = len(parsed.netloc)
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query) if parsed.query else 0

            # URL structure analysis
            features['has_ip_address'] = self._is_ip_address(parsed.netloc)
            features['has_port'] = ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443')
            features['uses_https'] = 1 if parsed.scheme == 'https' else 0

            # Domain analysis
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['domain_has_hyphen'] = 1 if '-' in extracted.domain else 0
            features['domain_has_numbers'] = 1 if any(c.isdigit() for c in extracted.domain) else 0

            # TLD analysis
            features['suspicious_tld'] = 1 if f".{extracted.suffix}" in self.suspicious_tlds else 0
            features['tld_length'] = len(extracted.suffix) if extracted.suffix else 0

            # Path analysis
            features['path_depth'] = len([p for p in parsed.path.split('/') if p])
            features['has_query_params'] = 1 if parsed.query else 0
            features['query_param_count'] = len(parse_qs(parsed.query)) if parsed.query else 0

            # Suspicious patterns in URL
            url_lower = url.lower()
            features['has_phishing_keywords'] = 1 if any(keyword in url_lower for keyword in self.phishing_keywords) else 0
            features['has_brand_name'] = self._check_brand_impersonation(url_lower, extracted.domain)

            # URL obfuscation indicators
            features['url_encoded_chars'] = url.count('%')
            features['has_double_slash'] = 1 if '//' in parsed.path else 0
            features['has_at_symbol'] = 1 if '@' in url else 0

            # Domain reputation (basic check)
            features['is_trusted_domain'] = 1 if extracted.top_domain_under_public_suffix in self.trusted_domains else 0

        except Exception as e:
            logger.warning(f"URL feature extraction failed: {e}")

        return features

    def extract_domain_features(self, url):
        """Extract domain and DNS-based features"""
        features = {}

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]  # Remove port if present

            # Domain age and registration
            try:
                domain_info = whois.whois(domain, timeout=10)
                if domain_info.creation_date:
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]

                    domain_age_days = (datetime.now() - creation_date).days
                    features['domain_age_days'] = domain_age_days
                    features['domain_recently_registered'] = 1 if domain_age_days < 30 else 0
                else:
                    features['domain_age_days'] = -1
                    features['domain_recently_registered'] = 0

            except Exception as e:
                logger.warning(f"WHOIS failed for {domain}: {e}")
                features['domain_age_days'] = -1
                features['domain_recently_registered'] = 0

            # DNS and connectivity features
            try:
                # Check if domain resolves
                socket.gethostbyname(domain)
                features['domain_resolves'] = 1

                # Count IP addresses (A records)
                addr_info = socket.getaddrinfo(domain, None)
                unique_ips = set([addr[4][0] for addr in addr_info])
                features['ip_address_count'] = len(unique_ips)

            except Exception as e:
                logger.warning(f"DNS resolution failed for {domain}: {e}")
                features['domain_resolves'] = 0
                features['ip_address_count'] = 0

        except Exception as e:
            logger.warning(f"Domain feature extraction failed: {e}")

        return features

    def extract_content_features(self, url):
        """Extract features from web page content"""
        features = {}

        try:
            # Fetch page content with timeout
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=certifi.where(),
                                    allow_redirects=True)

            # Response analysis
            features['response_status_code'] = response.status_code
            features['redirect_count'] = len(response.history)
            features['content_length'] = len(response.content)

            # Content type analysis
            content_type = response.headers.get('Content-Type', '').lower()
            features['is_html_content'] = 1 if 'text/html' in content_type else 0

            if response.status_code == 200 and 'text/html' in content_type:
                soup = BeautifulSoup(response.content, 'html.parser')

                # Page structure analysis
                features['title_length'] = len(soup.title.string) if soup.title and soup.title.string else 0
                features['has_favicon'] = 1 if soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon') else 0

                # Form analysis
                forms = soup.find_all('form')
                features['form_count'] = len(forms)
                features['has_password_field'] = 1 if soup.find('input', type='password') else 0
                features['has_hidden_fields'] = 1 if soup.find('input', type='hidden') else 0

                # External form actions
                external_forms = 0
                for form in forms:
                    action = form.get('action', '')
                    if action and not action.startswith('/') and urlparse(url).netloc not in action:
                        external_forms += 1
                features['external_form_count'] = external_forms

                # Link analysis
                links = soup.find_all('a', href=True)
                external_links = 0
                suspicious_links = 0

                for link in links:
                    href = link['href']
                    if href.startswith('http') and urlparse(url).netloc not in href:
                        external_links += 1
                    if any(keyword in href.lower() for keyword in self.phishing_keywords):
                        suspicious_links += 1

                features['external_link_count'] = external_links
                features['suspicious_link_count'] = suspicious_links
                features['external_link_ratio'] = external_links / len(links) if links else 0

                # Content analysis
                page_text = soup.get_text().lower()
                features['text_length'] = len(page_text)
                features['phishing_keyword_count'] = sum(1 for keyword in self.phishing_keywords if keyword in page_text)

                # Brand impersonation
                features['brand_impersonation_score'] = self._analyze_brand_impersonation(page_text, url)

                # Urgency indicators
                urgency_words = ['urgent', 'immediate', 'expires', 'suspended', 'verify now', 'act now']
                features['urgency_word_count'] = sum(1 for word in urgency_words if word in page_text)

                # Technical indicators
                features['has_iframe'] = 1 if soup.find('iframe') else 0
                features['iframe_count'] = len(soup.find_all('iframe'))

                # Meta tag analysis
                meta_tags = soup.find_all('meta')
                features['meta_tag_count'] = len(meta_tags)
                features['has_meta_refresh'] = 1 if soup.find('meta', {'http-equiv': 'refresh'}) else 0

            else:
                # Non-HTML or error response
                features.update({
                    'title_length': 0, 'has_favicon': 0, 'form_count': 0,
                    'has_password_field': 0, 'has_hidden_fields': 0, 'external_form_count': 0,
                    'external_link_count': 0, 'suspicious_link_count': 0, 'external_link_ratio': 0,
                    'text_length': 0, 'phishing_keyword_count': 0, 'brand_impersonation_score': 0,
                    'urgency_word_count': 0, 'has_iframe': 0, 'iframe_count': 0,
                    'meta_tag_count': 0, 'has_meta_refresh': 0
                })

        except requests.RequestException as e:
            logger.warning(f"Content fetch failed for {url}: {e}")
            features.update({
                'response_status_code': 0, 'redirect_count': 0,
                'content_length': 0, 'is_html_content': 0,
                'title_length': 0, 'has_favicon': 0, 'form_count': 0,
                'has_password_field': 0, 'has_hidden_fields': 0, 'external_form_count': 0,
                'external_link_count': 0, 'suspicious_link_count': 0, 'external_link_ratio': 0,
                'text_length': 0, 'phishing_keyword_count': 0, 'brand_impersonation_score': 0,
                'urgency_word_count': 0, 'has_iframe': 0, 'iframe_count': 0,
                'meta_tag_count': 0, 'has_meta_refresh': 0
            })

        except Exception as e:
            logger.error(f"Content analysis failed: {e}")

        return features

    def extract_ssl_features(self, url):
        """Extract SSL certificate features"""
        features = {}

        try:
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                hostname = parsed.netloc.split(':')[0]
                port = 443

                # Get SSL certificate
                context = ssl.create_default_context(cafile=certifi.where())
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()

                        # Certificate analysis
                        features['has_valid_ssl'] = 1
                        issuer = cert.get('issuer', [[('organizationName', 'Unknown')]])
                        features['ssl_issuer'] = next((item[1] for item in issuer if item[0] == 'organizationName'), 'Unknown')

                        # Certificate validity period
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.now()).days
                        features['ssl_days_until_expiry'] = days_until_expiry
                        features['ssl_expires_soon'] = 1 if days_until_expiry < 30 else 0

                        # Subject alternative names
                        san_count = sum(1 for item in cert.get('subjectAltName', []) if item[0] == 'DNS')
                        features['ssl_san_count'] = san_count

            else:
                features.update({
                    'has_valid_ssl': 0, 'ssl_issuer': 'None',
                    'ssl_days_until_expiry': 0, 'ssl_expires_soon': 0, 'ssl_san_count': 0
                })

        except Exception as e:
            logger.warning(f"SSL analysis failed for {url}: {e}")
            features.update({
                'has_valid_ssl': 0, 'ssl_issuer': 'None',
                'ssl_days_until_expiry': 0, 'ssl_expires_soon': 0, 'ssl_san_count': 0
            })

        return features

    def _is_ip_address(self, hostname):
        """Check if hostname is an IP address"""
        try:
            socket.inet_aton(hostname.split(':')[0])
            return 1
        except socket.error:
            return 0

    def _check_brand_impersonation(self, url_lower, domain):
        """Check for brand impersonation in URL"""
        major_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'twitter']

        for brand in major_brands:
            if brand in url_lower and not domain.endswith(f'{brand}.com'):
                return 1
        return 0

    def _analyze_brand_impersonation(self, page_text, url):
        """Analyze brand impersonation in page content"""
        score = 0
        major_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook']
        domain = urlparse(url).netloc.lower()

        for brand in major_brands:
            if brand in page_text and not domain.endswith(f'{brand}.com'):
                score += 1

        return score

def process_url_dataset(urls_file, labels_file, output_file):
    """Process a dataset of URLs and extract features"""
    extractor = PhishingFeatureExtractor()

    # Load URLs and labels
    try:
        with open(urls_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"URLs file not found: {urls_file}")
        return None

    try:
        with open(labels_file, 'r') as f:
            labels = [int(line.strip()) for line in f]
    except FileNotFoundError:
        logger.error(f"Labels file not found: {labels_file}")
        return None

    # Ensure equal lengths
    if len(urls) != len(labels):
        logger.error(f"Mismatch: {len(urls)} URLs but {len(labels)} labels")
        return None

    # Extract features for each URL
    features_list = []

    for i, url in enumerate(urls):
        logger.info(f"Processing {i+1}/{len(urls)}: {url}")

        features = extractor.extract_all_features(url)
        features['label'] = labels[i]  # 0 = legitimate, 1 = phishing
        features['url'] = url

        features_list.append(features)

        # Rate limiting
        time.sleep(0.1)

    # Convert to DataFrame and save
    try:
        df = pd.DataFrame(features_list)
        df.to_csv(output_file, index=False)
        logger.info(f"Feature extraction complete. Saved to {output_file}")
        return df
    except Exception as e:
        logger.error(f"Failed to save features to {output_file}: {e}")
        return None

if __name__ == "__main__":
    # Example usage
    extractor = PhishingFeatureExtractor()

    # Test with sample URLs
    test_urls = [
        "https://www.google.com/login",
        "http://paypal-security.tk/verify",
        "https://github.com/microsoft/vscode"
    ]

    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        features = extractor.extract_all_features(url)
        print(f"Features extracted: {len(features)}")
        print(f"Sample features: {dict(list(features.items())[:5])}")
