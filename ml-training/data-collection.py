#!/usr/bin/env python3
"""
PhishGuard AI - Data Collection Pipeline
Collects and preprocesses phishing/legitimate URL datasets for model training
"""

import requests
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
import time
import json
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PhishingDataCollector:
    def __init__(self):
        self.phishing_urls = []
        self.legitimate_urls = []
        self.features_dataset = []
        
    def collect_phishing_urls(self):
        """Collect known phishing URLs from multiple sources"""
        logger.info("Collecting phishing URLs from threat intelligence sources...")
        
        # Source 1: PhishTank API (requires API key)
        phishtank_urls = self.fetch_phishtank_data()
        
        # Source 2: OpenPhish feed
        openphish_urls = self.fetch_openphish_data()
        
        # Source 3: Manual curated list for training
        manual_phishing = self.get_manual_phishing_samples()
        
        self.phishing_urls = list(set(phishtank_urls + openphish_urls + manual_phishing))
        logger.info(f"Collected {len(self.phishing_urls)} phishing URLs")
        
        return self.phishing_urls
    
    def collect_legitimate_urls(self):
        """Collect legitimate URLs from trusted sources"""
        logger.info("Collecting legitimate URLs...")
        
        # Source 1: Alexa Top 1M (or similar ranking)
        top_sites = self.fetch_top_websites()
        
        # Source 2: Government and educational domains
        trusted_domains = self.get_trusted_domains()
        
        # Source 3: Major corporations and services
        corporate_sites = self.get_corporate_websites()
        
        self.legitimate_urls = list(set(top_sites + trusted_domains + corporate_sites))
        logger.info(f"Collected {len(self.legitimate_urls)} legitimate URLs")
        
        return self.legitimate_urls
    
    def fetch_phishtank_data(self):
        """Fetch phishing URLs from PhishTank API"""
        try:
            # Note: Replace with actual PhishTank API key
            api_url = "http://data.phishtank.com/data/online-valid.json"
            response = requests.get(api_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                urls = [entry['url'] for entry in data[:1000]]  # Limit for training
                return urls
            else:
                logger.warning("Failed to fetch PhishTank data")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching PhishTank data: {e}")
            return []
    
    def fetch_openphish_data(self):
        """Fetch phishing URLs from OpenPhish feed"""
        try:
            api_url = "https://openphish.com/feed.txt"
            response = requests.get(api_url, timeout=30)
            
            if response.status_code == 200:
                urls = response.text.strip().split('\n')[:500]  # Limit for training
                return [url.strip() for url in urls if url.strip()]
            else:
                logger.warning("Failed to fetch OpenPhish data")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching OpenPhish data: {e}")
            return []
    
    def get_manual_phishing_samples(self):
        """Manually curated phishing samples for training"""
        return [
            "http://paypal-security-update.tk/login",
            "https://amazon-customer-verify.ml/account",
            "http://192.168.1.100/microsoft-security/",
            "https://apple-support-suspended.ga/verify",
            "http://google-account-recovery.cf/signin",
            "https://facebook-security-alert.tk/login",
            "http://netflix-payment-update.ml/billing",
            "https://instagram-verify-account.ga/confirm",
            "http://paypal.security-verify.com/webscr",
            "https://amazon-payments.update-required.net/signin"
        ]
    
    def fetch_top_websites(self):
        """Get top legitimate websites"""
        # Simulate fetching from Alexa/Tranco top sites
        top_sites = [
            "https://www.google.com",
            "https://www.youtube.com", 
            "https://www.facebook.com",
            "https://www.amazon.com",
            "https://www.wikipedia.org",
            "https://www.twitter.com",
            "https://www.instagram.com",
            "https://www.linkedin.com",
            "https://www.reddit.com",
            "https://www.netflix.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://www.github.com",
            "https://www.stackoverflow.com",
            "https://www.paypal.com"
        ]
        
        # Add subpages for more variety
        subpages = []
        for site in top_sites[:10]:
            subpages.extend([
                f"{site}/login",
                f"{site}/account", 
                f"{site}/support",
                f"{site}/about"
            ])
        
        return top_sites + subpages
    
    def get_trusted_domains(self):
        """Get government and educational domains"""
        return [
            "https://www.irs.gov",
            "https://www.usa.gov",
            "https://www.cdc.gov",
            "https://www.fda.gov",
            "https://www.mit.edu",
            "https://www.stanford.edu",
            "https://www.harvard.edu",
            "https://www.berkeley.edu"
        ]
    
    def get_corporate_websites(self):
        """Get major corporate websites"""
        return [
            "https://www.chase.com",
            "https://www.wellsfargo.com",
            "https://www.bankofamerica.com",
            "https://www.visa.com",
            "https://www.mastercard.com",
            "https://www.ibm.com",
            "https://www.oracle.com",
            "https://www.salesforce.com"
        ]
    
    def save_datasets(self):
        """Save collected URLs to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save phishing URLs
        phishing_file = f"training-data/phishing_urls_{timestamp}.txt"
        with open(phishing_file, 'w') as f:
            for url in self.phishing_urls:
                f.write(f"{url}\n")
        
        # Save legitimate URLs  
        legitimate_file = f"training-data/legitimate_urls_{timestamp}.txt"
        with open(legitimate_file, 'w') as f:
            for url in self.legitimate_urls:
                f.write(f"{url}\n")
        
        logger.info(f"Datasets saved: {phishing_file}, {legitimate_file}")
        
        return phishing_file, legitimate_file

def main():
    """Main data collection pipeline"""
    collector = PhishingDataCollector()
    
    # Collect datasets
    phishing_urls = collector.collect_phishing_urls()
    legitimate_urls = collector.collect_legitimate_urls()
    
    # Save to files
    collector.save_datasets()
    
    # Print summary
    print(f"\n📊 Data Collection Complete!")
    print(f"Phishing URLs: {len(phishing_urls)}")
    print(f"Legitimate URLs: {len(legitimate_urls)}")
    print(f"Total samples: {len(phishing_urls) + len(legitimate_urls)}")

if __name__ == "__main__":
    main()
