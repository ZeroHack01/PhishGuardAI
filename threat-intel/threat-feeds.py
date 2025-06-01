"""
PhishGuard AI - Threat Intelligence Feeds Integration
File: threat-intel/threat-feeds.py

Advanced threat intelligence aggregation from multiple external sources
Provides real-time phishing URL detection and domain reputation data
"""

import asyncio
import aiohttp
import json
import hashlib
import time
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import dns.resolver
import whois
import requests
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('threat_intel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelligence:
    """Data structure for threat intelligence information"""
    url: str
    domain: str
    threat_score: float  # 0.0 (safe) to 1.0 (malicious)
    threat_types: List[str]
    sources: List[str]
    confidence: float
    first_seen: datetime
    last_updated: datetime
    reputation_score: int  # -100 (malicious) to +100 (trusted)
    metadata: Dict

class ThreatIntelligenceAggregator:
    """Main threat intelligence aggregation and management system"""
    
    def __init__(self, db_path: str = "threat_intel.db", api_keys_file: str = "api_keys.json"):
        """
        Initialize the threat intelligence aggregator
        
        Args:
            db_path: Path to SQLite database for caching
            api_keys_file: Path to API keys configuration file
        """
        self.db_path = db_path
        self.api_keys = self.load_api_keys(api_keys_file)
        self.session = None
        
        # Initialize database
        self.init_database()
        
        # Feed configurations
        self.feeds = {
            'virustotal': {
                'enabled': True,
                'rate_limit': 4,  # requests per minute for free tier
                'last_request': 0
            },
            'phishtank': {
                'enabled': True,
                'rate_limit': 100,  # requests per hour
                'last_request': 0
            },
            'urlvoid': {
                'enabled': True,
                'rate_limit': 1000,  # requests per day
                'last_request': 0
            },
            'safebrowsing': {
                'enabled': True,
                'rate_limit': 10000,  # requests per day
                'last_request': 0
            },
            'opendbl': {
                'enabled': True,
                'rate_limit': float('inf'),  # No limit for DNS queries
                'last_request': 0
            }
        }
        
        # Cache settings
        self.cache_duration = timedelta(hours=6)  # Cache results for 6 hours
        
        logger.info("🛡️ ThreatIntelligenceAggregator initialized")

    def load_api_keys(self, api_keys_file: str) -> Dict:
        """Load API keys from configuration file"""
        try:
            if os.path.exists(api_keys_file):
                with open(api_keys_file, 'r') as f:
                    return json.load(f)
            else:
                # Create template API keys file
                template = {
                    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
                    "urlvoid": "YOUR_URLVOID_API_KEY", 
                    "safebrowsing": "YOUR_GOOGLE_SAFEBROWSING_API_KEY",
                    "phishtank": "YOUR_PHISHTANK_API_KEY"
                }
                with open(api_keys_file, 'w') as f:
                    json.dump(template, f, indent=2)
                logger.warning(f"⚠️ Created template API keys file: {api_keys_file}")
                return template
        except Exception as e:
            logger.error(f"❌ Error loading API keys: {e}")
            return {}

    def init_database(self):
        """Initialize SQLite database for caching threat intelligence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_cache (
                url_hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                threat_score REAL NOT NULL,
                threat_types TEXT NOT NULL,
                sources TEXT NOT NULL,
                confidence REAL NOT NULL,
                first_seen TIMESTAMP NOT NULL,
                last_updated TIMESTAMP NOT NULL,
                reputation_score INTEGER NOT NULL,
                metadata TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_reputation (
                domain TEXT PRIMARY KEY,
                reputation_score INTEGER NOT NULL,
                age_days INTEGER,
                registrar TEXT,
                country TEXT,
                last_updated TIMESTAMP NOT NULL,
                metadata TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feed_statistics (
                feed_name TEXT PRIMARY KEY,
                total_queries INTEGER DEFAULT 0,
                successful_queries INTEGER DEFAULT 0,
                failed_queries INTEGER DEFAULT 0,
                last_query TIMESTAMP,
                average_response_time REAL DEFAULT 0.0
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON threat_cache(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_updated ON threat_cache(last_updated)')
        
        conn.commit()
        conn.close()
        
        logger.info("✅ Database initialized")

    async def analyze_url(self, url: str, force_refresh: bool = False) -> ThreatIntelligence:
        """
        Comprehensive URL threat analysis using multiple intelligence sources
        
        Args:
            url: URL to analyze
            force_refresh: Force refresh cache and query all sources
            
        Returns:
            ThreatIntelligence object with aggregated results
        """
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        domain = urlparse(url).netloc
        
        # Check cache first (unless force refresh)
        if not force_refresh:
            cached_result = self.get_cached_result(url_hash)
            if cached_result:
                logger.info(f"📋 Cache hit for {domain}")
                return cached_result
        
        logger.info(f"🔍 Analyzing URL: {domain}")
        
        # Initialize session if needed
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={'User-Agent': 'PhishGuard-ThreatIntel/1.0'}
            )
        
        # Collect results from all enabled feeds
        tasks = []
        
        if self.feeds['virustotal']['enabled']:
            tasks.append(self.query_virustotal(url))
        
        if self.feeds['phishtank']['enabled']:
            tasks.append(self.query_phishtank(url))
        
        if self.feeds['urlvoid']['enabled']:
            tasks.append(self.query_urlvoid(url))
        
        if self.feeds['safebrowsing']['enabled']:
            tasks.append(self.query_safebrowsing(url))
        
        if self.feeds['opendbl']['enabled']:
            tasks.append(self.query_dns_blacklists(domain))
        
        # Execute all queries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        threat_intel = self.aggregate_results(url, domain, results)
        
        # Get domain reputation
        domain_rep = await self.get_domain_reputation(domain)
        threat_intel.reputation_score = domain_rep
        
        # Cache result
        self.cache_result(url_hash, threat_intel)
        
        logger.info(f"✅ Analysis complete for {domain} - Score: {threat_intel.threat_score:.2f}")
        
        return threat_intel

    async def query_virustotal(self, url: str) -> Dict:
        """Query VirusTotal API for URL analysis"""
        if not self.api_keys.get('virustotal') or self.api_keys['virustotal'] == 'YOUR_VIRUSTOTAL_API_KEY':
            return {'source': 'virustotal', 'error': 'API key not configured'}
        
        # Rate limiting
        await self.enforce_rate_limit('virustotal')
        
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            async with self.session.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    stats = attributes.get('last_analysis_stats', {})
                    
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values())
                    
                    threat_score = (malicious + suspicious * 0.5) / max(total, 1)
                    
                    return {
                        'source': 'virustotal',
                        'threat_score': threat_score,
                        'threat_types': ['phishing'] if malicious > 0 else [],
                        'confidence': min(total / 50, 1.0),  # More engines = higher confidence
                        'metadata': {
                            'malicious_engines': malicious,
                            'suspicious_engines': suspicious,
                            'total_engines': total,
                            'scan_date': attributes.get('last_analysis_date')
                        }
                    }
                else:
                    return {'source': 'virustotal', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            logger.error(f"❌ VirusTotal query failed: {e}")
            return {'source': 'virustotal', 'error': str(e)}

    async def query_phishtank(self, url: str) -> Dict:
        """Query PhishTank for known phishing URLs"""
        try:
            # PhishTank uses POST requests
            data = {
                'url': url,
                'format': 'json'
            }
            
            async with self.session.post(
                'https://checkurl.phishtank.com/checkurl/',
                data=data
            ) as response:
                
                if response.status == 200:
                    result = await response.json()
                    
                    if result.get('results', {}).get('in_database'):
                        is_phish = result['results'].get('valid')
                        return {
                            'source': 'phishtank',
                            'threat_score': 1.0 if is_phish else 0.0,
                            'threat_types': ['phishing'] if is_phish else [],
                            'confidence': 0.9,
                            'metadata': {
                                'phishtank_id': result['results'].get('phish_id'),
                                'verified': result['results'].get('verified'),
                                'submission_time': result['results'].get('submission_time')
                            }
                        }
                    else:
                        return {
                            'source': 'phishtank',
                            'threat_score': 0.0,
                            'threat_types': [],
                            'confidence': 0.3,  # Lower confidence for unknown URLs
                            'metadata': {'in_database': False}
                        }
                else:
                    return {'source': 'phishtank', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            logger.error(f"❌ PhishTank query failed: {e}")
            return {'source': 'phishtank', 'error': str(e)}

    async def query_urlvoid(self, url: str) -> Dict:
        """Query URLVoid for URL reputation"""
        if not self.api_keys.get('urlvoid') or self.api_keys['urlvoid'] == 'YOUR_URLVOID_API_KEY':
            return {'source': 'urlvoid', 'error': 'API key not configured'}
        
        try:
            domain = urlparse(url).netloc
            api_url = f'https://api.urlvoid.com/v1/pay-as-you-go/?key={self.api_keys["urlvoid"]}&host={domain}'
            
            async with self.session.get(api_url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if 'error' not in data:
                        detections = data.get('detections', 0)
                        engines_count = data.get('engines_count', 1)
                        
                        threat_score = detections / max(engines_count, 1)
                        
                        return {
                            'source': 'urlvoid',
                            'threat_score': threat_score,
                            'threat_types': ['malicious'] if detections > 0 else [],
                            'confidence': 0.8,
                            'metadata': {
                                'detections': detections,
                                'engines_count': engines_count,
                                'scan_date': data.get('scan_date')
                            }
                        }
                    else:
                        return {'source': 'urlvoid', 'error': data.get('error')}
                else:
                    return {'source': 'urlvoid', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            logger.error(f"❌ URLVoid query failed: {e}")
            return {'source': 'urlvoid', 'error': str(e)}

    async def query_safebrowsing(self, url: str) -> Dict:
        """Query Google Safe Browsing API"""
        if not self.api_keys.get('safebrowsing') or self.api_keys['safebrowsing'] == 'YOUR_GOOGLE_SAFEBROWSING_API_KEY':
            return {'source': 'safebrowsing', 'error': 'API key not configured'}
        
        try:
            api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_keys["safebrowsing"]}'
            
            payload = {
                'client': {
                    'clientId': 'phishguard',
                    'clientVersion': '1.0'
                },
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes': ['ALL_PLATFORMS'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            async with self.session.post(api_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if 'matches' in data and data['matches']:
                        threat_types = [match['threatType'] for match in data['matches']]
                        return {
                            'source': 'safebrowsing',
                            'threat_score': 1.0,
                            'threat_types': threat_types,
                            'confidence': 0.95,
                            'metadata': {'matches': data['matches']}
                        }
                    else:
                        return {
                            'source': 'safebrowsing',
                            'threat_score': 0.0,
                            'threat_types': [],
                            'confidence': 0.8,
                            'metadata': {'clean': True}
                        }
                else:
                    return {'source': 'safebrowsing', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            logger.error(f"❌ Safe Browsing query failed: {e}")
            return {'source': 'safebrowsing', 'error': str(e)}

    async def query_dns_blacklists(self, domain: str) -> Dict:
        """Query DNS-based blacklists"""
        blacklists = [
            'multi.surbl.org',
            'phishing.rbl.msrbl.net',
            'uribl.com',
            'dbl.spamhaus.org'
        ]
        
        detections = 0
        total_lists = len(blacklists)
        
        try:
            for blacklist in blacklists:
                try:
                    query_domain = f"{domain}.{blacklist}"
                    dns.resolver.resolve(query_domain, 'A')
                    detections += 1
                except dns.resolver.NXDOMAIN:
                    # Not found in this blacklist (good)
                    pass
                except Exception:
                    # Query failed, don't count
                    total_lists -= 1
            
            threat_score = detections / max(total_lists, 1)
            
            return {
                'source': 'dns_blacklists',
                'threat_score': threat_score,
                'threat_types': ['blacklisted'] if detections > 0 else [],
                'confidence': 0.7,
                'metadata': {
                    'detections': detections,
                    'total_lists': total_lists,
                    'blacklists_checked': blacklists
                }
            }
            
        except Exception as e:
            logger.error(f"❌ DNS blacklist query failed: {e}")
            return {'source': 'dns_blacklists', 'error': str(e)}

    async def get_domain_reputation(self, domain: str) -> int:
        """Get comprehensive domain reputation score"""
        try:
            # Check cache first
            cached_rep = self.get_cached_domain_reputation(domain)
            if cached_rep is not None:
                return cached_rep
            
            reputation_score = 0
            
            # WHOIS analysis
            try:
                w = whois.whois(domain)
                creation_date = w.creation_date
                
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if creation_date:
                    age_days = (datetime.now() - creation_date).days
                    
                    # Age scoring
                    if age_days > 365:
                        reputation_score += 30  # Older domains are more trusted
                    elif age_days > 90:
                        reputation_score += 10
                    else:
                        reputation_score -= 20  # Very new domains are suspicious
                    
                    # Registrar reputation
                    registrar = str(w.registrar).lower() if w.registrar else ""
                    trusted_registrars = ['godaddy', 'namecheap', 'cloudflare', 'google']
                    
                    if any(trusted in registrar for trusted in trusted_registrars):
                        reputation_score += 10
                    
                    # Cache domain reputation
                    self.cache_domain_reputation(domain, reputation_score, age_days, str(w.registrar), str(w.country))
                    
            except Exception as e:
                logger.warning(f"WHOIS query failed for {domain}: {e}")
                reputation_score = 0
            
            return max(-100, min(100, reputation_score))
            
        except Exception as e:
            logger.error(f"❌ Domain reputation analysis failed: {e}")
            return 0

    def aggregate_results(self, url: str, domain: str, results: List) -> ThreatIntelligence:
        """Aggregate results from multiple threat intelligence sources"""
        valid_results = [r for r in results if isinstance(r, dict) and 'error' not in r]
        
        if not valid_results:
            # No valid results, return neutral assessment
            return ThreatIntelligence(
                url=url,
                domain=domain,
                threat_score=0.5,  # Neutral
                threat_types=['unknown'],
                sources=['error'],
                confidence=0.0,
                first_seen=datetime.now(),
                last_updated=datetime.now(),
                reputation_score=0,
                metadata={'error': 'No valid threat intelligence sources available'}
            )
        
        # Weighted aggregation
        total_score = 0
        total_weight = 0
        all_threat_types = set()
        sources = []
        confidence_scores = []
        metadata = {}
        
        # Source weights (higher = more trusted)
        source_weights = {
            'virustotal': 0.3,
            'safebrowsing': 0.25,
            'phishtank': 0.2,
            'urlvoid': 0.15,
            'dns_blacklists': 0.1
        }
        
        for result in valid_results:
            source = result.get('source', 'unknown')
            weight = source_weights.get(source, 0.1)
            
            threat_score = result.get('threat_score', 0)
            confidence = result.get('confidence', 0)
            
            # Weighted score calculation
            total_score += threat_score * weight * confidence
            total_weight += weight * confidence
            
            # Collect threat types
            all_threat_types.update(result.get('threat_types', []))
            
            # Collect sources and metadata
            sources.append(source)
            confidence_scores.append(confidence)
            metadata[source] = result.get('metadata', {})
        
        # Calculate final aggregated score
        final_threat_score = total_score / max(total_weight, 0.1)
        final_confidence = sum(confidence_scores) / len(confidence_scores)
        
        return ThreatIntelligence(
            url=url,
            domain=domain,
            threat_score=final_threat_score,
            threat_types=list(all_threat_types),
            sources=sources,
            confidence=final_confidence,
            first_seen=datetime.now(),
            last_updated=datetime.now(),
            reputation_score=0,  # Will be set by caller
            metadata=metadata
        )

    async def enforce_rate_limit(self, feed_name: str):
        """Enforce rate limiting for API calls"""
        feed_config = self.feeds.get(feed_name, {})
        rate_limit = feed_config.get('rate_limit', float('inf'))
        last_request = feed_config.get('last_request', 0)
        
        if rate_limit != float('inf'):
            time_since_last = time.time() - last_request
            min_interval = 60 / rate_limit  # Convert to seconds between requests
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                logger.info(f"⏱️ Rate limiting {feed_name}: sleeping {sleep_time:.2f}s")
                await asyncio.sleep(sleep_time)
        
        self.feeds[feed_name]['last_request'] = time.time()

    def get_cached_result(self, url_hash: str) -> Optional[ThreatIntelligence]:
        """Retrieve cached threat intelligence result"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM threat_cache 
                WHERE url_hash = ? AND last_updated > ?
            ''', (url_hash, datetime.now() - self.cache_duration))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return ThreatIntelligence(
                    url=row[1],
                    domain=row[2],
                    threat_score=row[3],
                    threat_types=json.loads(row[4]),
                    sources=json.loads(row[5]),
                    confidence=row[6],
                    first_seen=datetime.fromisoformat(row[7]),
                    last_updated=datetime.fromisoformat(row[8]),
                    reputation_score=row[9],
                    metadata=json.loads(row[10])
                )
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Cache retrieval failed: {e}")
            return None

    def cache_result(self, url_hash: str, threat_intel: ThreatIntelligence):
        """Cache threat intelligence result"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO threat_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                url_hash,
                threat_intel.url,
                threat_intel.domain,
                threat_intel.threat_score,
                json.dumps(threat_intel.threat_types),
                json.dumps(threat_intel.sources),
                threat_intel.confidence,
                threat_intel.first_seen.isoformat(),
                threat_intel.last_updated.isoformat(),
                threat_intel.reputation_score,
                json.dumps(threat_intel.metadata)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Cache storage failed: {e}")

    def get_cached_domain_reputation(self, domain: str) -> Optional[int]:
        """Get cached domain reputation"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT reputation_score FROM domain_reputation 
                WHERE domain = ? AND last_updated > ?
            ''', (domain, datetime.now() - timedelta(days=7)))
            
            row = cursor.fetchone()
            conn.close()
            
            return row[0] if row else None
            
        except Exception:
            return None

    def cache_domain_reputation(self, domain: str, reputation_score: int, age_days: int, registrar: str, country: str):
        """Cache domain reputation data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO domain_reputation VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                domain,
                reputation_score,
                age_days,
                registrar,
                country,
                datetime.now().isoformat(),
                json.dumps({'age_days': age_days, 'registrar': registrar, 'country': country})
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Domain reputation cache failed: {e}")

    async def bulk_analyze_urls(self, urls: List[str]) -> Dict[str, ThreatIntelligence]:
        """Analyze multiple URLs concurrently"""
        logger.info(f"🔍 Bulk analyzing {len(urls)} URLs")
        
        tasks = [self.analyze_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            url: result for url, result in zip(urls, results)
            if not isinstance(result, Exception)
        }

    async def close(self):
        """Clean up resources"""
        if self.session:
            await self.session.close()
        logger.info("🧹 ThreatIntelligenceAggregator closed")

    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Cache statistics
            cursor.execute('SELECT COUNT(*) FROM threat_cache')
            total_cached = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM threat_cache WHERE last_updated > ?', 
                         (datetime.now() - timedelta(days=1),))
            recent_cached = cursor.fetchone()[0]
            
            # Threat distribution
            cursor.execute('SELECT AVG(threat_score) FROM threat_cache')
            avg_threat_score = cursor.fetchone()[0] or 0
            
            conn.close()
            
            return {
                'total_cached_results': total_cached,
                'recent_analyses': recent_cached,
                'average_threat_score': round(avg_threat_score, 3),
                'cache_duration_hours': self.cache_duration.total_seconds() / 3600,
                'enabled_feeds': [name for name, config in self.feeds.items() if config['enabled']]
            }
            
        except Exception as e:
            logger.error(f"❌ Statistics retrieval failed: {e}")
            return {}

# Example usage and testing
async def main():
    """Example usage of the ThreatIntelligenceAggregator"""
    aggregator = ThreatIntelligenceAggregator()
    
    # Test URLs
    test_urls = [
        'https://google.com',
        'https://phishing-example.com',
        'https://malware-test.com'
    ]
    
    try:
        # Analyze individual URL
        result = await aggregator.analyze_url('https://google.com')
        print(f"Analysis result: {result}")
        
        # Bulk analysis
        bulk_results = await aggregator.bulk_analyze_urls(test_urls)
        for url, intel in bulk_results.items():
            print(f"{url}: Threat Score {intel.threat_score:.2f}")
        
        # Get statistics
        stats = aggregator.get_statistics()
        print(f"Statistics: {stats}")
        
    finally:
        await aggregator.close()

if __name__ == "__main__":
    asyncio.run(main())
