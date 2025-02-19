from typing import List, Dict, Any
import requests
from bs4 import BeautifulSoup
import pandas as pd
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import logging
import time
import csv

load_dotenv()

class OWASPHistoricalCollector:
    """Collects historical OWASP Top 10 data from various releases"""
    
    OWASP_RELEASES = {
        "2013": "https://owasp.org/www-project-top-ten/2013/A1_Injection",
        "2017": "https://owasp.org/www-project-top-ten/2017/Top_10",
        "2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    }

    # Mapping of known vulnerabilities across years for consistency
    VULNERABILITY_MAPPING = {
        "Injection": ["Injection", "SQL Injection", "Command Injection", "A1-Injection"],
        "Broken Authentication": ["Broken Authentication", "Broken Authentication and Session Management", "A2:2017-Broken Authentication", "A07:2021-Identification and Authentication Failures"],
        "Sensitive Data Exposure": ["Sensitive Data Exposure", "Cryptographic Failures", "A3:2017-Sensitive Data Exposure", "A02:2021-Cryptographic Failures"],
        "XML External Entities": ["XML External Entities", "XXE", "A4:2017-XML External Entities"],
        "Broken Access Control": ["Broken Access Control", "A5:2017-Broken Access Control", "A01:2021-Broken Access Control"],
        "Security Misconfiguration": ["Security Misconfiguration", "A6:2017-Security Misconfiguration", "A05:2021-Security Misconfiguration"],
        "Cross-Site Scripting": ["Cross-Site Scripting", "XSS", "A7:2017-Cross-Site Scripting"],
        "Insecure Deserialization": ["Insecure Deserialization", "A8:2017-Insecure Deserialization", "A08:2021-Software and Data Integrity Failures"],
        "Using Components with Known Vulnerabilities": ["Using Components with Known Vulnerabilities", "A9:2017-Using Components with Known Vulnerabilities", "A06:2021-Vulnerable and Outdated Components"],
        "Insufficient Logging & Monitoring": ["Insufficient Logging & Monitoring", "A10:2017-Insufficient Logging & Monitoring", "A09:2021-Security Logging and Monitoring Failures"]
    }

    OWASP_2021_DATA = [
        ("A01:2021-Broken Access Control", 1),
        ("A02:2021-Cryptographic Failures", 2),
        ("A03:2021-Injection", 3),
        ("A04:2021-Insecure Design", 4),
        ("A05:2021-Security Misconfiguration", 5),
        ("A06:2021-Vulnerable and Outdated Components", 6),
        ("A07:2021-Identification and Authentication Failures", 7),
        ("A08:2021-Software and Data Integrity Failures", 8),
        ("A09:2021-Security Logging and Monitoring Failures", 9),
        ("A10:2021-Server-Side Request Forgery", 10)
    ]

    OWASP_2017_DATA = [
        ("A1:2017-Injection", 1),
        ("A2:2017-Broken Authentication", 2),
        ("A3:2017-Sensitive Data Exposure", 3),
        ("A4:2017-XML External Entities", 4),
        ("A5:2017-Broken Access Control", 5),
        ("A6:2017-Security Misconfiguration", 6),
        ("A7:2017-Cross-Site Scripting", 7),
        ("A8:2017-Insecure Deserialization", 8),
        ("A9:2017-Using Components with Known Vulnerabilities", 9),
        ("A10:2017-Insufficient Logging & Monitoring", 10)
    ]

    OWASP_2013_DATA = [
        ("A1-Injection", 1),
        ("A2-Broken Authentication and Session Management", 2),
        ("A3-Cross-Site Scripting", 3),
        ("A4-Insecure Direct Object References", 4),
        ("A5-Security Misconfiguration", 5),
        ("A6-Sensitive Data Exposure", 6),
        ("A7-Missing Function Level Access Control", 7),
        ("A8-Cross-Site Request Forgery", 8),
        ("A9-Using Components with Known Vulnerabilities", 9),
        ("A10-Unvalidated Redirects and Forwards", 10)
    ]

    def collect(self) -> pd.DataFrame:
        data = []
        
        # Add 2013 data
        for vuln, rank in self.OWASP_2013_DATA:
            data.append({
                'year': '2013',
                'rank': rank,
                'vulnerability': self._normalize_vulnerability(vuln),
                'original_name': vuln
            })
        
        # Add 2017 data
        for vuln, rank in self.OWASP_2017_DATA:
            data.append({
                'year': '2017',
                'rank': rank,
                'vulnerability': self._normalize_vulnerability(vuln),
                'original_name': vuln
            })
        
        # Add 2021 data
        for vuln, rank in self.OWASP_2021_DATA:
            data.append({
                'year': '2021',
                'rank': rank,
                'vulnerability': self._normalize_vulnerability(vuln),
                'original_name': vuln
            })
        
        return pd.DataFrame(data)

    def _normalize_vulnerability(self, vuln: str) -> str:
        """Normalize vulnerability names across years"""
        # Remove year and rank prefixes
        clean_vuln = vuln.split('-')[-1].strip()
        
        for normalized, variants in self.VULNERABILITY_MAPPING.items():
            if any(variant.lower() in vuln.lower() for variant in variants):
                return normalized
            
        # If no mapping found, return cleaned vulnerability name
        return clean_vuln

class GitHubSecurityCollector:
    """Collects security advisory data from GitHub"""
    
    def __init__(self):
        self.token = os.getenv('GITHUB_TOKEN')
        if not self.token:
            logging.error("GitHub token not found in environment variables")
            raise ValueError("GitHub token is required")
        self.headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v4+json'
        }
        
    def collect(self, days_back: int = 30) -> pd.DataFrame:
        query = """
        query {
          securityVulnerabilities(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}) {
            nodes {
              severity
              package {
                name
                ecosystem
              }
              advisory {
                ghsaId
                description
                summary
                references {
                  url
                }
                publishedAt
              }
            }
          }
        }
        """
        
        try:
            response = requests.post(
                'https://api.github.com/graphql',
                json={'query': query},
                headers=self.headers,
                timeout=60  # Increased timeout
            )
            response.raise_for_status()
            
            data = response.json()
            if 'errors' in data:
                logging.error(f"GitHub API errors: {data['errors']}")
                return pd.DataFrame()
                
            vulns = data.get('data', {}).get('securityVulnerabilities', {}).get('nodes', [])
            if not vulns:
                logging.warning("No vulnerabilities found in GitHub response")
                return pd.DataFrame()
            
            # Transform the data into a flat structure
            formatted_vulns = []
            for vuln in vulns:
                if not vuln:
                    continue
                try:
                    formatted_vulns.append({
                        'id': vuln.get('advisory', {}).get('ghsaId', ''),
                        'severity': self._normalize_severity(vuln.get('severity', 'UNKNOWN')),
                        'ecosystem': vuln.get('package', {}).get('ecosystem', 'UNKNOWN'),
                        'package_name': vuln.get('package', {}).get('name', 'UNKNOWN'),
                        'description': vuln.get('advisory', {}).get('description', ''),
                        'summary': vuln.get('advisory', {}).get('summary', ''),
                        'published_date': vuln.get('advisory', {}).get('publishedAt', '')
                    })
                except Exception as e:
                    logging.warning(f"Error processing vulnerability: {str(e)}")
                    continue
            
            if not formatted_vulns:
                logging.warning("No valid vulnerabilities found after processing")
                return pd.DataFrame()
            
            df = pd.DataFrame(formatted_vulns)
            
            # Convert severity to numeric scale
            df['severity'] = df['severity'].astype(float)
            
            # Ensure published_date is datetime
            df['published_date'] = pd.to_datetime(df['published_date'])
            
            return df
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Error collecting GitHub security data: {str(e)}")
            return pd.DataFrame()
        except Exception as e:
            logging.error(f"Unexpected error in GitHub collection: {str(e)}")
            return pd.DataFrame()
    
    def _normalize_severity(self, severity: str) -> float:
        """Convert GitHub severity levels to numeric scale"""
        severity_map = {
            'CRITICAL': 9.0,
            'HIGH': 7.0,
            'MODERATE': 5.0,
            'LOW': 3.0,
            'UNKNOWN': 0.0
        }
        return severity_map.get(severity.upper(), 0.0)

class CVECollector:
    """Collects CVE data from multiple sources with fallback options"""
    
    def __init__(self):
        self.api_key = os.getenv('NVD_API_KEY')
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.sources = [
            self._collect_from_nvd,
            self._collect_from_github_advisory,
            self._collect_from_osv,
            self._collect_from_mitre
        ]
    
    def collect(self) -> pd.DataFrame:
        """Try collecting CVE data from multiple sources until successful"""
        all_cves = []
        
        for source_func in self.sources:
            try:
                df = source_func()
                if not df.empty:
                    all_cves.append(df)
                    logging.info(f"Successfully collected {len(df)} CVEs from {source_func.__name__}")
            except Exception as e:
                logging.warning(f"Failed to collect from {source_func.__name__}: {str(e)}")
                continue
        
        if not all_cves:
            logging.error("Failed to collect CVE data from any source")
            return pd.DataFrame()
        
        # Combine and deduplicate CVEs
        combined_df = pd.concat(all_cves, ignore_index=True)
        combined_df = combined_df.drop_duplicates(subset=['id'])
        
        logging.info(f"Total unique CVEs collected: {len(combined_df)}")
        return combined_df
    
    def _collect_from_nvd(self) -> pd.DataFrame:
        """Collect CVEs from NVD API with improved error handling"""
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; OWASP-Top10-Predictor/1.0)',
            'Accept': 'application/json'
        }
        
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        # Last 30 days of CVEs
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        params = {
            'pubStartDate': start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            'pubEndDate': end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            'resultsPerPage': 20
        }
        
        cves = []
        try:
            # Add exponential backoff retry logic
            max_retries = 3
            retry_delay = 5
            
            for attempt in range(max_retries):
                try:
                    response = requests.get(
                        base_url, 
                        headers=headers, 
                        params=params, 
                        timeout=60  # Increased timeout
                    )
                    response.raise_for_status()
                    
                    if response.status_code == 200:
                        data = response.json()
                        for vuln in data.get('vulnerabilities', []):
                            cve = vuln.get('cve', {})
                            if cve:
                                cves.append(self._parse_nvd_cve(cve))
                        break  # Success, exit retry loop
                    
                except requests.exceptions.Timeout:
                    if attempt < max_retries - 1:
                        sleep_time = retry_delay * (2 ** attempt)  # Exponential backoff
                        logging.warning(f"NVD request timed out, retrying in {sleep_time} seconds...")
                        time.sleep(sleep_time)
                        continue
                    raise
                
                except requests.exceptions.RequestException as e:
                    if attempt < max_retries - 1:
                        sleep_time = retry_delay * (2 ** attempt)
                        logging.warning(f"NVD request failed, retrying in {sleep_time} seconds... Error: {str(e)}")
                        time.sleep(sleep_time)
                        continue
                    raise
                    
        except Exception as e:
            logging.error(f"Error collecting from NVD: {str(e)}")
            return pd.DataFrame()
        
        if not cves:
            logging.warning("No CVEs collected from NVD")
            return pd.DataFrame()
            
        return pd.DataFrame(cves)
    
    def _collect_from_github_advisory(self) -> pd.DataFrame:
        """Collect CVEs from GitHub Security Advisory Database"""
        if not self.github_token:
            return pd.DataFrame()
        
        query = """
        query {
          securityVulnerabilities(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}) {
            nodes {
              advisory {
                identifiers {
                  type
                  value
                }
                description
                severity
                publishedAt
                references {
                  url
                }
              }
              package {
                name
                ecosystem
              }
              severity
              vulnerableVersionRange
            }
          }
        }
        """
        
        headers = {'Authorization': f'Bearer {self.github_token}'}
        cves = []
        
        try:
            response = requests.post(
                'https://api.github.com/graphql',
                json={'query': query},
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get('data', {}).get('securityVulnerabilities', {}).get('nodes', [])
                for vuln in vulns:
                    cves.append(self._parse_github_advisory(vuln))
        except Exception as e:
            logging.error(f"Error collecting from GitHub: {str(e)}")
            return pd.DataFrame()
        
        return pd.DataFrame(cves)
    
    def _collect_from_osv(self) -> pd.DataFrame:
        """Collect vulnerability data from OSV (Open Source Vulnerabilities)"""
        base_url = "https://api.osv.dev/v1/query"
        
        # Query last 30 days
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=30)
        
        query = {
            "commit": "",
            "version": "",
            "package": {"name": "", "ecosystem": ""},
            "page_token": "",
            "page_size": 1000
        }
        
        cves = []
        try:
            response = requests.post(base_url, json=query, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulns', []):
                    cves.append(self._parse_osv_vuln(vuln))
        except Exception as e:
            logging.error(f"Error collecting from OSV: {str(e)}")
            return pd.DataFrame()
        
        return pd.DataFrame(cves)
    
    def _collect_from_mitre(self) -> pd.DataFrame:
        """Collect CVE data from MITRE CVE List"""
        base_url = "https://cve.mitre.org/data/downloads/allitems.csv"
        
        try:
            df = pd.read_csv(base_url, 
                            quoting=csv.QUOTE_ALL,  # Handle quoted fields
                            escapechar='\\',        # Handle escaped characters
                            on_bad_lines='skip')    # Skip problematic lines
            return df
        except Exception as e:
            logging.error(f"Error collecting from MITRE: {str(e)}")
            return pd.DataFrame()
    
    def _parse_nvd_cve(self, cve: Dict) -> Dict:
        """Parse NVD CVE data into common format"""
        metrics = cve.get('metrics', {})
        cvss_data = None
        base_score = 0.0
        
        for metric_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            metric_list = metrics.get(metric_type, [])
            if metric_list:
                metric = metric_list[0]
                cvss_data = metric.get('cvssData', {})
                base_score = float(metric.get('baseScore', 0.0))
                break
        
        return {
            'id': cve.get('id', ''),
            'source': 'nvd',
            'published_date': cve.get('published', ''),
            'description': next((d['value'] for d in cve.get('descriptions', [])
                               if d.get('lang') == 'en'), ''),
            'severity': base_score,
            'attack_vector': cvss_data.get('attackVector', '') if cvss_data else '',
            'attack_complexity': cvss_data.get('attackComplexity', '') if cvss_data else '',
            'impact_type': self._categorize_vulnerability(cve)
        }
    
    def _parse_github_advisory(self, advisory: Dict) -> Dict:
        """Parse GitHub Security Advisory data into common format"""
        # Get CVE ID if available, otherwise use GHSA ID
        identifiers = advisory.get('advisory', {}).get('identifiers', [])
        cve_id = next((i['value'] for i in identifiers if i['type'] == 'CVE'), None)
        ghsa_id = advisory.get('advisory', {}).get('ghsaId', '')
        
        return {
            'id': cve_id or ghsa_id or f"GHSA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'source': 'github',
            'published_date': advisory.get('advisory', {}).get('publishedAt', ''),
            'description': advisory.get('advisory', {}).get('description', ''),
            'severity': self._normalize_severity(advisory.get('severity', '')),
            'attack_vector': 'network' if 'remote' in advisory.get('advisory', {}).get('description', '').lower() else 'local',
            'attack_complexity': 'high' if 'complex' in advisory.get('advisory', {}).get('description', '').lower() else 'low',
            'impact_type': self._categorize_vulnerability(advisory)
        }
    
    def _parse_osv_vuln(self, vuln: Dict) -> Dict:
        """Parse OSV vulnerability data into common format"""
        return {
            'id': vuln.get('id', ''),
            'source': 'osv',
            'published_date': vuln.get('published', ''),
            'description': vuln.get('details', ''),
            'severity': self._calculate_severity_from_affects(vuln.get('affected', [])),
            'attack_vector': 'unknown',
            'attack_complexity': 'unknown',
            'impact_type': self._categorize_vulnerability(vuln)
        }
    
    def _normalize_severity(self, severity: str) -> float:
        """Convert string severity levels to numeric scale"""
        severity_map = {
            'CRITICAL': 9.0,
            'HIGH': 7.0,
            'MODERATE': 5.0,
            'LOW': 3.0,
            'UNKNOWN': 0.0
        }
        return severity_map.get(severity.upper(), 0.0)
    
    def _calculate_severity_from_affects(self, affects: List[Dict]) -> float:
        """Calculate severity based on number of affected versions/packages"""
        if not affects:
            return 0.0
        return min(len(affects) * 2.0, 10.0)  # Scale based on impact breadth
    
    def _categorize_vulnerability(self, data: Dict) -> str:
        """Categorize vulnerability into OWASP Top 10 categories"""
        description = str(data.get('description', '')).lower()
        
        categories = {
            'Broken Access Control': ['access control', 'authorization', 'permission', 'privilege'],
            'Cryptographic Failures': ['crypto', 'encrypt', 'tls', 'ssl', 'cipher'],
            'Injection': ['sql', 'command injection', 'xpath', 'nosql', 'ldap injection'],
            'Insecure Design': ['design flaw', 'architectural', 'business logic'],
            'Security Misconfiguration': ['config', 'default setting', 'hardcoded', 'setup'],
            'Vulnerable Components': ['dependency', 'outdated', 'component', 'library'],
            'Authentication Failures': ['auth', 'login', 'password', 'credential'],
            'Software Integrity Failures': ['integrity', 'supply chain', 'update mechanism'],
            'Logging Failures': ['log', 'monitor', 'audit', 'track'],
            'Server-Side Request Forgery': ['ssrf', 'request forgery', 'server side request']
        }
        
        for category, keywords in categories.items():
            if any(keyword in description for keyword in keywords):
                return category
        
        return 'Other'