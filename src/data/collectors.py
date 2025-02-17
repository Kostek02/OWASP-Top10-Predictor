from typing import List, Dict, Any
import requests
from bs4 import BeautifulSoup
import pandas as pd
from datetime import datetime
import os
from dotenv import load_dotenv
import logging
import time

load_dotenv()

class OWASPHistoricalCollector:
    """Collects historical OWASP Top 10 data from various releases"""
    
    OWASP_RELEASES = {
        "2004": "https://raw.githubusercontent.com/OWASP/www-project-top-ten/master/2004/OWASP_Top_Ten_2004.pdf",
        "2007": "https://raw.githubusercontent.com/OWASP/www-project-top-ten/master/2007/OWASP_Top_Ten_2007.pdf",
        "2010": "https://raw.githubusercontent.com/OWASP/www-project-top-ten/master/2010/OWASP%20Top%2010%20-%202010.pdf",
        "2013": "https://raw.githubusercontent.com/OWASP/www-project-top-ten/master/2013/OWASP%20Top%2010%20-%202013.pdf",
        "2017": "https://owasp.org/www-project-top-ten/2017/Top_10",
        "2021": "https://owasp.org/Top10/"
    }

    # Mapping of known vulnerabilities across years for consistency
    VULNERABILITY_MAPPING = {
        "Injection": ["Injection", "SQL Injection", "Command Injection"],
        "Broken Authentication": ["Broken Authentication", "Broken Authentication and Session Management"],
        "Sensitive Data Exposure": ["Sensitive Data Exposure", "Insecure Cryptographic Storage", "Insecure Communications"],
        "XML External Entities": ["XML External Entities", "XXE"],
        "Broken Access Control": ["Broken Access Control", "Insecure Direct Object References", "Missing Function Level Access Control"],
        "Security Misconfiguration": ["Security Misconfiguration"],
        "Cross-Site Scripting": ["Cross-Site Scripting", "XSS", "Cross Site Scripting"],
        "Insecure Deserialization": ["Insecure Deserialization", "Object Deserialization"],
        "Using Components with Known Vulnerabilities": ["Using Components with Known Vulnerabilities", "Known Vulnerabilities"],
        "Insufficient Logging & Monitoring": ["Insufficient Logging & Monitoring", "Insufficient Logging"]
    }

    def collect(self) -> pd.DataFrame:
        data = []
        seen = set()  # Track unique vulnerability-year combinations
        
        for year, url in self.OWASP_RELEASES.items():
            try:
                response = requests.get(url)
                if year in ["2017", "2021"]:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    vulns = self._parse_vulnerabilities(soup, year)
                else:
                    vulns = self._get_historical_vulns(year)
                
                for rank, vuln in enumerate(vulns, 1):
                    key = f"{year}-{vuln}"
                    if key not in seen:
                        seen.add(key)
                        normalized_vuln = self._normalize_vulnerability(vuln)
                        data.append({
                            'year': year,
                            'rank': rank,
                            'vulnerability': normalized_vuln,
                            'original_name': vuln
                        })
            except Exception as e:
                logging.error(f"Error collecting data for {year}: {str(e)}")
                continue
                
        return pd.DataFrame(data)

    def _normalize_vulnerability(self, vuln: str) -> str:
        """Normalize vulnerability names across years"""
        for normalized, variants in self.VULNERABILITY_MAPPING.items():
            if any(variant.lower() in vuln.lower() for variant in variants):
                return normalized
        return vuln

    def _parse_vulnerabilities(self, soup: BeautifulSoup, year: str) -> List[str]:
        if year == "2021":
            # 2021 format
            vulns = []
            headers = soup.find_all(['h1', 'h2'])
            for header in headers:
                text = header.get_text().strip()
                if any(c.isdigit() for c in text) and "A" in text and ":" in text:
                    vuln = text.split(":", 1)[1].strip()
                    vulns.append(vuln)
            return vulns[:10]
        
        elif year == "2017":
            # 2017 format
            vulns = []
            links = soup.find_all('a')
            for link in links:
                text = link.get_text().strip()
                if text.startswith('A') and any(c.isdigit() for c in text):
                    vuln = text.split('-', 1)[1].strip()
                    vulns.append(vuln)
            return vulns[:10]

    def _get_historical_vulns(self, year: str) -> List[str]:
        """Return predefined lists for older versions"""
        historical_data = {
            "2004": [
                "Unvalidated Input",
                "Broken Access Control",
                "Broken Authentication and Session Management",
                "Cross Site Scripting",
                "Buffer Overflow",
                "Injection Flaws",
                "Improper Error Handling",
                "Insecure Storage",
                "Application Denial of Service",
                "Insecure Configuration Management"
            ],
            "2007": [
                "Cross Site Scripting",
                "Injection Flaws",
                "Malicious File Execution",
                "Insecure Direct Object Reference",
                "Cross Site Request Forgery",
                "Information Leakage and Improper Error Handling",
                "Broken Authentication and Session Management",
                "Insecure Cryptographic Storage",
                "Insecure Communications",
                "Failure to Restrict URL Access"
            ],
            "2010": [
                "Injection",
                "Cross-Site Scripting",
                "Broken Authentication and Session Management",
                "Insecure Direct Object References",
                "Cross-Site Request Forgery",
                "Security Misconfiguration",
                "Insecure Cryptographic Storage",
                "Failure to Restrict URL Access",
                "Insufficient Transport Layer Protection",
                "Unvalidated Redirects and Forwards"
            ],
            "2013": [
                "Injection",
                "Broken Authentication and Session Management",
                "Cross-Site Scripting",
                "Insecure Direct Object References",
                "Security Misconfiguration",
                "Sensitive Data Exposure",
                "Missing Function Level Access Control",
                "Cross-Site Request Forgery",
                "Using Components with Known Vulnerabilities",
                "Unvalidated Redirects and Forwards"
            ]
        }
        return historical_data.get(year, [])

class GitHubSecurityCollector:
    """Collects security advisory data from GitHub"""
    
    def __init__(self):
        self.token = os.getenv('GITHUB_TOKEN')
        self.headers = {'Authorization': f'token {self.token}'}
        
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
        
        response = requests.post(
            'https://api.github.com/graphql',
            json={'query': query},
            headers=self.headers
        )
        
        vulns = response.json()['data']['securityVulnerabilities']['nodes']
        return pd.DataFrame(vulns)

class CVECollector:
    """Collects CVE data from NVD"""
    
    def __init__(self):
        self.api_key = os.getenv('NVD_API_KEY')
        self.headers = {'apiKey': self.api_key} if self.api_key else {}
        self.max_retries = 3
        self.retry_delay = 5  # seconds
    
    def collect(self, days_back: int = 30) -> pd.DataFrame:
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        current_date = datetime.now().strftime("%Y-%m-%d")
        
        params = {
            'pubStartDate': f"{days_back}d",
            'pubEndDate': current_date
        }
        
        for attempt in range(self.max_retries):
            try:
                response = requests.get(base_url, params=params, headers=self.headers)
                response.raise_for_status()
                cves = response.json()['vulnerabilities']
                
                return pd.DataFrame([{
                    'id': cve['cve']['id'],
                    'description': cve['cve']['descriptions'][0]['value'],
                    'severity': cve.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', None),
                    'published': cve['cve']['published'],
                    'lastModified': cve['cve']['lastModified']
                } for cve in cves])
                
            except requests.exceptions.RequestException as e:
                if response.status_code == 403:
                    logging.warning("Rate limit exceeded for NVD API. Consider adding an API key.")
                    break  # No point retrying rate limit errors
                elif response.status_code == 401:
                    logging.error("Invalid NVD API key.")
                    break  # No point retrying auth errors
                elif response.status_code == 503 and attempt < self.max_retries - 1:
                    logging.warning(f"NVD API temporarily unavailable. Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                    continue
                else:
                    logging.error(f"Error fetching CVE data: {str(e)}")
                    break
            
        # If all retries failed or we broke out due to auth/rate limit, return empty DataFrame
        logging.warning("Failed to fetch CVE data after all attempts. Proceeding with empty dataset.")
        return pd.DataFrame(columns=['id', 'description', 'severity', 'published', 'lastModified']) 