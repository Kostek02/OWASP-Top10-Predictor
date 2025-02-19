import time
from typing import Dict, Any, List
import requests
from bs4 import BeautifulSoup
import logging
from tqdm import tqdm
import json
from pathlib import Path
import os
import gzip
from io import BytesIO

class MITRECollector:
    def __init__(self, cache_file: str = "data/mitre_data.json", cache_duration: int = 24):
        self.cache_file = cache_file
        self.cache_duration = cache_duration
        self.base_url = "https://cve.mitre.org/data/downloads/allitems.csv.gz"
        self.max_retries = 5
        self.retry_delay = 10  # seconds
        self.chunk_size = 1024 * 1024  # 1MB chunks

    def collect(self) -> List[Dict[str, Any]]:
        """Collect vulnerability data from MITRE with retry logic"""
        if self._is_cache_valid():
            return self._load_from_cache()

        for attempt in range(self.max_retries):
            try:
                data = self._fetch_data()
                if data:  # Only save if we got valid data
                    self._save_to_cache(data)
                    return data
            except Exception as e:
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (attempt + 1)  # Exponential backoff
                    logging.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    logging.error(f"Failed to collect MITRE data after {self.max_retries} attempts: {str(e)}")
                    if os.path.exists(self.cache_file):
                        logging.info("Falling back to cached data...")
                        return self._load_from_cache()
                    raise

    def _fetch_data(self) -> List[Dict[str, Any]]:
        """Fetch data from MITRE with chunked download and gzip handling"""
        session = requests.Session()
        session.headers.update({
            'Accept-Encoding': 'gzip',
            'User-Agent': 'Mozilla/5.0 (compatible; OWASP-Top10-Predictor/1.0)'
        })
        
        # Use a larger chunk size (5MB) for faster downloads
        chunk_size = 5 * 1024 * 1024
        
        try:
            response = session.get(self.base_url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            progress_bar = tqdm(total=total_size, unit='iB', unit_scale=True, desc="Downloading MITRE data")
            
            content = BytesIO()
            downloaded_size = 0
            
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    content.write(chunk)
                    downloaded_size += len(chunk)
                    progress_bar.update(len(chunk))
                    
                    # Verify download progress
                    if total_size > 0 and downloaded_size >= total_size:
                        break
            
            progress_bar.close()
            
            if downloaded_size < total_size:
                raise Exception(f"Incomplete download: {downloaded_size} of {total_size} bytes")
            
            # Decompress gzipped content
            content.seek(0)
            with gzip.GzipFile(fileobj=content) as gz:
                decompressed = gz.read().decode('utf-8')
            
            # Parse the CSV data
            return self._parse_vulnerabilities(decompressed)
            
        except Exception as e:
            logging.error(f"Error downloading MITRE data: {str(e)}")
            if os.path.exists(self.cache_file):
                logging.info("Falling back to cached data...")
                return self._load_from_cache()
            raise

    def _parse_vulnerabilities(self, data: str) -> List[Dict[str, Any]]:
        """Parse vulnerability data from CSV format"""
        vulnerabilities = []
        lines = data.split('\n')[1:]  # Skip header
        
        for line in lines:
            if not line.strip():
                continue
                
            try:
                # Parse CSV line (basic implementation - enhance based on actual format)
                fields = line.split(',')
                if len(fields) >= 3:
                    vuln = {
                        'id': fields[0].strip(),
                        'description': fields[2].strip(),
                        'published_date': fields[1].strip() if len(fields) > 1 else None,
                        'source': 'mitre'
                    }
                    vulnerabilities.append(vuln)
            except Exception as e:
                logging.warning(f"Error parsing line: {str(e)}")
                continue
        
        return vulnerabilities

    def _is_cache_valid(self) -> bool:
        """Check if cache exists and is within duration"""
        if not os.path.exists(self.cache_file):
            return False
        
        cache_age = time.time() - os.path.getmtime(self.cache_file)
        return cache_age < (self.cache_duration * 3600)

    def _load_from_cache(self) -> List[Dict[str, Any]]:
        """Load data from cache file"""
        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading cache: {str(e)}")
            return []

    def _save_to_cache(self, data: List[Dict[str, Any]]) -> None:
        """Save data to cache file"""
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        with open(self.cache_file, 'w') as f:
            json.dump(data, f) 