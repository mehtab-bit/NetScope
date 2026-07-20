import os
import urllib.request
import logging
from typing import Set

logger = logging.getLogger(__name__)

class ThreatIntelFeed:
    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        self.ja3_blacklist_path = os.path.join(self.cache_dir, "ja3_fingerprints.csv")
        self.bad_ja3: Set[str] = set()
        
        # Load the blacklist on init
        self.load_blacklist()

    def load_blacklist(self):
        """Loads JA3 blacklist from local file, or downloads if missing."""
        if not os.path.exists(self.ja3_blacklist_path):
            self.update_feed()
            
        if os.path.exists(self.ja3_blacklist_path):
            try:
                with open(self.ja3_blacklist_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split(",")
                            if len(parts) > 0:
                                self.bad_ja3.add(parts[0].strip().lower())
                logger.info(f"Loaded {len(self.bad_ja3)} bad JA3 fingerprints.")
            except Exception as e:
                logger.error(f"Failed to load JA3 blacklist: {e}")

    def update_feed(self):
        """Downloads the latest JA3 blacklist from Abuse.ch."""
        url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
        try:
            logger.info(f"Downloading Threat Intel Feed from {url}...")
            # We are mocking the UA to prevent 403 Forbidden sometimes
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                with open(self.ja3_blacklist_path, 'wb') as out_file:
                    out_file.write(response.read())
            logger.info("Threat Intel Feed updated.")
        except Exception as e:
            logger.error(f"Failed to download Threat Intel Feed: {e}")

    def is_ja3_malicious(self, ja3_hash: str) -> bool:
        """Checks if a JA3 hash is in the blacklist."""
        return ja3_hash.lower() in self.bad_ja3

# Global singleton
intel_feed = None

def get_threat_intel():
    global intel_feed
    if intel_feed is None:
        intel_feed = ThreatIntelFeed(os.path.dirname(__file__))
    return intel_feed
