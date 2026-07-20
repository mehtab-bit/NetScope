import os
import geoip2.database
import logging

logger = logging.getLogger(__name__)

class GeoIPLookup:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.reader = None
        
        if os.path.exists(self.db_path):
            try:
                self.reader = geoip2.database.Reader(self.db_path)
                logger.info("GeoIP database loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")
        else:
            logger.warning(f"GeoIP database not found at {self.db_path}")

    def lookup_ip(self, ip_address: str) -> dict:
        """Returns Country and City for a given IP."""
        if not self.reader:
            return {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}
            
        try:
            response = self.reader.city(ip_address)
            return {
                "country": response.country.name or "Unknown",
                "countryCode": response.country.iso_code or "",
                "city": response.city.name or "Unknown",
                "lat": response.location.latitude or 0.0,
                "lon": response.location.longitude or 0.0
            }
        except geoip2.errors.AddressNotFoundError:
            return {"country": "Unknown", "countryCode": "", "city": "Unknown", "lat": 0.0, "lon": 0.0}
        except Exception as e:
            return {"country": "Unknown", "countryCode": "", "city": "Unknown", "lat": 0.0, "lon": 0.0}

    def close(self):
        if self.reader:
            self.reader.close()

# Singleton
_geoip = None

def get_geoip():
    global _geoip
    if _geoip is None:
        db_path = os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb")
        _geoip = GeoIPLookup(db_path)
    return _geoip
