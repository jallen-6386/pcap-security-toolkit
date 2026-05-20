"""
Optional GeoIP and ASN enrichment for external IP addresses.

Requires the maxminddb library and a GeoLite2 database file.

Setup:
  1. pip install maxminddb
  2. Download GeoLite2-ASN.mmdb (free) from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  3. Pass the database path via --geoip-db or place GeoLite2-ASN.mmdb in the project root.

Fails silently if the library or database is not present so the tool
continues to work without GeoIP enrichment.
"""

from pathlib import Path


try:
    import maxminddb
    _HAS_MAXMINDDB = True
except ImportError:
    _HAS_MAXMINDDB = False


_EMPTY = {
    "country_iso": "",
    "country_name": "",
    "asn": "",
    "asn_org": "",
}


class GeoIPEnricher:
    def __init__(self, db_path: str | None = None):
        self._db = None
        self._available = False

        if not _HAS_MAXMINDDB:
            return

        candidates = []
        if db_path:
            candidates.append(Path(db_path))
        candidates += [
            Path("GeoLite2-ASN.mmdb"),
            Path("GeoLite2-City.mmdb"),
            Path(__file__).resolve().parent.parent / "GeoLite2-ASN.mmdb",
            Path(__file__).resolve().parent.parent / "GeoLite2-City.mmdb",
        ]

        for candidate in candidates:
            if candidate.exists():
                try:
                    self._db = maxminddb.open_database(str(candidate))
                    self._available = True
                    break
                except Exception:
                    continue

    @property
    def available(self) -> bool:
        return self._available

    def enrich(self, ip: str) -> dict:
        if not self._available or not self._db:
            return dict(_EMPTY)

        try:
            record = self._db.get(ip)
            if not record:
                return dict(_EMPTY)
        except Exception:
            return dict(_EMPTY)

        result = dict(_EMPTY)

        # GeoLite2-ASN fields
        asn_num = record.get("autonomous_system_number")
        asn_org = record.get("autonomous_system_organization", "")
        if asn_num:
            result["asn"] = str(asn_num)
        if asn_org:
            result["asn_org"] = asn_org

        # GeoLite2-City fields (country info)
        country = record.get("country", {})
        if country:
            result["country_iso"] = country.get("iso_code", "")
            names = country.get("names", {})
            result["country_name"] = names.get("en", "")

        # GeoLite2-Country fields (flat structure)
        if not result["country_iso"]:
            result["country_iso"] = record.get("country", {}).get("iso_code", "")

        return result

    def close(self):
        if self._db:
            try:
                self._db.close()
            except Exception:
                pass


def enrich_ips(ip_list: list[str], enricher: GeoIPEnricher) -> dict[str, dict]:
    """Return a mapping of IP → enrichment dict for a list of unique IPs."""
    result = {}
    for ip in ip_list:
        if ip and ip not in result:
            result[ip] = enricher.enrich(ip)
    return result
