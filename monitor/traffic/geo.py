"""Country / ASN lookup from MaxMind-format (.mmdb) databases. Works with the bundled GeoLite2 files and with user-supplied
databases (GeoLite2, IPinfo Lite ...). Everything is optional: with no database or no `maxminddb` module lookups return empty."""
import os
import threading

try:
    import maxminddb
except Exception:                       # module missing: geo features simply stay empty
    maxminddb = None

DATA = os.path.join(os.path.dirname(__file__), "data", "geo")
COUNTRY_NAMES = {}                      # filled lazily from the database itself (names.en)


class GeoDb:
    def __init__(self):
        self._lock = threading.Lock()
        self.country = self.asn = None
        self.country_path = self.asn_path = ""
        self.errors = []

    def load(self, country_path=None, asn_path=None):
        """(Re)open the databases. A custom path that is empty, missing or not a valid database falls back to the bundled file
        (like Sniffnet) and the problem is reported in status()['errors']. Returns status dict."""
        self.errors = []
        with self._lock:
            self.country = self._open(country_path, os.path.join(DATA, "GeoLite2-Country.mmdb"), "country")
            self.asn = self._open(asn_path, os.path.join(DATA, "GeoLite2-ASN.mmdb"), "asn")
        return self.status()

    def _open(self, custom, default, what):
        if maxminddb is None:
            self.errors.append("python module 'maxminddb' is not installed"); return None
        for path, is_custom in ((custom, True), (default, False)):
            if not path: continue
            if not os.path.isfile(path):
                if is_custom: self.errors.append(f"{what} database not found, using the bundled one: {path}")
                continue
            try:
                r = maxminddb.open_database(path)
            except Exception as e:
                if is_custom: self.errors.append(f"{what} database is not a valid .mmdb file, using the bundled one: {path} ({e})")
                continue
            if what == "country": self.country_path = path
            else: self.asn_path = path
            return r
        self.errors.append(f"no {what} database available")
        return None

    def status(self):
        return {"country": bool(self.country), "asn": bool(self.asn), "country_path": self.country_path if self.country else "",
                "asn_path": self.asn_path if self.asn else "", "errors": list(self.errors)}

    def lookup(self, ip):
        """-> (country_code, country_name, asn_number, asn_name). Understands GeoLite2 and IPinfo (asn / lite / location) records."""
        cc = cn = an = ""; asn = 0
        try:
            if self.country:
                r = self.country.get(ip) or {}
                c = r.get("country") if isinstance(r.get("country"), dict) else (r.get("registered_country") or {})
                cc = (c.get("iso_code") if isinstance(c, dict) else None) or r.get("country_code") or ""
                cn = ((c.get("names") or {}).get("en") if isinstance(c, dict) else None) or (r.get("country") if isinstance(r.get("country"), str) else "") or ""
            if self.asn:
                r = self.asn.get(ip) or {}
                raw = r.get("autonomous_system_number") if r.get("autonomous_system_number") is not None else r.get("asn", 0)
                asn = int(str(raw).upper().replace("AS", "") or 0)
                an = r.get("autonomous_system_organization") or r.get("as_name") or r.get("name") or ""
        except Exception:
            pass
        return (cc or "", cn or "", asn, an or "")
