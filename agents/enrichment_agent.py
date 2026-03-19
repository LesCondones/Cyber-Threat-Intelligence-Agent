"""
Threat Intel Enrichment Agent

Enriches IOCs (IPs, domains, hashes) with reputation data from:
- VirusTotal: malware detection, URL/domain/IP scanning
- Shodan: open ports, services, vulnerabilities on IPs
- AbuseIPDB: IP abuse reports and confidence scores

Workflow:
    Research agent finds IOCs
        -> Enrichment agent queries external APIs
        -> Returns risk scores and reputation data
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

import requests

if TYPE_CHECKING:
    from agents.ioc_extractor import IOCResults

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentResult:
    """Result from enriching a single IOC."""
    ioc_value: str
    ioc_type: str  # "ip", "domain", "hash"
    risk_score: int = 0  # 0-100 composite score
    malicious: bool = False
    sources: Dict[str, dict] = field(default_factory=dict)
    # sources = {"virustotal": {...}, "shodan": {...}, "abuseipdb": {...}}

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 80:
            return "Critical"
        elif self.risk_score >= 60:
            return "High"
        elif self.risk_score >= 40:
            return "Medium"
        elif self.risk_score >= 20:
            return "Low"
        return "Clean"


@dataclass
class EnrichmentSummary:
    """Aggregated enrichment results for all IOCs in an investigation."""
    results: List[EnrichmentResult] = field(default_factory=list)

    @property
    def malicious_count(self) -> int:
        return sum(1 for r in self.results if r.malicious)

    @property
    def high_risk_iocs(self) -> List[EnrichmentResult]:
        return [r for r in self.results if r.risk_score >= 60]

    def to_dict(self) -> dict:
        return {
            "total_enriched": len(self.results),
            "malicious_count": self.malicious_count,
            "results": [
                {
                    "ioc": r.ioc_value,
                    "type": r.ioc_type,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level,
                    "malicious": r.malicious,
                    "sources": r.sources,
                }
                for r in self.results
            ],
        }


class EnrichmentAgent:
    """
    Enriches IOCs with threat intelligence from external APIs.

    All API calls are optional — if a key is missing or an API fails,
    the agent gracefully skips that source and continues with the rest.
    """

    def __init__(
        self,
        virustotal_api_key: str = "",
        shodan_api_key: str = "",
        abuseipdb_api_key: str = "",
    ):
        self.vt_key = virustotal_api_key
        self.shodan_key = shodan_api_key
        self.abuseipdb_key = abuseipdb_api_key
        self._session = requests.Session()
        self._session.timeout = 15

    def enrich_all(self, iocs) -> EnrichmentSummary:
        """
        Enrich all IOCs from an IOCResults object.

        Processes IPs, domains, and hashes. Skips types that have
        no entries to avoid wasted API calls.
        """
        summary = EnrichmentSummary()

        for ip in iocs.ipv4_addresses:
            result = self.enrich_ip(ip)
            if result:
                summary.results.append(result)

        for domain in iocs.domains:
            result = self.enrich_domain(domain)
            if result:
                summary.results.append(result)

        for hash_val in iocs.md5_hashes + iocs.sha256_hashes:
            result = self.enrich_hash(hash_val)
            if result:
                summary.results.append(result)

        return summary

    def enrich_ip(self, ip: str) -> Optional[EnrichmentResult]:
        """Enrich an IP address using all available sources."""
        result = EnrichmentResult(ioc_value=ip, ioc_type="ip")
        scores = []

        # VirusTotal
        if self.vt_key:
            vt_data = self._virustotal_ip(ip)
            if vt_data:
                result.sources["virustotal"] = vt_data
                scores.append(vt_data.get("risk_score", 0))

        # Shodan
        if self.shodan_key:
            shodan_data = self._shodan_ip(ip)
            if shodan_data:
                result.sources["shodan"] = shodan_data
                scores.append(shodan_data.get("risk_score", 0))

        # AbuseIPDB
        if self.abuseipdb_key:
            abuse_data = self._abuseipdb_check(ip)
            if abuse_data:
                result.sources["abuseipdb"] = abuse_data
                scores.append(abuse_data.get("risk_score", 0))

        if scores:
            result.risk_score = max(scores)
            result.malicious = result.risk_score >= 50
        else:
            return None

        return result

    def enrich_domain(self, domain: str) -> Optional[EnrichmentResult]:
        """Enrich a domain using VirusTotal."""
        result = EnrichmentResult(ioc_value=domain, ioc_type="domain")

        if self.vt_key:
            vt_data = self._virustotal_domain(domain)
            if vt_data:
                result.sources["virustotal"] = vt_data
                result.risk_score = vt_data.get("risk_score", 0)
                result.malicious = result.risk_score >= 50
                return result

        return None

    def enrich_hash(self, file_hash: str) -> Optional[EnrichmentResult]:
        """Enrich a file hash using VirusTotal."""
        result = EnrichmentResult(ioc_value=file_hash, ioc_type="hash")

        if self.vt_key:
            vt_data = self._virustotal_hash(file_hash)
            if vt_data:
                result.sources["virustotal"] = vt_data
                result.risk_score = vt_data.get("risk_score", 0)
                result.malicious = result.risk_score >= 50
                return result

        return None

    # ── VirusTotal API ──

    def _virustotal_ip(self, ip: str) -> Optional[dict]:
        """Query VirusTotal for IP reputation."""
        try:
            resp = self._session.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_key},
            )
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            score = int((malicious / total) * 100)
            return {
                "risk_score": score,
                "malicious_detections": malicious,
                "total_engines": total,
                "country": data.get("country", "Unknown"),
                "as_owner": data.get("as_owner", "Unknown"),
                "reputation": data.get("reputation", 0),
            }
        except Exception as e:
            logger.warning(f"VirusTotal IP lookup failed for {ip}: {e}")
            return None

    def _virustotal_domain(self, domain: str) -> Optional[dict]:
        """Query VirusTotal for domain reputation."""
        try:
            resp = self._session.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self.vt_key},
            )
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            score = int((malicious / total) * 100)
            return {
                "risk_score": score,
                "malicious_detections": malicious,
                "total_engines": total,
                "registrar": data.get("registrar", "Unknown"),
                "creation_date": str(data.get("creation_date", "")),
                "reputation": data.get("reputation", 0),
            }
        except Exception as e:
            logger.warning(f"VirusTotal domain lookup failed for {domain}: {e}")
            return None

    def _virustotal_hash(self, file_hash: str) -> Optional[dict]:
        """Query VirusTotal for file hash reputation."""
        try:
            resp = self._session.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self.vt_key},
            )
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            score = int((malicious / total) * 100)
            return {
                "risk_score": score,
                "malicious_detections": malicious,
                "total_engines": total,
                "file_type": data.get("type_description", "Unknown"),
                "file_name": data.get("meaningful_name", "Unknown"),
                "tags": data.get("tags", [])[:5],
            }
        except Exception as e:
            logger.warning(f"VirusTotal hash lookup failed for {file_hash}: {e}")
            return None

    # ── Shodan API ──

    def _shodan_ip(self, ip: str) -> Optional[dict]:
        """Query Shodan for IP host information."""
        try:
            resp = self._session.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.shodan_key},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            vulns = data.get("vulns", [])
            open_ports = data.get("ports", [])
            # Risk heuristic: more vulns and open ports = higher risk
            vuln_score = min(len(vulns) * 15, 70)
            port_score = min(len(open_ports) * 5, 30)
            score = min(vuln_score + port_score, 100)
            return {
                "risk_score": score,
                "open_ports": open_ports[:20],
                "vulns": vulns[:10],
                "os": data.get("os", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "city": data.get("city", "Unknown"),
                "country_name": data.get("country_name", "Unknown"),
                "hostnames": data.get("hostnames", [])[:5],
            }
        except Exception as e:
            logger.warning(f"Shodan lookup failed for {ip}: {e}")
            return None

    # ── AbuseIPDB API ──

    def _abuseipdb_check(self, ip: str) -> Optional[dict]:
        """Query AbuseIPDB for IP abuse reports."""
        try:
            resp = self._session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {})
            return {
                "risk_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "country_code": data.get("countryCode", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"),
            }
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
            return None
