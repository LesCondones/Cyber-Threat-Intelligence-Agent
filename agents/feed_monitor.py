"""
Real-Time Feed Monitoring Agent

Ingests threat intelligence from:
- CISA alerts (RSS)
- NVD CVE feeds (API)
- Security blogs (RSS)

Transforms the system from manual research to automated CTI monitoring.

Usage:
    monitor = FeedMonitor()
    alerts = monitor.check_all_feeds()
    cves = monitor.check_cve_feed(keyword="ransomware")
"""

import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class FeedAlert:
    """A single alert from a threat intel feed."""
    title: str
    description: str
    link: str
    source: str
    published: str = ""
    severity: str = "Unknown"
    cve_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class CVEEntry:
    """A single CVE entry from NVD."""
    cve_id: str
    description: str
    severity: str = "Unknown"
    cvss_score: float = 0.0
    published: str = ""
    references: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "published": self.published,
            "references": self.references,
            "affected_products": self.affected_products,
        }


# Default RSS feeds for threat intelligence
DEFAULT_FEEDS = {
    "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "CISA KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "US-CERT": "https://www.us-cert.gov/ncas/alerts.xml",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Threatpost": "https://threatpost.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}


class FeedMonitor:
    """
    Monitors security RSS feeds and CVE databases for new threats.

    Designed for periodic polling — call check_all_feeds() on a schedule
    to get new alerts since the last check.
    """

    def __init__(self, feeds: Optional[Dict[str, str]] = None):
        self.feeds = feeds or DEFAULT_FEEDS
        self._session = requests.Session()
        self._session.timeout = 20
        self._session.headers.update({
            "User-Agent": "CTI-Monitor/1.0 (Threat Intelligence Research)"
        })

    def check_all_feeds(self, max_per_feed: int = 5) -> List[FeedAlert]:
        """
        Check all configured RSS feeds and return recent alerts.

        Args:
            max_per_feed: Maximum number of alerts to return per feed.
        """
        all_alerts = []
        for name, url in self.feeds.items():
            if url.endswith(".json"):
                alerts = self._check_json_feed(name, url, max_per_feed)
            else:
                alerts = self._check_rss_feed(name, url, max_per_feed)
            all_alerts.extend(alerts)
            if alerts:
                print(f"   {name}: {len(alerts)} alerts")
        return all_alerts

    def check_cve_feed(
        self,
        keyword: Optional[str] = None,
        days_back: int = 7,
        max_results: int = 20,
    ) -> List[CVEEntry]:
        """
        Query NVD for recent CVEs, optionally filtered by keyword.

        Uses the NVD 2.0 API (no API key required, but rate-limited).
        """
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        pub_start = (datetime.utcnow() - timedelta(days=days_back)).strftime(
            "%Y-%m-%dT00:00:00.000"
        )
        pub_end = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")

        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": max_results,
        }
        if keyword:
            params["keywordSearch"] = keyword

        try:
            resp = self._session.get(base_url, params=params)
            if resp.status_code != 200:
                logger.warning(f"NVD API returned {resp.status_code}")
                return []
            data = resp.json()
        except Exception as e:
            logger.warning(f"NVD API call failed: {e}")
            return []

        entries = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            # Get description (English preferred)
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # Get CVSS score and severity
            cvss_score = 0.0
            severity = "Unknown"
            metrics = cve_data.get("metrics", {})
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    cvss_data = metrics[version][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "Unknown")
                    break

            # Get references
            refs = [
                r.get("url", "")
                for r in cve_data.get("references", [])[:5]
            ]

            # Get affected products from CPE configurations
            products = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor_product = f"{parts[3]}:{parts[4]}"
                            if vendor_product not in products:
                                products.append(vendor_product)

            entries.append(CVEEntry(
                cve_id=cve_id,
                description=desc,
                severity=severity,
                cvss_score=cvss_score,
                published=cve_data.get("published", ""),
                references=refs,
                affected_products=products[:10],
            ))

        return entries

    def _check_rss_feed(
        self, name: str, url: str, max_items: int
    ) -> List[FeedAlert]:
        """Parse an RSS/Atom feed and return alerts."""
        try:
            resp = self._session.get(url)
            if resp.status_code != 200:
                logger.warning(f"Feed {name} returned {resp.status_code}")
                return []

            root = ET.fromstring(resp.content)

            # Handle both RSS 2.0 and Atom formats
            alerts = []
            ns = {"atom": "http://www.w3.org/2005/Atom"}

            # RSS 2.0 format
            for item in root.findall(".//item")[:max_items]:
                title = item.findtext("title", "")
                desc = item.findtext("description", "")
                link = item.findtext("link", "")
                pub_date = item.findtext("pubDate", "")

                alerts.append(FeedAlert(
                    title=title.strip(),
                    description=desc.strip()[:500],
                    link=link.strip(),
                    source=name,
                    published=pub_date,
                ))

            # Atom format fallback
            if not alerts:
                for entry in root.findall(".//atom:entry", ns)[:max_items]:
                    title = entry.findtext("atom:title", "", ns)
                    desc = entry.findtext("atom:summary", "", ns)
                    link_el = entry.find("atom:link", ns)
                    link = link_el.get("href", "") if link_el is not None else ""
                    pub_date = entry.findtext("atom:published", "", ns)

                    alerts.append(FeedAlert(
                        title=title.strip(),
                        description=desc.strip()[:500],
                        link=link.strip(),
                        source=name,
                        published=pub_date,
                    ))

            return alerts

        except Exception as e:
            logger.warning(f"Failed to parse feed {name}: {e}")
            return []

    def _check_json_feed(
        self, name: str, url: str, max_items: int
    ) -> List[FeedAlert]:
        """Parse a JSON feed (e.g., CISA KEV)."""
        try:
            resp = self._session.get(url)
            if resp.status_code != 200:
                return []

            data = resp.json()
            alerts = []

            # Handle CISA KEV format
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities[:max_items]:
                cve_id = vuln.get("cveID", "")
                alerts.append(FeedAlert(
                    title=f"{cve_id}: {vuln.get('vulnerabilityName', '')}",
                    description=(
                        f"Product: {vuln.get('product', 'Unknown')} | "
                        f"Vendor: {vuln.get('vendorProject', 'Unknown')} | "
                        f"Action: {vuln.get('requiredAction', 'Unknown')}"
                    ),
                    link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    source=name,
                    published=vuln.get("dateAdded", ""),
                    cve_ids=[cve_id] if cve_id else [],
                ))

            return alerts

        except Exception as e:
            logger.warning(f"Failed to parse JSON feed {name}: {e}")
            return []
