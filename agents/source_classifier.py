"""
Deterministic source-type classifier.

Maps a URL or domain to a coarse intelligence source type and a corresponding
reliability hint, so the report can tag each source with its provenance
without spending an LLM call.

Categories follow common CTI source-grading practice:
- Gov / CERT       — official government and national CERT advisories
- Vendor           — security vendor advisories and threat-intel publications
- Research         — academic and security-research outlets
- News             — mainstream / tech news outlets
- Blog / Community — independent blogs, GitHub, forums
- Unknown          — domain not matched
"""

from dataclasses import dataclass
from typing import Tuple
from urllib.parse import urlparse


@dataclass
class SourceTag:
    category: str
    reliability_hint: str  # short Admiralty-style hint


_GOV_PATTERNS = (
    ".gov", ".gov.uk", ".gc.ca", ".gov.au", ".europa.eu",
    "cisa.gov", "ncsc.gov.uk", "nvd.nist.gov", "cert.org",
    "us-cert.cisa.gov", "kb.cert.org", "enisa.europa.eu",
)

_VENDOR_PATTERNS = (
    "microsoft.com", "mandiant.com", "crowdstrike.com", "sentinelone.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com", "fireeye.com",
    "cisco.com", "talosintelligence.com", "ibm.com", "kaspersky.com",
    "trendmicro.com", "symantec.com", "broadcom.com", "fortinet.com",
    "fortiguard.com", "check-point.com", "checkpoint.com", "sophos.com",
    "eset.com", "bitdefender.com", "rapid7.com", "tenable.com",
    "qualys.com", "proofpoint.com", "trellix.com", "cloudflare.com",
    "akamai.com", "google.com/security", "cloud.google.com",
    "secureworks.com", "recordedfuture.com", "intel471.com",
    "censys.io", "shodan.io", "virustotal.com", "abuseipdb.com",
    "huntress.com", "darktrace.com", "wiz.io", "snyk.io", "github.blog",
)

_RESEARCH_PATTERNS = (
    "arxiv.org", "usenix.org", "ieee.org", "acm.org", "sans.org",
    "isc.sans.edu", "schneier.com",
)

_NEWS_PATTERNS = (
    "bleepingcomputer.com", "thehackernews.com", "krebsonsecurity.com",
    "darkreading.com", "securityweek.com", "scmagazine.com",
    "infosecurity-magazine.com", "cyberscoop.com", "therecord.media",
    "wired.com", "arstechnica.com", "reuters.com", "bloomberg.com",
    "nytimes.com", "wsj.com", "ft.com", "theguardian.com",
    "techcrunch.com", "zdnet.com", "cnet.com",
)

_BLOG_PATTERNS = (
    "medium.com", "substack.com", "wordpress.com", "blogspot.com",
    "github.com", "gist.github.com", "reddit.com", "twitter.com",
    "x.com", "linkedin.com",
)


def _hostname(url_or_domain: str) -> str:
    if "://" in url_or_domain:
        host = urlparse(url_or_domain).netloc.lower()
    else:
        host = url_or_domain.lower().strip("/")
    if host.startswith("www."):
        host = host[4:]
    return host


def classify_source(url_or_domain: str) -> SourceTag:
    """Return a deterministic source category and reliability hint."""
    if not url_or_domain:
        return SourceTag("Unknown", "F - Cannot judge")

    host = _hostname(url_or_domain)

    for pattern in _GOV_PATTERNS:
        if pattern in host:
            return SourceTag("Gov / CERT", "A - Reliable")
    for pattern in _VENDOR_PATTERNS:
        if pattern in host:
            return SourceTag("Vendor", "B - Usually reliable")
    for pattern in _RESEARCH_PATTERNS:
        if pattern in host:
            return SourceTag("Research", "B - Usually reliable")
    for pattern in _NEWS_PATTERNS:
        if pattern in host:
            return SourceTag("News", "C - Fairly reliable")
    for pattern in _BLOG_PATTERNS:
        if pattern in host:
            return SourceTag("Blog / Community", "D - Not usually reliable")

    return SourceTag("Unknown", "F - Cannot judge")
