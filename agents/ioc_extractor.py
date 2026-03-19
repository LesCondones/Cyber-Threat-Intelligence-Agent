import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Set
from uuid import uuid4


@dataclass
class IOCResults:
    """Container for extracted Indicators of Compromise (IOCs)."""
    ipv4_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    md5_hashes: List[str] = field(default_factory=list)
    sha256_hashes: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    malware_names: List[str] = field(default_factory=list)

    def has_any(self) -> bool:
        """Return True if any IOC type has entries."""
        return any([
            self.ipv4_addresses, self.domains, self.urls,
            self.md5_hashes, self.sha256_hashes, self.cve_ids,
            self.emails, self.malware_names,
        ])

    def to_stix_bundle(self) -> dict:
        """
        Export IOCs as a STIX 2.1 bundle.

        STIX (Structured Threat Information Expression) is the standard
        format for sharing cyber threat intelligence. This produces a
        valid STIX 2.1 JSON bundle that can be imported by TAXII servers,
        MISP, OpenCTI, and other CTI platforms.
        """
        objects = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for ip in self.ipv4_addresses:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid4()}",
                "created": now,
                "modified": now,
                "name": f"Malicious IP: {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
            })

        for domain in self.domains:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid4()}",
                "created": now,
                "modified": now,
                "name": f"Malicious Domain: {domain}",
                "pattern": f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
            })

        for url in self.urls:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid4()}",
                "created": now,
                "modified": now,
                "name": f"Malicious URL: {url}",
                "pattern": f"[url:value = '{url}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
            })

        for md5 in self.md5_hashes:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid4()}",
                "created": now,
                "modified": now,
                "name": f"Malicious File (MD5): {md5}",
                "pattern": f"[file:hashes.MD5 = '{md5}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
            })

        for sha256 in self.sha256_hashes:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid4()}",
                "created": now,
                "modified": now,
                "name": f"Malicious File (SHA-256): {sha256}",
                "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
            })

        for cve in self.cve_ids:
            objects.append({
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid4()}",
                "created": now,
                "modified": now,
                "name": cve,
                "external_references": [{
                    "source_name": "cve",
                    "external_id": cve,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                }],
            })

        for malware in self.malware_names:
            objects.append({
                "type": "malware",
                "spec_version": "2.1",
                "id": f"malware--{uuid4()}",
                "created": now,
                "modified": now,
                "name": malware,
                "is_family": True,
                "malware_types": ["unknown"],
            })

        return {
            "type": "bundle",
            "id": f"bundle--{uuid4()}",
            "objects": objects,
        }


class IOCExtractor:
    """Extract Indicators of Compromise (IOCs) from text using regex patterns."""
    # Each pattern targets a specific type of IOC
    PATTERNS = {
        # Matches IPv4 like 192.168.1.1 — each octet 0-255
        "ipv4": re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        # Matches domains like evil.example.com — but not common benign ones
        "domain": re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
            r'+(?:com|net|org|io|ru|cn|xyz|top|tk|info|biz)\b'
        ),
        # URLs with http/https
        "url": re.compile(
            r'https?://[^\s<>"\')\]}{,]+',
        ),
        # MD5 = exactly 32 hex chars
        "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
        # SHA-256 = exactly 64 hex chars
        "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
        # CVE format: CVE-YYYY-NNNNN
        "cve": re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE),
        # Basic email pattern
        "email": re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
    }

    # Known malware families — matched case-insensitively as whole words
    KNOWN_MALWARE = [
        "LockBit", "BlackCat", "ALPHV", "Conti", "REvil", "Sodinokibi",
        "DarkSide", "Ryuk", "Emotet", "TrickBot", "QakBot", "QBot",
        "Cobalt Strike", "Mimikatz", "Metasploit", "BazarLoader",
        "IcedID", "Dridex", "Agent Tesla", "FormBook", "Remcos",
        "AsyncRAT", "NjRAT", "RedLine", "Raccoon Stealer", "Vidar",
        "StealC", "LummaC2", "Akira", "Royal", "Black Basta",
        "Cl0p", "Clop", "Play", "Medusa", "BianLian", "NoEscape",
        "Rhysida", "Hunters International", "8Base", "BlackSuit",
        "WannaCry", "NotPetya", "Stuxnet", "SolarWinds", "Sunburst",
        "Log4Shell", "ProxyShell", "ProxyLogon", "Hafnium",
        "Snake", "Turla", "APT28", "APT29", "Fancy Bear", "Cozy Bear",
        "Lazarus", "Kimsuky", "Sandworm", "Volt Typhoon", "Salt Typhoon",
    ]

    # Domains to ignore — these show up in search results but aren't threats
    DOMAIN_WHITELIST = {
        "google.com", "github.com", "wikipedia.org", "microsoft.com",
        "twitter.com", "linkedin.com", "youtube.com", "reddit.com",
        "x.com", "facebook.com", "apple.com", "amazon.com",
        "cloudflare.com", "akamai.com", "googleapis.com",
    }

    # URLs to ignore — common benign URLs from search results
    URL_WHITELIST_DOMAINS = {
        "google.com", "github.com", "wikipedia.org", "microsoft.com",
        "twitter.com", "linkedin.com", "youtube.com", "reddit.com",
        "x.com", "facebook.com", "apple.com", "amazon.com",
        "cisa.gov", "nist.gov", "mitre.org", "nvd.nist.gov",
    }

    def extract(self, text: str) -> IOCResults:
        """
        Scan text for all IOC types and return deduplicated results.

        Why sets? A single report might mention the same IP dozens of times.
        We convert to sorted lists at the end for consistent output.
        """
        results = IOCResults()

        # For each IOC type, findall matches, deduplicate with a set
        ipv4s: Set[str] = set(self.PATTERNS["ipv4"].findall(text))
        results.ipv4_addresses = sorted(ipv4s)

        domains: Set[str] = set(self.PATTERNS["domain"].findall(text))
        # Filter out benign domains that would just be noise
        domains -= self.DOMAIN_WHITELIST
        results.domains = sorted(domains)

        # Extract URLs, filter out benign ones
        urls: Set[str] = set(self.PATTERNS["url"].findall(text))
        filtered_urls = set()
        for url in urls:
            # Skip URLs from whitelisted domains
            is_benign = False
            for wd in self.URL_WHITELIST_DOMAINS:
                if wd in url:
                    is_benign = True
                    break
            if not is_benign:
                # Clean trailing punctuation
                url = url.rstrip(".,;:!?)")
                filtered_urls.add(url)
        results.urls = sorted(filtered_urls)

        results.md5_hashes = sorted(set(self.PATTERNS["md5"].findall(text)))
        results.sha256_hashes = sorted(set(self.PATTERNS["sha256"].findall(text)))

        # Normalize CVEs to uppercase for consistency
        cves = set(c.upper() for c in self.PATTERNS["cve"].findall(text))
        results.cve_ids = sorted(cves)

        results.emails = sorted(set(self.PATTERNS["email"].findall(text)))

        # Extract malware names by checking against known families
        malware_found: Set[str] = set()
        text_lower = text.lower()
        for malware in self.KNOWN_MALWARE:
            if malware.lower() in text_lower:
                malware_found.add(malware)
        results.malware_names = sorted(malware_found)

        return results
