import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Set, Tuple
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

    PATTERNS = {
        "ipv4": re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        "domain": re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
            r'+(?:com|net|org|io|ru|cn|xyz|top|tk|info|biz)\b'
        ),
        "url": re.compile(
            r'https?://[^\s<>"\')\]}{,]+',
        ),
        "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
        "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
        "cve": re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE),
        "email": re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
    }

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

    # Comprehensive whitelist of benign domains that appear in search results
    # but are NOT threat indicators. Organized by category.
    DOMAIN_WHITELIST = {
        # Major platforms & social media
        "google.com", "github.com", "wikipedia.org", "microsoft.com",
        "twitter.com", "linkedin.com", "youtube.com", "reddit.com",
        "x.com", "facebook.com", "apple.com", "amazon.com",
        "instagram.com", "tiktok.com", "pinterest.com", "tumblr.com",
        "whatsapp.com", "telegram.org", "discord.com", "slack.com",
        "medium.com", "substack.com", "wordpress.com", "blogger.com",
        "zoom.us", "dropbox.com", "box.com", "notion.so",
        "stackoverflow.com", "stackexchange.com", "quora.com",
        "archive.org", "web.archive.org", "wikimedia.org",

        # CDNs, cloud & infrastructure
        "cloudflare.com", "akamai.com", "googleapis.com",
        "cloudfront.net", "akamaized.net", "fastly.net",
        "azureedge.net", "azure.com", "azure.microsoft.com",
        "s3.amazonaws.com", "aws.amazon.com", "storage.googleapis.com",
        "gstatic.com", "gcloud.com", "digitalocean.com",
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
        "fontawesome.com", "bootstrapcdn.com",
        "fonts.googleapis.com", "fonts.gstatic.com",
        "cloudflare-dns.com",

        # Analytics, tracking & ads
        "googletagmanager.com", "google-analytics.com",
        "googlesyndication.com", "doubleclick.net",
        "hotjar.com", "mixpanel.com", "segment.com", "amplitude.com",
        "hubspot.com", "marketo.com", "mailchimp.com", "sendgrid.net",
        "intercom.io", "crisp.chat", "zendesk.com",
        "outbrain.com", "taboola.com", "adroll.com", "adsrvr.org",
        "onetrust.com", "cookiebot.com", "trustarc.com",

        # Security vendors & CTI sources (these are sources, not IOCs)
        "bleepingcomputer.com", "therecord.media", "darkreading.com",
        "securityweek.com", "thehackernews.com", "hackernews.com",
        "krebsonsecurity.com", "threatpost.com", "securityaffairs.com",
        "cyberscoop.com", "infosecurity-magazine.com", "csoonline.com",
        "scmagazine.com", "hackread.com", "cyberpress.org",
        "thecyberexpress.com", "industrialcyber.co",
        "checkpoint.com", "research.checkpoint.com",
        "cyble.com", "mandiant.com", "crowdstrike.com",
        "sentinelone.com", "paloaltonetworks.com", "trendmicro.com",
        "kaspersky.com", "sophos.com", "eset.com", "malwarebytes.com",
        "symantec.com", "mcafee.com", "fortinet.com", "fireeye.com",
        "proofpoint.com", "zscaler.com", "recordedfuture.com",
        "virustotal.com", "hybrid-analysis.com", "any.run",
        "urlscan.io", "shodan.io", "censys.io", "greynoise.io",
        "alienvault.com", "intezer.com", "threatconnect.com",
        "anomali.com", "flashpoint.io", "intel471.com",
        "socradar.io", "cyfirma.com", "cyberint.com",
        "constella.ai", "halcyon.ai", "vectra.ai",
        "extrahop.com", "elisity.com", "cymulate.com",
        "pushsecurity.com", "sisainfosec.com", "levelblue.com",
        "splunk.com", "elastic.co", "tenable.com", "rapid7.com",
        "qualys.com", "snyk.io", "sonarqube.org",
        "unit42.paloaltonetworks.com",

        # Government, standards & research
        "cisa.gov", "us-cert.gov", "nist.gov", "mitre.org",
        "nvd.nist.gov", "cert.org", "enisa.europa.eu", "ncsc.gov.uk",
        "cyber.gov.au", "ic3.gov", "fbi.gov", "justice.gov",
        "sec.gov", "whitehouse.gov", "state.gov",
        "ict.org.il", "w3.org",

        # News & media
        "reuters.com", "bbc.com", "bbc.co.uk", "cnn.com",
        "nytimes.com", "washingtonpost.com", "theguardian.com",
        "wired.com", "arstechnica.com", "techcrunch.com",
        "zdnet.com", "theregister.com", "techtarget.com",
        "politico.com", "haaretz.com", "jpost.com", "ynet.co.il",
        "sun-sentinel.com", "britannica.com",

        # Dev tools & SaaS
        "atlassian.com", "jira.com", "confluence.com",
        "bitbucket.org", "gitlab.com", "npmjs.com",
        "pypi.org", "rubygems.org", "docker.com", "hub.docker.com",
        "readthedocs.io", "docs.python.org",

        # Ad / tracking pixel domains commonly embedded in pages
        "d.adroll.com", "miro.medium.com", "cdn.prod.website-files.com",
        "lh7-rt.googleusercontent.com", "insight.adsrvr.org",

        # Misc benign
        "hackerone.com", "bugcrowd.com", "rewardsforjustice.net",
        "donate.wikimedia.org", "foundation.wikimedia.org",
        "gnet-research.org", "bellingcat.com",
        "undercodenews.com", "infosecwriteups.com",
        "securityboulevard.com",
        "swktech.com", "autoitscript.com",
        "adl.org", "jiss.org.il",
        "imgur.com", "pastebin.com",
        "status.medium.com", "note.com",
    }

    # URL whitelist uses the same set — no reason to maintain two lists
    URL_WHITELIST_DOMAINS = DOMAIN_WHITELIST

    # URL path patterns that indicate navigation/UI elements, not threat IOCs
    URL_NOISE_PATH_PATTERNS = re.compile(
        r'(?:'
        r'/sign[_-]?(?:in|up|out)|/log[_-]?(?:in|out)|/register|/auth(?:enticate)?'
        r'|/cookie|/privacy|/terms|/legal|/tos|/gdpr|/consent'
        r'|/careers|/jobs|/about[_-]?us|/contact[_-]?us|/team'
        r'|/tag/|/category/|/archive/|/page/\d'
        r'|/search\?|/wp-content/|/wp-includes/|/wp-json/'
        r'|/assets/|/static/|/images/|/img/|/icons/|/fonts/'
        r'|/css/|/js/|/dist/|/build/|/bundle'
        r'|/resize:|/thumbnail|/avatar|/profile[_-]?pic'
        r'|/widget|/embed|/iframe|/pixel|/beacon'
        r'|/unsubscribe|/preferences|/newsletter|/subscribe'
        r'|/share\?|/sharer|/intent/tweet'
        r'|/feed/?$|/rss/?$|/atom/?$|/sitemap'
        r'|/themes/|/plugins/|/modules/'
        r'|/hubfs/|/uploaded-files/'
        r'|\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|webp)(?:\?|$)'
        r')',
        re.IGNORECASE,
    )

    # Email prefixes that are generic contact addresses, not threat actor emails
    EMAIL_NOISE_PREFIXES = re.compile(
        r'^(?:'
        r'info|contact|support|admin|sales|marketing'
        r'|noreply|no-reply|donotreply|newsletter'
        r'|press|media|feedback|help|hello|team'
        r'|webmaster|postmaster|abuse|privacy'
        r'|careers|jobs|billing|legal|compliance'
        r')@',
        re.IGNORECASE,
    )

    # Private/reserved IPv4 ranges
    _PRIVATE_IP_PATTERNS = [
        re.compile(r'^10\.'),
        re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
        re.compile(r'^192\.168\.'),
        re.compile(r'^127\.'),
        re.compile(r'^0\.'),
        re.compile(r'^169\.254\.'),
        re.compile(r'^255\.'),
        re.compile(r'^224\.'),  # multicast
    ]

    # Context pattern for version numbers preceding an IP-like string
    _VERSION_CONTEXT = re.compile(r'(?:version|ver|v)[\s.:]*$', re.IGNORECASE)

    def _is_whitelisted_domain(self, domain: str) -> bool:
        """Check if domain or any parent domain is in the whitelist."""
        domain_lower = domain.lower()
        if domain_lower in self.DOMAIN_WHITELIST:
            return True
        parts = domain_lower.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.DOMAIN_WHITELIST:
                return True
        return False

    def _is_private_ip(self, ip: str) -> bool:
        """Return True if IP is in a private/reserved range."""
        return any(pat.match(ip) for pat in self._PRIVATE_IP_PATTERNS)

    def _extract_ipv4s(self, text: str) -> Set[str]:
        """Extract IPv4 addresses, excluding private ranges and version numbers."""
        ips = set()
        for m in self.PATTERNS["ipv4"].finditer(text):
            ip = m.group()
            if self._is_private_ip(ip):
                continue
            prefix = text[max(0, m.start() - 15):m.start()]
            if self._VERSION_CONTEXT.search(prefix):
                continue
            ips.add(ip)
        return ips

    def _get_url_spans(self, text: str) -> List[Tuple[int, int]]:
        """Get (start, end) spans of all URLs in the text."""
        return [(m.start(), m.end()) for m in self.PATTERNS["url"].finditer(text)]

    def _is_inside_url(self, pos: int, url_spans: List[Tuple[int, int]]) -> bool:
        """Check if a position falls inside any URL span."""
        for us, ue in url_spans:
            if us <= pos < ue:
                return True
            if us > pos:
                break  # spans are sorted, no need to check further
        return False

    def _looks_like_real_hash(self, hex_str: str) -> bool:
        """Reject hex strings that are unlikely to be real file hashes."""
        s = hex_str.lower()
        if len(set(s)) <= 2:
            return False
        if s.count('0') > len(s) * 0.7 or s.count('f') > len(s) * 0.7:
            return False
        return True

    def _extract_hashes(
        self, text: str, pattern_key: str, url_spans: List[Tuple[int, int]]
    ) -> Set[str]:
        """Extract hex hashes, filtering out those embedded in URLs."""
        hashes = set()
        for m in self.PATTERNS[pattern_key].finditer(text):
            if self._is_inside_url(m.start(), url_spans):
                continue
            h = m.group()
            if self._looks_like_real_hash(h):
                hashes.add(h)
        return hashes

    def extract(self, text: str) -> IOCResults:
        """
        Scan text for all IOC types and return deduplicated, filtered results.

        Applies multiple layers of filtering to remove web page noise:
        - Domain/URL whitelisting with subdomain matching
        - URL path noise pattern rejection
        - Private IP range filtering
        - Context-aware hash extraction (skip hashes inside URLs)
        - Email noise prefix filtering
        """
        results = IOCResults()

        # IPv4 — filter private ranges and version numbers
        results.ipv4_addresses = sorted(self._extract_ipv4s(text))

        # Domains — filter whitelisted (with subdomain matching)
        domains: Set[str] = set(self.PATTERNS["domain"].findall(text))
        domains = {d for d in domains if not self._is_whitelisted_domain(d)}
        results.domains = sorted(domains)

        # URLs — filter whitelisted domains and noisy path patterns
        urls: Set[str] = set(self.PATTERNS["url"].findall(text))
        filtered_urls = set()
        for url in urls:
            url = url.rstrip(".,;:!?)")
            # Check domain whitelist (with subdomain matching)
            try:
                domain_part = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
            except IndexError:
                continue
            if self._is_whitelisted_domain(domain_part):
                continue
            # Check noisy URL path patterns
            if self.URL_NOISE_PATH_PATTERNS.search(url):
                continue
            filtered_urls.add(url)
        results.urls = sorted(filtered_urls)

        # Hashes — skip those embedded in URLs and degenerate patterns
        url_spans = self._get_url_spans(text)
        results.md5_hashes = sorted(self._extract_hashes(text, "md5", url_spans))
        results.sha256_hashes = sorted(self._extract_hashes(text, "sha256", url_spans))

        # CVEs — these are specific format, minimal noise
        cves = set(c.upper() for c in self.PATTERNS["cve"].findall(text))
        results.cve_ids = sorted(cves)

        # Emails — filter whitelisted domains and generic prefixes
        raw_emails = set(self.PATTERNS["email"].findall(text))
        filtered_emails = set()
        for email in raw_emails:
            email_domain = email.split("@", 1)[1] if "@" in email else ""
            if self._is_whitelisted_domain(email_domain):
                continue
            if self.EMAIL_NOISE_PREFIXES.match(email):
                continue
            filtered_emails.add(email)
        results.emails = sorted(filtered_emails)

        # Malware names — match against known families
        malware_found: Set[str] = set()
        text_lower = text.lower()
        for malware in self.KNOWN_MALWARE:
            if malware.lower() in text_lower:
                malware_found.add(malware)
        results.malware_names = sorted(malware_found)

        return results
