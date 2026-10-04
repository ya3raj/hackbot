"""
HackBot OSINT Module
====================
Open-Source Intelligence gathering: subdomain enumeration, email harvesting,
WHOIS lookup, DNS records, technology stack fingerprinting.
"""

from __future__ import annotations

import json
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests

from hackbot.core.bounded import (
    CancellationToken,
    Deadline,
    OperationCancelled,
    OperationDeadlineExceeded,
    OperationLimitExceeded,
)


MAX_BOUNDED_OSINT_STAGES = 5
MAX_BOUNDED_OSINT_ITEMS_PER_STAGE = 128
MAX_BOUNDED_OSINT_RESPONSE_BYTES = 524_288
MAX_BOUNDED_OSINT_RUNTIME_SECONDS = 60.0
BOUNDED_OSINT_STAGES = ("subdomains", "dns", "whois", "techstack", "emails")

# ── Data Models ──────────────────────────────────────────────────────────────


@dataclass
class SubdomainResult:
    """Discovered subdomain with optional metadata."""

    subdomain: str
    ip: str = ""
    source: str = ""
    status: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "subdomain": self.subdomain,
            "ip": self.ip,
            "source": self.source,
            "status": self.status,
        }


@dataclass
class WHOISResult:
    """Parsed WHOIS data."""

    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    org: str = ""
    country: str = ""
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "creation_date": self.creation_date,
            "expiration_date": self.expiration_date,
            "updated_date": self.updated_date,
            "name_servers": self.name_servers,
            "status": self.status,
            "emails": self.emails,
            "org": self.org,
            "country": self.country,
        }


@dataclass
class DNSRecord:
    """A DNS record."""

    record_type: str
    value: str
    ttl: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.record_type, "value": self.value, "ttl": self.ttl}


@dataclass
class TechStackResult:
    """Detected technologies on a web target."""

    url: str
    server: str = ""
    powered_by: str = ""
    technologies: List[Dict[str, str]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    scripts: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "server": self.server,
            "powered_by": self.powered_by,
            "technologies": self.technologies,
            "headers": self.headers,
            "cookies": self.cookies,
            "meta_tags": self.meta_tags,
            "scripts": self.scripts,
            "frameworks": self.frameworks,
        }


@dataclass
class OSINTReport:
    """Full OSINT report for a domain."""

    domain: str
    subdomains: List[SubdomainResult] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)
    whois: Optional[WHOISResult] = None
    tech_stack: Optional[TechStackResult] = None
    emails: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomains": [s.to_dict() for s in self.subdomains],
            "dns_records": [d.to_dict() for d in self.dns_records],
            "whois": self.whois.to_dict() if self.whois else None,
            "tech_stack": self.tech_stack.to_dict() if self.tech_stack else None,
            "emails": self.emails,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class BoundedOSINTResult:
    """A complete bounded scan plus execution metadata."""

    report: OSINTReport
    completed_stages: List[str]
    elapsed_seconds: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report": self.report.to_dict(),
            "completed_stages": list(self.completed_stages),
            "elapsed_seconds": self.elapsed_seconds,
        }


# ── Technology Fingerprints ──────────────────────────────────────────────────

TECH_FINGERPRINTS: Dict[str, Any] = {
    # Headers
    "headers": {
        "X-Powered-By": {
            "Express": {"name": "Express.js", "category": "Web Framework"},
            "PHP": {"name": "PHP", "category": "Language"},
            "ASP.NET": {"name": "ASP.NET", "category": "Web Framework"},
            "Next.js": {"name": "Next.js", "category": "Web Framework"},
            "Servlet": {"name": "Java Servlet", "category": "Web Framework"},
        },
        "Server": {
            "nginx": {"name": "Nginx", "category": "Web Server"},
            "Apache": {"name": "Apache", "category": "Web Server"},
            "Microsoft-IIS": {"name": "IIS", "category": "Web Server"},
            "LiteSpeed": {"name": "LiteSpeed", "category": "Web Server"},
            "cloudflare": {"name": "Cloudflare", "category": "CDN"},
            "AmazonS3": {"name": "Amazon S3", "category": "Cloud Storage"},
            "gunicorn": {"name": "Gunicorn", "category": "Web Server"},
            "Caddy": {"name": "Caddy", "category": "Web Server"},
        },
        "X-AspNet-Version": {
            "": {"name": "ASP.NET", "category": "Web Framework"},
        },
        "X-Drupal-Cache": {
            "": {"name": "Drupal", "category": "CMS"},
        },
    },
    # Cookie names
    "cookies": {
        "PHPSESSID": {"name": "PHP", "category": "Language"},
        "JSESSIONID": {"name": "Java", "category": "Language"},
        "ASP.NET_SessionId": {"name": "ASP.NET", "category": "Web Framework"},
        "csrftoken": {"name": "Django", "category": "Web Framework"},
        "laravel_session": {"name": "Laravel", "category": "Web Framework"},
        "wp-settings": {"name": "WordPress", "category": "CMS"},
        "_rails_": {"name": "Ruby on Rails", "category": "Web Framework"},
        "connect.sid": {"name": "Express.js", "category": "Web Framework"},
    },
    # HTML patterns
    "html": {
        "wp-content": {"name": "WordPress", "category": "CMS"},
        "wp-includes": {"name": "WordPress", "category": "CMS"},
        "Joomla": {"name": "Joomla", "category": "CMS"},
        "Drupal.settings": {"name": "Drupal", "category": "CMS"},
        "react": {"name": "React", "category": "JS Framework"},
        "vue": {"name": "Vue.js", "category": "JS Framework"},
        "angular": {"name": "Angular", "category": "JS Framework"},
        "__next": {"name": "Next.js", "category": "Web Framework"},
        "__nuxt": {"name": "Nuxt.js", "category": "Web Framework"},
        "gatsby": {"name": "Gatsby", "category": "Static Site Generator"},
        "shopify": {"name": "Shopify", "category": "E-Commerce"},
        "jquery": {"name": "jQuery", "category": "JS Library"},
        "bootstrap": {"name": "Bootstrap", "category": "CSS Framework"},
        "tailwindcss": {"name": "Tailwind CSS", "category": "CSS Framework"},
    },
}

# Common subdomain wordlist (compact)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
    "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
    "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum",
    "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api",
    "exchange", "app", "gov", "2tty", "vps", "govyty", "hbd",
    "news", "corporate", "intranet", "staging", "beta", "demo",
    "internal", "lab", "stg", "sandbox", "git", "jenkins", "ci",
    "jira", "confluence", "wiki", "monitor", "grafana", "kibana",
    "elastic", "prometheus", "sentry", "status", "docs", "assets",
    "static", "media", "images", "img", "files", "backup", "old",
    "legacy", "proxy", "gateway", "auth", "sso", "login", "id",
]


# ── OSINT Engine ─────────────────────────────────────────────────────────────


class OSINTEngine:
    """Open-Source Intelligence gathering engine."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        })

    # ── Subdomain Enumeration ────────────────────────────────────────────

    def enumerate_subdomains(
        self,
        domain: str,
        use_bruteforce: bool = False,
        on_found: Optional[Any] = None,
    ) -> List[SubdomainResult]:
        """
        Enumerate subdomains using passive sources + optional DNS brute force.

        Sources: crt.sh (Certificate Transparency), DNS brute force.
        """
        domain = self._clean_domain(domain)
        found: Dict[str, SubdomainResult] = {}

        # 1. Certificate Transparency (crt.sh)
        ct_subs = self._crtsh_subdomains(domain)
        for sub in ct_subs:
            if sub not in found:
                result = SubdomainResult(subdomain=sub, source="crt.sh")
                found[sub] = result
                if on_found:
                    on_found(result)

        # 2. DNS brute force (optional)
        if use_bruteforce:
            for word in SUBDOMAIN_WORDLIST:
                sub = f"{word}.{domain}"
                if sub in found:
                    continue
                ip = self._resolve_host(sub)
                if ip:
                    result = SubdomainResult(subdomain=sub, ip=ip, source="brute")
                    found[sub] = result
                    if on_found:
                        on_found(result)

        # 3. Resolve IPs for all subdomains
        for sub, result in found.items():
            if not result.ip:
                result.ip = self._resolve_host(sub)

        return sorted(found.values(), key=lambda s: s.subdomain)

    def _crtsh_subdomains(self, domain: str) -> Set[str]:
        """Fetch subdomains from Certificate Transparency logs via crt.sh."""
        subs: Set[str] = set()
        try:
            resp = self._session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=self.timeout,
            )
            if resp.ok:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line.endswith(f".{domain}") or line == domain:
                            # Remove wildcard prefix
                            line = line.lstrip("*.")
                            if self._is_valid_subdomain(line):
                                subs.add(line)
        except (requests.RequestException, json.JSONDecodeError):
            pass
        return subs

    # ── DNS Records ──────────────────────────────────────────────────────

    def get_dns_records(self, domain: str) -> List[DNSRecord]:
        """
        Retrieve DNS records for a domain using dnspython if available,
        with fallback to socket resolution.
        """
        domain = self._clean_domain(domain)
        records: List[DNSRecord] = []

        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout

            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]

            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    for rdata in answers:
                        records.append(DNSRecord(
                            record_type=rtype,
                            value=str(rdata),
                            ttl=answers.rrset.ttl if answers.rrset else 0,
                        ))
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                        dns.resolver.NoNameservers, dns.exception.Timeout):
                    continue
                except Exception:
                    continue

        except ImportError:
            # Fallback: basic socket resolution
            try:
                ips = socket.getaddrinfo(domain, None)
                seen = set()
                for family, _, _, _, sockaddr in ips:
                    ip = sockaddr[0]
                    rtype = "A" if family == socket.AF_INET else "AAAA"
                    key = (rtype, ip)
                    if key not in seen:
                        records.append(DNSRecord(record_type=rtype, value=str(ip)))
                        seen.add(key)
            except socket.gaierror:
                pass

        return records

    # ── WHOIS ────────────────────────────────────────────────────────────

    def whois_lookup(self, domain: str) -> Optional[WHOISResult]:
        """
        Perform a WHOIS lookup via a public WHOIS API.
        Falls back to socket-based WHOIS if API unavailable.
        """
        domain = self._clean_domain(domain)

        # Try RDAP first (modern WHOIS replacement)
        result = self._rdap_lookup(domain)
        if result:
            return result

        # Fallback: socket-based WHOIS
        return self._socket_whois(domain)

    def _rdap_lookup(self, domain: str) -> Optional[WHOISResult]:
        """RDAP lookup (IETF replacement for WHOIS)."""
        try:
            resp = self._session.get(
                f"https://rdap.org/domain/{domain}",
                timeout=self.timeout,
                headers={"Accept": "application/rdap+json"},
            )
            if not resp.ok:
                return None

            data = resp.json()

            result = WHOISResult(domain=domain)

            # Registrar
            entities = data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
                    for item in vcard:
                        if item[0] == "fn":
                            result.registrar = item[3]
                            break

            # Events (dates)
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")[:10]
                if action == "registration":
                    result.creation_date = date
                elif action == "expiration":
                    result.expiration_date = date
                elif action == "last changed":
                    result.updated_date = date

            # Nameservers
            for ns in data.get("nameservers", []):
                name = ns.get("ldhName", "")
                if name:
                    result.name_servers.append(name)

            # Status
            result.status = data.get("status", [])

            return result

        except (requests.RequestException, json.JSONDecodeError, KeyError):
            return None

    def _socket_whois(self, domain: str) -> Optional[WHOISResult]:
        """Basic WHOIS via socket connection to whois servers."""
        try:
            # Determine WHOIS server based on TLD
            tld = domain.rsplit(".", 1)[-1]
            whois_servers = {
                "com": "whois.verisign-grs.com",
                "net": "whois.verisign-grs.com",
                "org": "whois.pir.org",
                "io": "whois.nic.io",
                "dev": "whois.nic.google",
                "app": "whois.nic.google",
            }
            server = whois_servers.get(tld, f"whois.nic.{tld}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, 43))
            sock.send(f"{domain}\r\n".encode())

            raw = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
            sock.close()

            text = raw.decode("utf-8", errors="replace")

            result = WHOISResult(domain=domain, raw=text)

            # Parse common fields
            for line in text.splitlines():
                line = line.strip()
                lower = line.lower()
                if "registrar:" in lower:
                    result.registrar = line.split(":", 1)[1].strip()
                elif "creation date:" in lower or "created:" in lower:
                    result.creation_date = line.split(":", 1)[1].strip()[:10]
                elif "expir" in lower and "date:" in lower:
                    result.expiration_date = line.split(":", 1)[1].strip()[:10]
                elif "updated date:" in lower:
                    result.updated_date = line.split(":", 1)[1].strip()[:10]
                elif "name server:" in lower:
                    result.name_servers.append(line.split(":", 1)[1].strip())
                elif "registrant organization:" in lower:
                    result.org = line.split(":", 1)[1].strip()
                elif "registrant country:" in lower:
                    result.country = line.split(":", 1)[1].strip()

            # Extract emails
            email_pattern = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
            result.emails = list(set(email_pattern.findall(text)))

            return result

        except (socket.error, OSError):
            return None

    # ── Email Harvesting ─────────────────────────────────────────────────

    def harvest_emails(self, domain: str) -> List[str]:
        """
        Harvest email addresses associated with a domain from public sources.
        Sources: search engines, Hunter-style patterns, certificate data.
        """
        domain = self._clean_domain(domain)
        emails: Set[str] = set()
        email_pattern = re.compile(
            rf"[\w.+-]+@(?:[\w-]+\.)*{re.escape(domain)}",
            re.IGNORECASE,
        )

        # Source 1: Google search (uses a simple scrape — may be rate-limited)
        search_queries = [
            f'"{domain}" email',
            f'site:{domain} "@{domain}"',
            f'"@{domain}" contact',
        ]
        for query in search_queries:
            try:
                search_params: Dict[str, Any] = {"q": query, "num": 20}
                resp = self._session.get(
                    "https://www.google.com/search",
                    params=search_params,
                    timeout=self.timeout,
                )
                if resp.ok:
                    found = email_pattern.findall(resp.text)
                    emails.update(e.lower() for e in found)
            except requests.RequestException:
                pass

        # Source 2: Check common email patterns against target domain
        common_prefixes = [
            "info", "admin", "contact", "support", "hello", "sales",
            "security", "abuse", "webmaster", "postmaster", "hr",
        ]
        for prefix in common_prefixes:
            email = f"{prefix}@{domain}"
            if self._verify_mx_exists(domain):
                emails.add(email)
                break  # If MX exists, add all common patterns
        if self._verify_mx_exists(domain):
            for prefix in common_prefixes:
                emails.add(f"{prefix}@{domain}")

        return sorted(emails)

    # ── Tech Stack Fingerprinting ────────────────────────────────────────

    def fingerprint_tech_stack(self, target: str) -> TechStackResult:
        """
        Detect technologies used by a web target by analyzing HTTP headers,
        cookies, HTML content, and JavaScript includes.
        """
        url = self._normalize_url(target)
        result = TechStackResult(url=url)

        try:
            resp = self._session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )

            # Headers analysis
            result.headers = dict(resp.headers)
            result.server = resp.headers.get("Server", "")
            result.powered_by = resp.headers.get("X-Powered-By", "")

            for header_name, patterns in TECH_FINGERPRINTS["headers"].items():
                header_val = resp.headers.get(header_name, "")
                if not header_val:
                    continue
                for pattern, tech in patterns.items():
                    if not pattern or pattern.lower() in header_val.lower():
                        result.technologies.append({
                            "name": tech["name"],
                            "category": tech["category"],
                            "evidence": f"Header: {header_name}: {header_val[:100]}",
                        })

            # Cookies analysis
            for cookie in resp.cookies:
                result.cookies.append(cookie.name)
                for pattern, tech in TECH_FINGERPRINTS["cookies"].items():
                    if pattern.lower() in cookie.name.lower():
                        result.technologies.append({
                            "name": tech["name"],
                            "category": tech["category"],
                            "evidence": f"Cookie: {cookie.name}",
                        })

            # HTML analysis
            html = resp.text
            for pattern, tech in TECH_FINGERPRINTS["html"].items():
                if pattern.lower() in html.lower():
                    result.technologies.append({
                        "name": tech["name"],
                        "category": tech["category"],
                        "evidence": f"HTML content match: {pattern}",
                    })

            # Extract script sources
            script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)', re.IGNORECASE)
            result.scripts = script_pattern.findall(html)[:20]

            # Extract meta tags
            meta_pattern = re.compile(
                r'<meta\s+(?:name|property)=["\']([^"\']+)["\']\s+content=["\']([^"\']+)',
                re.IGNORECASE,
            )
            for name, content in meta_pattern.findall(html):
                result.meta_tags[name] = content[:200]
                if "generator" in name.lower():
                    result.frameworks.append(content)

            # SSL/TLS info
            self._check_ssl(url, result)

            # Deduplicate technologies
            seen = set()
            unique_tech = []
            for tech in result.technologies:
                key = tech["name"]
                if key not in seen:
                    seen.add(key)
                    unique_tech.append(tech)
            result.technologies = unique_tech

        except requests.RequestException:
            pass

        return result

    def _check_ssl(self, url: str, result: TechStackResult) -> None:
        """Check SSL/TLS certificate info."""
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(), server_hostname=parsed.hostname
            ) as s:
                s.settimeout(self.timeout)
                s.connect((parsed.hostname, 443))
                cert = s.getpeercert()
                if cert:
                    issuer_pairs: List[tuple[str, str]] = []
                    for rdn in cert.get("issuer", ()):
                        for item in rdn:
                            if isinstance(item, (list, tuple)) and len(item) == 2:
                                issuer_pairs.append((str(item[0]), str(item[1])))
                    issuer = dict(issuer_pairs)
                    org = issuer.get("organizationName", "")
                    if org:
                        result.technologies.append({
                            "name": f"SSL: {org}",
                            "category": "Certificate Authority",
                            "evidence": f"Certificate issuer: {org}",
                        })
        except (socket.error, ssl.SSLError, OSError):
            pass

    # ── Full OSINT Scan ──────────────────────────────────────────────────

    def full_scan(
        self,
        domain: str,
        bruteforce_subs: bool = False,
        on_progress: Optional[Any] = None,
    ) -> OSINTReport:
        """
        Run a complete OSINT scan against a domain.

        Args:
            domain: Target domain
            bruteforce_subs: Whether to DNS brute-force subdomains
            on_progress: Callback(stage_name, detail) for progress updates
        """
        domain = self._clean_domain(domain)
        report = OSINTReport(domain=domain)

        def progress(stage: str, detail: str = "") -> None:
            if on_progress:
                on_progress(stage, detail)

        # 1. Subdomain Enumeration
        progress("subdomains", "Enumerating subdomains...")
        report.subdomains = self.enumerate_subdomains(domain, use_bruteforce=bruteforce_subs)
        progress("subdomains", f"Found {len(report.subdomains)} subdomains")

        # 2. DNS Records
        progress("dns", "Resolving DNS records...")
        report.dns_records = self.get_dns_records(domain)
        progress("dns", f"Found {len(report.dns_records)} DNS records")

        # 3. WHOIS
        progress("whois", "Performing WHOIS lookup...")
        report.whois = self.whois_lookup(domain)
        progress("whois", "WHOIS complete")

        # 4. Tech Stack
        progress("techstack", "Fingerprinting technology stack...")
        report.tech_stack = self.fingerprint_tech_stack(domain)
        progress("techstack", f"Found {len(report.tech_stack.technologies)} technologies")

        # 5. Email Harvesting
        progress("emails", "Harvesting email addresses...")
        report.emails = self.harvest_emails(domain)
        progress("emails", f"Found {len(report.emails)} emails")

        return report

    # ── Explicit bounded federation scan ────────────────────────────────

    @staticmethod
    def strict_domain(target: str) -> str:
        """Canonicalize a bare DNS hostname and reject URL/IP ambiguity."""
        if not isinstance(target, str) or not target or target != target.strip():
            raise ValueError("target must be a non-empty bare hostname")
        if any(char in target for char in ("/", "\\", "@", ":", "?", "#")):
            raise ValueError("target must be a bare hostname")
        candidate = target[:-1] if target.endswith(".") else target
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            raise ValueError("IP literals are not accepted by full OSINT")
        try:
            canonical = candidate.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("target is not a valid IDNA hostname") from exc
        if len(canonical) > 253 or "." not in canonical:
            raise ValueError("target must be a fully qualified hostname")
        labels = canonical.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        ):
            raise ValueError("target is not a valid hostname")
        return canonical

    @staticmethod
    def _bounded_origin(url: str) -> tuple[str, str, int]:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("bounded OSINT requires credential-free HTTPS URLs")
        return (parsed.scheme, parsed.hostname.encode("idna").decode("ascii").lower(), parsed.port or 443)

    @staticmethod
    def _require_public_resolution(host: str) -> None:
        """Fail closed when a user-selected hostname resolves off the public Internet."""
        try:
            infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise RuntimeError("target DNS resolution failed") from exc
        addresses = set()
        for info in infos:
            try:
                addresses.add(ipaddress.ip_address(info[4][0]))
            except (ValueError, IndexError, TypeError):
                continue
        if not addresses or any(not address.is_global for address in addresses):
            raise RuntimeError("target DNS resolution is not exclusively public")

    @classmethod
    def _bounded_get(
        cls,
        session: requests.Session,
        url: str,
        deadline: Deadline,
        cancellation: CancellationToken,
        max_bytes: int,
    ) -> tuple[requests.Response, bytes]:
        """GET with TLS verification, exact-origin redirects, and response caps."""
        pinned_origin = cls._bounded_origin(url)
        current = url
        for _ in range(4):
            remaining = deadline.remaining(cancellation)
            response = session.get(
                current,
                timeout=(min(3.0, remaining), min(3.0, remaining)),
                allow_redirects=False,
                verify=True,
                stream=True,
            )
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                response.close()
                if not location:
                    raise RuntimeError("upstream redirect was invalid")
                redirected = urljoin(current, location)
                if cls._bounded_origin(redirected) != pinned_origin:
                    raise RuntimeError("cross-origin redirect blocked")
                current = redirected
                continue
            content_length = response.headers.get("Content-Length", "")
            if content_length.isdigit() and int(content_length) > max_bytes:
                response.close()
                raise OperationLimitExceeded("upstream response exceeds the configured limit")
            body = bytearray()
            try:
                for chunk in response.iter_content(chunk_size=8192):
                    deadline.remaining(cancellation)
                    if not chunk:
                        continue
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise OperationLimitExceeded(
                            "upstream response exceeds the configured limit"
                        )
            except Exception:
                response.close()
                raise
            return response, bytes(body)
        raise RuntimeError("too many same-origin redirects")

    @classmethod
    def _bounded_subdomains(
        cls,
        session: requests.Session,
        domain: str,
        deadline: Deadline,
        cancellation: CancellationToken,
        max_items: int,
        max_bytes: int,
    ) -> List[SubdomainResult]:
        response, body = cls._bounded_get(
            session,
            f"https://crt.sh/?q=%25.{domain}&output=json",
            deadline,
            cancellation,
            max_bytes,
        )
        try:
            if not response.ok:
                return []
            data = json.loads(body.decode("utf-8"))
        finally:
            response.close()
        if not isinstance(data, list):
            raise RuntimeError("certificate source returned an invalid schema")
        found: Set[str] = set()
        for entry in data:
            deadline.remaining(cancellation)
            if not isinstance(entry, dict) or not isinstance(entry.get("name_value"), str):
                continue
            for value in entry["name_value"].splitlines():
                value = value.strip().lower().lstrip("*.")
                try:
                    canonical = cls.strict_domain(value)
                except ValueError:
                    continue
                if canonical == domain or canonical.endswith(f".{domain}"):
                    found.add(canonical)
                if len(found) >= max_items:
                    break
            if len(found) >= max_items:
                break
        return [SubdomainResult(item, source="crt.sh") for item in sorted(found)]

    @staticmethod
    def _bounded_dns(
        domain: str,
        deadline: Deadline,
        cancellation: CancellationToken,
        max_items: int,
    ) -> List[DNSRecord]:
        records: List[DNSRecord] = []
        try:
            import dns.exception
            import dns.resolver
        except ImportError:
            return records
        resolver = dns.resolver.Resolver()
        for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"):
            remaining = deadline.remaining(cancellation)
            resolver.timeout = min(2.0, remaining)
            resolver.lifetime = min(2.0, remaining)
            try:
                answers = resolver.resolve(domain, record_type)
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                continue
            for answer in answers:
                deadline.remaining(cancellation)
                records.append(
                    DNSRecord(
                        record_type=record_type,
                        value=str(answer)[:2048],
                        ttl=answers.rrset.ttl if answers.rrset else 0,
                    )
                )
                if len(records) >= max_items:
                    return records
        return records

    @classmethod
    def _bounded_whois(
        cls,
        session: requests.Session,
        domain: str,
        deadline: Deadline,
        cancellation: CancellationToken,
        max_items: int,
        max_bytes: int,
    ) -> Optional[WHOISResult]:
        response, body = cls._bounded_get(
            session,
            f"https://rdap.org/domain/{domain}",
            deadline,
            cancellation,
            max_bytes,
        )
        try:
            if not response.ok:
                return None
            data = json.loads(body.decode("utf-8"))
        finally:
            response.close()
        if not isinstance(data, dict):
            raise RuntimeError("RDAP source returned an invalid schema")
        result = WHOISResult(domain=domain)
        entities = data.get("entities", [])
        if isinstance(entities, list):
            for entity in entities[:max_items]:
                if not isinstance(entity, dict) or "registrar" not in entity.get("roles", []):
                    continue
                vcard = entity.get("vcardArray")
                rows = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list) else []
                for row in rows[:max_items]:
                    if isinstance(row, list) and len(row) > 3 and row[0] == "fn":
                        result.registrar = str(row[3])[:512]
                        break
        events = data.get("events", [])
        if isinstance(events, list):
            for event in events[:max_items]:
                if not isinstance(event, dict):
                    continue
                action = event.get("eventAction")
                date = str(event.get("eventDate", ""))[:10]
                if action == "registration":
                    result.creation_date = date
                elif action == "expiration":
                    result.expiration_date = date
                elif action == "last changed":
                    result.updated_date = date
        nameservers = data.get("nameservers", [])
        if isinstance(nameservers, list):
            for item in nameservers[:max_items]:
                if isinstance(item, dict) and isinstance(item.get("ldhName"), str):
                    result.name_servers.append(item["ldhName"][:253])
        statuses = data.get("status", [])
        if isinstance(statuses, list):
            result.status = [str(item)[:128] for item in statuses[:max_items]]
        return result

    @classmethod
    def _bounded_tech_and_emails(
        cls,
        session: requests.Session,
        domain: str,
        deadline: Deadline,
        cancellation: CancellationToken,
        max_items: int,
        max_bytes: int,
    ) -> tuple[TechStackResult, List[str]]:
        cls._require_public_resolution(domain)
        url = f"https://{domain}/"
        response, body = cls._bounded_get(
            session, url, deadline, cancellation, max_bytes
        )
        try:
            result = TechStackResult(url=response.url or url)
            if not response.ok:
                return result, []
            for key, value in list(response.headers.items())[:32]:
                result.headers[str(key)[:128]] = str(value)[:1024]
            result.server = result.headers.get("Server", "")
            result.powered_by = result.headers.get("X-Powered-By", "")
            for cookie in list(response.cookies)[:max_items]:
                result.cookies.append(str(cookie.name)[:256])
        finally:
            response.close()
        html = body.decode("utf-8", errors="replace")
        for header_name, patterns in TECH_FINGERPRINTS["headers"].items():
            header_value = result.headers.get(header_name, "")
            for pattern, tech in patterns.items():
                if header_value and (not pattern or pattern.lower() in header_value.lower()):
                    result.technologies.append(
                        {
                            "name": tech["name"],
                            "category": tech["category"],
                            "evidence": f"Header: {header_name}: {header_value[:100]}",
                        }
                    )
        for pattern, tech in TECH_FINGERPRINTS["html"].items():
            if pattern.lower() in html.lower():
                result.technologies.append(
                    {
                        "name": tech["name"],
                        "category": tech["category"],
                        "evidence": f"HTML content match: {pattern}",
                    }
                )
            if len(result.technologies) >= max_items:
                break
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)', re.IGNORECASE)
        result.scripts = [item[:2048] for item in script_pattern.findall(html)[:20]]
        email_pattern = re.compile(
            rf"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*{re.escape(domain)}",
            re.IGNORECASE,
        )
        emails = sorted({item.lower() for item in email_pattern.findall(html)})[:max_items]
        return result, emails

    def full_scan_bounded(
        self,
        target: str,
        *,
        enabled: bool,
        max_items_per_stage: int = 64,
        max_response_bytes: int = 262_144,
        deadline_seconds: float = 30.0,
        cancellation: Optional[CancellationToken] = None,
    ) -> BoundedOSINTResult:
        """Run the five-stage OSINT contract under one absolute deadline.

        The bounded path uses only HTTPS sources, verifies TLS, follows redirects only
        within the exact origin, never brute-forces subdomains, and never invokes the
        legacy raw WHOIS or search-engine scraping fallbacks.
        """
        if enabled is not True:
            raise ValueError("bounded OSINT execution requires enabled=true")
        if (
            isinstance(max_items_per_stage, bool)
            or not isinstance(max_items_per_stage, int)
            or max_items_per_stage < 1
            or max_items_per_stage > MAX_BOUNDED_OSINT_ITEMS_PER_STAGE
        ):
            raise ValueError("max_items_per_stage is outside the supported range")
        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or max_response_bytes < 1024
            or max_response_bytes > MAX_BOUNDED_OSINT_RESPONSE_BYTES
        ):
            raise ValueError("max_response_bytes is outside the supported range")
        if (
            isinstance(deadline_seconds, bool)
            or not isinstance(deadline_seconds, (int, float))
            or deadline_seconds <= 0
            or deadline_seconds > MAX_BOUNDED_OSINT_RUNTIME_SECONDS
        ):
            raise ValueError("deadline_seconds is outside the supported range")

        domain = self.strict_domain(target)
        self._require_public_resolution(domain)
        token = cancellation or CancellationToken()
        deadline = Deadline(float(deadline_seconds))
        token.raise_if_cancelled()
        session = requests.Session()
        session.trust_env = False
        session.headers.update({"User-Agent": "HackBot-Federation/1.0"})
        close_handle = token.add_callback(session.close)
        completed: List[str] = []
        report = OSINTReport(domain=domain)
        try:
            report.subdomains = self._bounded_subdomains(
                session, domain, deadline, token, max_items_per_stage, max_response_bytes
            )
            completed.append("subdomains")
            report.dns_records = self._bounded_dns(
                domain, deadline, token, max_items_per_stage
            )
            completed.append("dns")
            report.whois = self._bounded_whois(
                session, domain, deadline, token, max_items_per_stage, max_response_bytes
            )
            completed.append("whois")
            report.tech_stack, report.emails = self._bounded_tech_and_emails(
                session, domain, deadline, token, max_items_per_stage, max_response_bytes
            )
            completed.extend(("techstack", "emails"))
            deadline.remaining(token)
            encoded = json.dumps(report.to_dict(), ensure_ascii=False).encode("utf-8")
            if len(encoded) > max_response_bytes:
                raise OperationLimitExceeded("OSINT report exceeds the configured limit")
        except (OperationCancelled, OperationDeadlineExceeded, OperationLimitExceeded):
            raise
        except requests.RequestException as exc:
            if token.cancelled:
                raise OperationCancelled("operation cancelled") from exc
            if time.monotonic() >= deadline.ends:
                raise OperationDeadlineExceeded("operation deadline exceeded") from exc
            raise RuntimeError("OSINT upstream request failed") from None
        finally:
            token.remove_callback(close_handle)
            session.close()

        return BoundedOSINTResult(
            report=report,
            completed_stages=completed,
            elapsed_seconds=round(deadline.elapsed, 6),
        )

    # ── Formatting ───────────────────────────────────────────────────────

    @staticmethod
    def format_report(report: OSINTReport) -> str:
        """Format an OSINT report as rich markdown."""
        lines = [
            f"# OSINT Report: {report.domain}\n",
            f"_Generated at {time.strftime('%Y-%m-%d %H:%M:%S')}_\n",
        ]

        # Summary
        lines.append("## 📊 Summary\n")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Subdomains | {len(report.subdomains)} |")
        lines.append(f"| DNS Records | {len(report.dns_records)} |")
        lines.append(f"| Emails | {len(report.emails)} |")
        tech_count = len(report.tech_stack.technologies) if report.tech_stack else 0
        lines.append(f"| Technologies | {tech_count} |")
        lines.append("")

        # Subdomains
        if report.subdomains:
            lines.append("## 🌐 Subdomains\n")
            lines.append("| Subdomain | IP | Source |")
            lines.append("|-----------|-----|--------|")
            for s in report.subdomains[:50]:
                lines.append(f"| {s.subdomain} | {s.ip or '—'} | {s.source} |")
            if len(report.subdomains) > 50:
                lines.append(f"\n_...and {len(report.subdomains) - 50} more_")
            lines.append("")

        # DNS Records
        if report.dns_records:
            lines.append("## 📡 DNS Records\n")
            lines.append("| Type | Value | TTL |")
            lines.append("|------|-------|-----|")
            for r in report.dns_records:
                val = r.value[:80] + "..." if len(r.value) > 80 else r.value
                lines.append(f"| {r.record_type} | {val} | {r.ttl} |")
            lines.append("")

        # WHOIS
        if report.whois:
            w = report.whois
            lines.append("## 📋 WHOIS Information\n")
            if w.registrar:
                lines.append(f"- **Registrar:** {w.registrar}")
            if w.org:
                lines.append(f"- **Organization:** {w.org}")
            if w.country:
                lines.append(f"- **Country:** {w.country}")
            if w.creation_date:
                lines.append(f"- **Created:** {w.creation_date}")
            if w.expiration_date:
                lines.append(f"- **Expires:** {w.expiration_date}")
            if w.name_servers:
                lines.append(f"- **Name Servers:** {', '.join(w.name_servers)}")
            if w.emails:
                lines.append(f"- **Contacts:** {', '.join(w.emails)}")
            lines.append("")

        # Tech Stack
        if report.tech_stack and report.tech_stack.technologies:
            ts = report.tech_stack
            lines.append("## 🔧 Technology Stack\n")
            if ts.server:
                lines.append(f"- **Server:** {ts.server}")
            if ts.powered_by:
                lines.append(f"- **Powered By:** {ts.powered_by}")
            lines.append("")

            # Group by category
            by_category: Dict[str, List[Dict[str, str]]] = {}
            for tech in ts.technologies:
                cat = tech.get("category", "Other")
                by_category.setdefault(cat, []).append(tech)

            for cat, techs in by_category.items():
                lines.append(f"**{cat}:**")
                for t in techs:
                    lines.append(f"- {t['name']} _{t.get('evidence', '')}_")
                lines.append("")

        # Emails
        if report.emails:
            lines.append("## 📧 Email Addresses\n")
            for email in report.emails:
                lines.append(f"- {email}")
            lines.append("")

        return "\n".join(lines)

    # ── Utilities ────────────────────────────────────────────────────────

    @staticmethod
    def _clean_domain(domain: str) -> str:
        """Normalize a domain input."""
        domain = domain.strip().lower()
        # Strip protocol
        for prefix in ["https://", "http://", "www."]:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        # Strip path
        domain = domain.split("/")[0]
        # Strip port
        domain = domain.split(":")[0]
        return domain

    @staticmethod
    def _normalize_url(target: str) -> str:
        """Ensure target has a scheme."""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        return target

    @staticmethod
    def _is_valid_subdomain(name: str) -> bool:
        """Check if a string is a valid subdomain."""
        if not name or len(name) > 253:
            return False
        pattern = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
        return bool(pattern.match(name))

    def _resolve_host(self, hostname: str) -> str:
        """Resolve a hostname to an IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return ""

    def _verify_mx_exists(self, domain: str) -> bool:
        """Check if a domain has MX records."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            return len(list(answers)) > 0
        except Exception:
            pass
        # Fallback
        try:
            socket.getaddrinfo(f"mail.{domain}", 25)
            return True
        except socket.gaierror:
            return False
