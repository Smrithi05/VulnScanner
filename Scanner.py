#!/usr/bin/env python3
"""
Custom Vulnerability Scanner
=============================
A lightweight Python tool that scans a web application for indicators of
common OWASP Top 10 (2021) vulnerability classes.

LEGAL / ETHICAL NOTICE
-----------------------
Only run this tool against applications you own or have explicit written
authorization to test. Unauthorized scanning of systems you do not control
may be illegal under computer-crime laws (e.g. the CFAA in the US) even if
no damage is caused. This tool performs non-destructive, read-only checks
and does NOT attempt to exploit or exfiltrate data.

Usage
-----
    python scanner.py https://example.com
    python scanner.py https://example.com --output report.json
    python scanner.py https://example.com --crawl --max-pages 25

Requirements
------------
    pip install requests beautifulsoup4
"""

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()  # we deliberately allow self-signed for scanning

USER_AGENT = "CustomVulnScanner/1.0 (+authorized-security-testing)"
TIMEOUT = 10


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    severity: str          # Critical / High / Medium / Low / Info
    category: str          # OWASP category, e.g. "A03:2021 - Injection"
    title: str
    url: str
    detail: str
    evidence: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanReport:
    target: str
    started_at: str
    finished_at: str = ""
    findings: list = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def summary(self):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self):
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class VulnerabilityScanner:

    SENSITIVE_PATHS = [
        ".git/HEAD", ".git/config", ".env", ".env.local", "wp-config.php.bak",
        "config.php.bak", "backup.zip", "backup.sql", "db.sql", ".DS_Store",
        "web.config", ".svn/entries", "docker-compose.yml", ".htpasswd",
        "phpinfo.php", "server-status", "id_rsa", ".aws/credentials",
    ]

    ADMIN_PATHS = [
        "admin", "administrator", "wp-admin", "admin/login", "manage",
        "phpmyadmin", "adminer.php", "console", "actuator", "actuator/env",
    ]

    SQLI_PAYLOADS = ["'", "\" OR \"1\"=\"1", "' OR '1'='1", "1' ORDER BY 100--"]
    SQLI_ERROR_SIGNATURES = [
        "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
        "quoted string not properly terminated", "sqlstate", "pg_query()", "ora-01756",
        "sqlite3.operationalerror", "odbc sql server driver",
    ]

    XSS_PAYLOAD = "<script>alert('xvs_test_1337')</script>"

    SECURITY_HEADERS = {
        "Content-Security-Policy": "Mitigates XSS and data-injection attacks",
        "X-Content-Type-Options": "Prevents MIME-sniffing",
        "X-Frame-Options": "Mitigates clickjacking",
        "Strict-Transport-Security": "Enforces HTTPS",
        "Referrer-Policy": "Controls referrer leakage",
        "Permissions-Policy": "Restricts powerful browser features",
    }

    def __init__(self, target, crawl=False, max_pages=20, threads=8, delay=0.0):
        self.target = target.rstrip("/")
        parsed = urlparse(self.target)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.crawl = crawl
        self.max_pages = max_pages
        self.threads = threads
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.visited = set()
        self.report = ScanReport(target=self.target, started_at=datetime.utcnow().isoformat())

    # ---------------------------------------------------------------- utils
    def _get(self, url, **kwargs):
        try:
            time.sleep(self.delay)
            return self.session.get(url, timeout=TIMEOUT, verify=False,
                                     allow_redirects=True, **kwargs)
        except requests.RequestException:
            return None

    def _add(self, severity, category, title, url, detail, evidence=""):
        self.report.add(Finding(severity, category, title, url, detail, evidence))

    # ---------------------------------------------------------------- crawl
    def discover_pages(self):
        pages = {self.target}
        if not self.crawl:
            return pages
        queue = [self.target]
        while queue and len(pages) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            resp = self._get(url)
            if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup.find_all("a", href=True):
                link = urljoin(url, tag["href"])
                if urlparse(link).netloc == urlparse(self.target).netloc:
                    if link not in pages and len(pages) < self.max_pages:
                        pages.add(link)
                        queue.append(link)
        return pages

    # ------------------------------------------------------- A02 / transport
    def check_transport_security(self):
        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            self._add("High", "A02:2021 - Cryptographic Failures",
                       "Site not served over HTTPS", self.target,
                       "The application is accessible over plain HTTP, exposing traffic to "
                       "interception and tampering.")
            return

        host = parsed.netloc.split(":")[0]
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.utcnow()).days
                    if days_left < 14:
                        self._add("Medium", "A02:2021 - Cryptographic Failures",
                                   "TLS certificate expiring soon", self.target,
                                   f"Certificate expires in {days_left} days.")
        except ssl.SSLCertVerificationError as e:
            self._add("High", "A02:2021 - Cryptographic Failures",
                       "Invalid/untrusted TLS certificate", self.target, str(e))
        except Exception:
            pass  # non-fatal; connectivity issues shouldn't crash the scan

    # ---------------------------------------------------------- A05 headers
    def check_security_headers(self, url, resp):
        for header, reason in self.SECURITY_HEADERS.items():
            if header not in resp.headers:
                self._add("Low", "A05:2021 - Security Misconfiguration",
                           f"Missing header: {header}", url,
                           f"{reason}. Consider adding this response header.")

        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            for cookie in resp.raw.headers.get_all("Set-Cookie", []) if hasattr(resp.raw.headers, "get_all") else [cookies]:
                if "secure" not in cookie.lower():
                    self._add("Medium", "A05:2021 - Security Misconfiguration",
                               "Cookie missing 'Secure' flag", url,
                               "Cookie can be transmitted over unencrypted connections.",
                               evidence=cookie.split("=")[0])
                if "httponly" not in cookie.lower():
                    self._add("Medium", "A05:2021 - Security Misconfiguration",
                               "Cookie missing 'HttpOnly' flag", url,
                               "Cookie is accessible to client-side JavaScript, increasing XSS impact.",
                               evidence=cookie.split("=")[0])
                if "samesite" not in cookie.lower():
                    self._add("Low", "A05:2021 - Security Misconfiguration",
                               "Cookie missing 'SameSite' attribute", url,
                               "Cookie may be sent on cross-site requests, enabling CSRF.",
                               evidence=cookie.split("=")[0])

        server = resp.headers.get("Server")
        xpb = resp.headers.get("X-Powered-By")
        if server:
            self._add("Info", "A06:2021 - Vulnerable and Outdated Components",
                       "Server banner disclosed", url,
                       "Server header reveals software/version, aiding fingerprinting.",
                       evidence=server)
        if xpb:
            self._add("Info", "A06:2021 - Vulnerable and Outdated Components",
                       "X-Powered-By banner disclosed", url,
                       "Reveals backend framework/version.", evidence=xpb)

    # -------------------------------------------------------- sensitive files
    def check_sensitive_paths(self):
        def probe(path):
            url = f"{self.base}/{path}"
            resp = self._get(url)
            if resp is not None and resp.status_code == 200 and len(resp.content) > 0:
                return path, resp
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for result in ex.map(probe, self.SENSITIVE_PATHS):
                if result:
                    path, resp = result
                    self._add("High", "A01:2021 - Broken Access Control",
                               f"Sensitive file exposed: /{path}", f"{self.base}/{path}",
                               "This file may leak credentials, source code, or configuration.")

    def check_admin_paths(self):
        def probe(path):
            url = f"{self.base}/{path}"
            resp = self._get(url)
            if resp is not None and resp.status_code in (200, 401, 403):
                return path, resp
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for result in ex.map(probe, self.ADMIN_PATHS):
                if result:
                    path, resp = result
                    sev = "Medium" if resp.status_code == 200 else "Info"
                    self._add(sev, "A01:2021 - Broken Access Control",
                               f"Administrative endpoint reachable: /{path}",
                               f"{self.base}/{path}",
                               f"Endpoint returned HTTP {resp.status_code}. Confirm it requires "
                               "proper authentication/authorization.")

    def check_directory_listing(self, url, resp):
        if resp and re.search(r"<title>Index of /", resp.text, re.I):
            self._add("Medium", "A01:2021 - Broken Access Control",
                       "Directory listing enabled", url,
                       "Server exposes a raw directory index, potentially revealing files "
                       "not meant to be public.")

    # ---------------------------------------------------------------- forms
    def _extract_forms(self, url, resp):
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                    })
            forms.append({"action": action, "method": method, "inputs": inputs, "url": url})
        return forms

    def check_csrf_tokens(self, forms):
        token_hints = ("csrf", "token", "authenticity", "nonce")
        for form in forms:
            if form["method"] != "post":
                continue
            has_token = any(any(h in i["name"].lower() for h in token_hints) for i in form["inputs"])
            if not has_token:
                self._add("Medium", "A01:2021 - Broken Access Control",
                           "POST form without visible CSRF token", form["url"],
                           f"Form submitting to {form['action']} has no field resembling a "
                           "CSRF token. Verify server-side protections (e.g. SameSite cookies, "
                           "double-submit tokens) are in place.")

    # ------------------------------------------------------------- injection
    def _params_from_url(self, url):
        parsed = urlparse(url)
        return parsed, parse_qs(parsed.query)

    def check_reflected_xss_and_sqli(self, url):
        parsed, params = self._params_from_url(url)
        if not params:
            return

        for param in params:
            # --- XSS ---
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = self.XSS_PAYLOAD
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            resp = self._get(test_url)
            if resp and self.XSS_PAYLOAD in resp.text:
                self._add("High", "A03:2021 - Injection",
                           f"Possible reflected XSS via parameter '{param}'", test_url,
                           "The payload was reflected unescaped in the response body. "
                           "Confirm output encoding / CSP as a defense.",
                           evidence=self.XSS_PAYLOAD)

            # --- SQLi (error-based detection only) ---
            for payload in self.SQLI_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                resp = self._get(test_url)
                if resp:
                    body = resp.text.lower()
                    for sig in self.SQLI_ERROR_SIGNATURES:
                        if sig in body:
                            self._add("Critical", "A03:2021 - Injection",
                                       f"Possible SQL injection via parameter '{param}'",
                                       test_url,
                                       "Injecting SQL metacharacters triggered a database "
                                       "error message, suggesting unsanitized input reaches "
                                       "a SQL query.",
                                       evidence=sig)
                            break

    def check_forms_injection(self, forms):
        for form in forms:
            if not form["inputs"]:
                continue
            data = {i["name"]: self.XSS_PAYLOAD if i["type"] not in ("checkbox", "radio", "submit")
                     else "on" for i in form["inputs"]}
            try:
                if form["method"] == "post":
                    resp = self.session.post(form["action"], data=data, timeout=TIMEOUT, verify=False)
                else:
                    resp = self.session.get(form["action"], params=data, timeout=TIMEOUT, verify=False)
            except requests.RequestException:
                continue
            if resp is not None and self.XSS_PAYLOAD in resp.text:
                self._add("High", "A03:2021 - Injection",
                           "Possible reflected XSS via form submission", form["action"],
                           "Submitting a script payload through a form field was reflected "
                           "unescaped in the response.", evidence=self.XSS_PAYLOAD)

    # ---------------------------------------------------------------- run
    def run(self):
        pages = self.discover_pages()
        self.check_transport_security()
        self.check_sensitive_paths()
        self.check_admin_paths()

        for url in pages:
            resp = self._get(url)
            if resp is None:
                continue
            self.check_security_headers(url, resp)
            self.check_directory_listing(url, resp)
            if "text/html" in resp.headers.get("Content-Type", ""):
                forms = self._extract_forms(url, resp)
                self.check_csrf_tokens(forms)
                self.check_forms_injection(forms)
            self.check_reflected_xss_and_sqli(url)

        self.report.finished_at = datetime.utcnow().isoformat()
        return self.report


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {
    "Critical": "\033[95m", "High": "\033[91m", "Medium": "\033[93m",
    "Low": "\033[94m", "Info": "\033[90m",
}
RESET = "\033[0m"


def print_report(report: ScanReport):
    print(f"\nScan target : {report.target}")
    print(f"Started     : {report.started_at}")
    print(f"Finished    : {report.finished_at}")
    print("\nSummary:")
    for sev, count in report.summary().items():
        print(f"  {SEVERITY_COLOR.get(sev,'')}{sev:<10}{RESET}: {count}")

    print("\nFindings:")
    findings_sorted = sorted(report.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    for f in findings_sorted:
        color = SEVERITY_COLOR.get(f.severity, "")
        print(f"\n{color}[{f.severity}]{RESET} {f.title}")
        print(f"  Category : {f.category}")
        print(f"  URL      : {f.url}")
        print(f"  Detail   : {f.detail}")
        if f.evidence:
            print(f"  Evidence : {f.evidence}")

    if not report.findings:
        print("  No issues detected by the checks performed.")


def main():
    parser = argparse.ArgumentParser(
        description="Custom Vulnerability Scanner - OWASP Top 10 checks. "
                     "Only use on systems you are authorized to test.")
    parser.add_argument("target", help="Target base URL, e.g. https://example.com")
    parser.add_argument("--crawl", action="store_true", help="Crawl internal links before scanning")
    parser.add_argument("--max-pages", type=int, default=20, help="Max pages to crawl (default 20)")
    parser.add_argument("--threads", type=int, default=8, help="Concurrent requests for path probing")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds)")
    parser.add_argument("--output", help="Write JSON report to this file")
    args = parser.parse_args()

    if not urlparse(args.target).scheme:
        print("Error: target must include scheme, e.g. https://example.com", file=sys.stderr)
        sys.exit(1)

    print("Starting scan — only proceed if you are authorized to test this target.")
    scanner = VulnerabilityScanner(
        target=args.target, crawl=args.crawl, max_pages=args.max_pages,
        threads=args.threads, delay=args.delay,
    )
    report = scanner.run()
    print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"\nJSON report written to {args.output}")


if __name__ == "__main__":
    main()