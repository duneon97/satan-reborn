"""Opt-in OSV queries. Only ecosystem, package name, and version leave the host."""

import json
import re
from http.client import HTTPException
from urllib import error, request

from .checks.dependencies import Dependency
from .models import Finding, Severity

MAX_RESPONSE = 1024 * 1024


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OSVClient:
    def __init__(self, timeout: float = 3.0, max_queries: int = 100):
        self.timeout = timeout
        self.max_queries = max_queries
        self.cache = {}
        self.warnings = []
        self.offline = False
        # Ignore environment proxies, which might forward dependency metadata.
        self.opener = request.build_opener(request.ProxyHandler({}), NoRedirect())

    def query(self, dependency: Dependency) -> list[dict]:
        key = (dependency.ecosystem, dependency.name, dependency.version)
        if key in self.cache:
            return self.cache[key]
        if self.offline:
            return []
        if len(self.cache) >= self.max_queries:
            warning = (f"OSV query limit reached ({self.max_queries} unique versions); "
                       "remaining versions were skipped.")
            if warning not in self.warnings:
                self.warnings.append(warning)
            return []
        payload = json.dumps({
            "package": {"ecosystem": dependency.ecosystem, "name": dependency.name},
            "version": dependency.version,
        }).encode("utf-8")
        req = request.Request("https://api.osv.dev/v1/query", data=payload,
                              headers={"Content-Type": "application/json",
                                       "User-Agent": "SATAN-Reborn/1.0"}, method="POST")
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                body = response.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise ValueError("response too large")
            data = json.loads(body)
            vulns = data.get("vulns", [])
            if not isinstance(vulns, list) or any(not isinstance(v, dict) for v in vulns):
                raise ValueError("invalid vulnerability list")
            self.cache[key] = vulns
            return vulns
        except (OSError, error.URLError, HTTPException, ValueError, TypeError,
                AttributeError, RecursionError):
            # Never echo server bodies, proxy credentials, or exception text.
            self.offline = True
            self.warnings.append("OSV unavailable or returned invalid data; remaining online checks "
                                 "were skipped. Local checks are complete.")
            return []

    def findings(self, dependency: Dependency) -> list[Finding]:
        findings = []
        for vuln in self.query(dependency):
            if vuln.get("withdrawn"):
                continue
            advisory = str(vuln.get("id", "OSV-advisory"))
            if not re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", advisory):
                advisory = "OSV-advisory"
            database = vuln.get("database_specific", {})
            database = database if isinstance(database, dict) else {}
            severity = {
                "CRITICAL": Severity.CRYPT, "HIGH": Severity.HAUNT,
                "MODERATE": Severity.SPOOK, "MEDIUM": Severity.SPOOK,
                "LOW": Severity.WHISPER,
            }.get(str(database.get("severity", "")).upper(), Severity.HAUNT)
            findings.append(Finding(
                "deps.osv", severity, f"Known dependency vulnerability: {advisory}",
                dependency.file, dependency.line,
                "Review the advisory and upgrade to a fixed version. Re-lock and test dependencies. "
                "Unspecified advisory severity defaults to HAUNT.",
                "CWE-1395",
            ))
        return findings
