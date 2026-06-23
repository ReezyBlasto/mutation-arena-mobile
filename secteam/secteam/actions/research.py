"""
Research actions — the system's ability to look things up when confidence is low
or when an agent encounters something unknown.

Chain (fastest/cheapest first):
  1. Local knowledge base cache
  2. Man pages (instant, local)
  3. dpkg/apt package info (local)
  4. NVD/CVE API (free, no key)
  5. MITRE ATT&CK API (free, no key)
  6. AbuseIPDB (free tier, no key needed for basic)
  7. DuckDuckGo Instant Answers (no key)
  8. DuckDuckGo web search (no key)
  9. Synthesize and cache result
"""

from __future__ import annotations
import json
import logging
import re
import subprocess
from typing import Optional

import requests
from duckduckgo_search import DDGS

from secteam.models import ResearchResult
from secteam.core.knowledge_base import KnowledgeBase

log = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 10
_HEADERS = {"User-Agent": "secteam-research/1.0 (security audit system)"}


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


# ── 1. Local knowledge base ────────────────────────────────────────────────

def search_kb(query: str, kb: KnowledgeBase) -> Optional[ResearchResult]:
    return kb.get_research(query, source="any", max_age_hours=48)


# ── 2. Man pages ───────────────────────────────────────────────────────────

def lookup_manpage(term: str) -> ResearchResult:
    out = _run(["man", "-P", "cat", term], timeout=15)
    if not out:
        # try whatis for a shorter description
        out = _run(["whatis", term])
    content = out[:3000] if out else f"No man page found for '{term}'."
    return ResearchResult(
        query=term,
        source="manpage",
        content=content,
        confidence=0.95 if out else 0.3,
    )


# ── 3. Package database ────────────────────────────────────────────────────

def lookup_package(name: str) -> ResearchResult:
    # installed package info
    installed = _run(["dpkg", "-s", name])
    if installed and "Status: install ok installed" in installed:
        return ResearchResult(
            query=name,
            source="dpkg",
            content=installed[:2000],
            confidence=0.99,
        )
    # available but not installed
    available = _run(["apt-cache", "show", name])
    content = available[:2000] if available else f"Package '{name}' not found in apt cache."
    return ResearchResult(
        query=name,
        source="apt-cache",
        content=content,
        confidence=0.90 if available else 0.2,
    )


# ── 4. CVE / NVD lookup ────────────────────────────────────────────────────

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cve(cve_id: str) -> ResearchResult:
    """Query the NVD API for a specific CVE."""
    cve_id = cve_id.upper().strip()
    if not re.match(r"CVE-\d{4}-\d+", cve_id):
        return ResearchResult(
            query=cve_id, source="nvd",
            content=f"Invalid CVE format: {cve_id}", confidence=0.0,
        )
    try:
        r = requests.get(
            NVD_BASE,
            params={"cveId": cve_id},
            headers=_HEADERS,
            timeout=_REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return ResearchResult(
                query=cve_id, source="nvd",
                content=f"{cve_id} not found in NVD database.", confidence=0.6,
            )
        cve = vulns[0]["cve"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "No description available.",
        )
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity   = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_score = m.get("cvssData", {}).get("baseScore")
                severity   = m.get("cvssData", {}).get("baseSeverity")
                break

        refs = [r["url"] for r in cve.get("references", [])[:5]]
        content = (
            f"CVE: {cve_id}\n"
            f"CVSS Score: {cvss_score} ({severity})\n"
            f"Published: {cve.get('published', 'unknown')}\n"
            f"Description: {desc}\n"
            f"References: {chr(10).join(refs)}"
        )
        return ResearchResult(
            query=cve_id, source="nvd", content=content,
            confidence=0.98, urls=refs,
        )
    except requests.RequestException as e:
        log.warning("NVD API error for %s: %s", cve_id, e)
        return ResearchResult(
            query=cve_id, source="nvd",
            content=f"NVD API unavailable: {e}", confidence=0.0,
        )


def search_cves_for_package(package: str, version: str) -> ResearchResult:
    """Search NVD for CVEs affecting a specific package version."""
    try:
        r = requests.get(
            NVD_BASE,
            params={"keywordSearch": package, "resultsPerPage": 10},
            headers=_HEADERS,
            timeout=_REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        data  = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return ResearchResult(
                query=f"{package} {version}", source="nvd",
                content=f"No CVEs found for {package}", confidence=0.70,
            )
        items = []
        for v in vulns[:10]:
            cve  = v["cve"]
            cid  = cve.get("id", "")
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "",
            )[:200]
            items.append(f"• {cid}: {desc}")

        return ResearchResult(
            query=f"{package} {version}", source="nvd",
            content=f"CVEs for {package}:\n" + "\n".join(items),
            confidence=0.85,
        )
    except Exception as e:
        return ResearchResult(
            query=f"{package} {version}", source="nvd",
            content=f"NVD search error: {e}", confidence=0.0,
        )


# ── 5. MITRE ATT&CK ────────────────────────────────────────────────────────

MITRE_BASE = "https://attack.mitre.org/api"


def lookup_mitre(query: str) -> ResearchResult:
    """Search MITRE ATT&CK for techniques matching a query."""
    # Use the STIX data via raw URL — no auth needed
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            timeout=30,
            headers=_HEADERS,
        )
        r.raise_for_status()
        data = r.json()
        query_lower = query.lower()
        matches = []

        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()
            if query_lower in name or query_lower in desc:
                ext_refs = obj.get("external_references", [])
                tid = next(
                    (e["external_id"] for e in ext_refs if e.get("source_name") == "mitre-attack"),
                    "",
                )
                matches.append(f"• {tid}: {obj.get('name', '')}\n  {obj.get('description', '')[:200]}")
                if len(matches) >= 5:
                    break

        if not matches:
            return ResearchResult(
                query=query, source="mitre_attack",
                content=f"No MITRE ATT&CK techniques found matching '{query}'",
                confidence=0.50,
            )
        return ResearchResult(
            query=query, source="mitre_attack",
            content=f"MITRE ATT&CK — '{query}':\n" + "\n\n".join(matches),
            confidence=0.90,
        )
    except Exception as e:
        log.warning("MITRE ATT&CK lookup error: %s", e)
        return ResearchResult(
            query=query, source="mitre_attack",
            content=f"MITRE API error: {e}", confidence=0.0,
        )


# ── 6. AbuseIPDB (no key for basic checks) ────────────────────────────────

def check_ip_reputation(ip: str, api_key: Optional[str] = None) -> ResearchResult:
    if not api_key:
        # Fall back to a free check via ipinfo
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json",
                             headers=_HEADERS, timeout=_REQUEST_TIMEOUT)
            data = r.json()
            content = (
                f"IP: {ip}\n"
                f"ASN: {data.get('org', 'unknown')}\n"
                f"Country: {data.get('country', 'unknown')}\n"
                f"Region: {data.get('region', 'unknown')}\n"
                f"Hostname: {data.get('hostname', 'unknown')}\n"
                f"Note: Full abuse check requires AbuseIPDB API key."
            )
            return ResearchResult(
                query=ip, source="ipinfo", content=content, confidence=0.60,
            )
        except Exception as e:
            return ResearchResult(
                query=ip, source="ipinfo",
                content=f"IP info lookup failed: {e}", confidence=0.0,
            )

    # With API key — use AbuseIPDB
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={**_HEADERS, "Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=_REQUEST_TIMEOUT,
        )
        data = r.json().get("data", {})
        content = (
            f"IP: {ip}\n"
            f"Abuse confidence: {data.get('abuseConfidenceScore', 0)}%\n"
            f"ISP: {data.get('isp', 'unknown')}\n"
            f"Country: {data.get('countryCode', 'unknown')}\n"
            f"Total reports: {data.get('totalReports', 0)}\n"
            f"Last reported: {data.get('lastReportedAt', 'never')}\n"
            f"Usage type: {data.get('usageType', 'unknown')}"
        )
        confidence = 0.9 if data.get("totalReports", 0) > 0 else 0.7
        return ResearchResult(
            query=ip, source="abuseipdb", content=content, confidence=confidence,
        )
    except Exception as e:
        return ResearchResult(
            query=ip, source="abuseipdb",
            content=f"AbuseIPDB error: {e}", confidence=0.0,
        )


# ── 7-8. DuckDuckGo ────────────────────────────────────────────────────────

def web_search(query: str, max_results: int = 5) -> ResearchResult:
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return ResearchResult(
                query=query, source="duckduckgo",
                content="No web results found.", confidence=0.1,
            )

        lines = []
        urls  = []
        for r in results:
            lines.append(f"• {r.get('title', '')}\n  {r.get('body', '')[:300]}")
            if r.get("href"):
                urls.append(r["href"])

        return ResearchResult(
            query=query, source="duckduckgo",
            content="\n\n".join(lines),
            confidence=0.65,
            urls=urls,
        )
    except Exception as e:
        log.warning("DuckDuckGo search error: %s", e)
        return ResearchResult(
            query=query, source="duckduckgo",
            content=f"Search failed: {e}", confidence=0.0,
        )


# ── Main research dispatcher ────────────────────────────────────────────────

def research(query: str, kb: KnowledgeBase,
             api_key_abuseipdb: Optional[str] = None) -> ResearchResult:
    """
    Full research chain.  Tries sources in order, caches the best result.
    Automatically detects what kind of query this is and routes accordingly.
    """
    # Check cache first
    cached = search_kb(query, kb)
    if cached:
        log.debug("Research cache hit: %s", query)
        return cached

    result: Optional[ResearchResult] = None
    q_lower = query.lower()

    # CVE ID
    if re.search(r"cve-\d{4}-\d+", q_lower):
        cve_id = re.search(r"(cve-\d{4}-\d+)", q_lower, re.IGNORECASE)
        if cve_id:
            result = lookup_cve(cve_id.group(1))

    # IP address
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query.strip()):
        result = check_ip_reputation(query.strip(), api_key_abuseipdb)

    # Package name (short single word, likely a tool/package)
    elif re.match(r"^[a-z0-9][a-z0-9\-\.]+$", q_lower) and len(q_lower.split()) == 1:
        pkg = lookup_package(q_lower)
        if pkg.confidence > 0.5:
            result = pkg
        if not result or result.confidence < 0.7:
            man = lookup_manpage(q_lower)
            if man.confidence > (result.confidence if result else 0):
                result = man

    # MITRE technique
    elif "t1" in q_lower or "mitre" in q_lower or "ttp" in q_lower or "tactic" in q_lower:
        result = lookup_mitre(query)

    # Everything else → web search with security context
    if not result or result.confidence < 0.5:
        web = web_search(f"cybersecurity linux {query}")
        if not result or web.confidence > result.confidence:
            result = web

    if result and result.confidence >= 0.5:
        kb.save_research(result)

    return result or ResearchResult(
        query=query, source="none",
        content="No research results found.", confidence=0.0,
    )
