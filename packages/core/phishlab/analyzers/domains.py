from __future__ import annotations

from pathlib import Path

import yaml

from phishlab.analyzers.base import BaseAnalyzer
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Category, Finding, Severity
from phishlab.utils.text_utils import extract_domain

_RULES_DIR = Path(__file__).resolve().parents[4] / "rules"

_CHAR_SUBS: dict[str, list[str]] = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l", "!"],
    "a": ["@", "4"],
    "e": ["3"],
    "s": ["5", "$"],
    "t": ["7"],
    "g": ["9"],
}

_SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "secure", "security", "account", "update", "confirm",
    "support", "service", "alert", "notify", "notification",
]


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row

    return prev_row[-1]


def _has_char_substitution(domain: str, brand: str) -> bool:
    if len(domain) != len(brand):
        return False
    diffs = 0
    for dc, bc in zip(domain, brand):
        if dc != bc:
            subs = _CHAR_SUBS.get(bc, [])
            if dc not in subs:
                return False
            diffs += 1
    return 0 < diffs <= 2


def _load_brands() -> list[dict]:
    path = _RULES_DIR / "brands.yml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data.get("brands", [])


class DomainAnalyzer(BaseAnalyzer):
    def __init__(self) -> None:
        self._brands = _load_brands()
        self._all_legit_domains: set[str] = set()
        for brand in self._brands:
            self._all_legit_domains.add(brand["domain"])
            for alias in brand.get("aliases", []):
                self._all_legit_domains.add(alias)

    def analyze(self, email: NormalizedEmail) -> list[Finding]:
        findings: list[Finding] = []
        checked_domains: set[str] = set()

        domains_to_check: list[str] = []

        from_domain = extract_domain(email.from_address)
        if from_domain:
            domains_to_check.append(from_domain)

        if email.reply_to:
            rt_domain = extract_domain(email.reply_to)
            if rt_domain:
                domains_to_check.append(rt_domain)

        for link in email.links:
            if link.target_domain:
                domains_to_check.append(link.target_domain)

        for domain in domains_to_check:
            domain_lower = domain.lower()
            if domain_lower in checked_domains or domain_lower in self._all_legit_domains:
                continue
            checked_domains.add(domain_lower)

            base_domain = _extract_base_domain(domain_lower)

            for brand in self._brands:
                brand_base = brand["domain"].split(".")[0]
                domain_base = base_domain.split(".")[0]

                distance = _levenshtein(domain_base, brand_base)
                if 0 < distance <= 2:
                    findings.append(Finding(
                        title=f"Possible typosquatting of {brand['name']}",
                        category=Category.BRAND_IMPERSONATION,
                        severity=Severity.HIGH,
                        description=(
                            f"The domain '{domain_lower}' is very similar to {brand['name']} "
                            f"({brand['domain']}), with a Levenshtein distance of {distance}."
                        ),
                        evidence=f"Domain: {domain_lower}, Brand: {brand['domain']}, Distance: {distance}",
                        recommendation=f"Verify this is not an impersonation of {brand['name']}.",
                        location=f"Domain: {domain_lower}",
                        tags=["typosquatting"],
                    ))
                    break

                if _has_char_substitution(domain_base, brand_base):
                    findings.append(Finding(
                        title=f"Character substitution impersonating {brand['name']}",
                        category=Category.BRAND_IMPERSONATION,
                        severity=Severity.HIGH,
                        description=(
                            f"The domain '{domain_lower}' uses character substitution to "
                            f"impersonate {brand['name']} ({brand['domain']})."
                        ),
                        evidence=f"Domain: {domain_lower}, Brand: {brand['domain']}",
                        recommendation=f"This domain is likely impersonating {brand['name']}.",
                        location=f"Domain: {domain_lower}",
                        tags=["char-substitution"],
                    ))
                    break

                if brand_base in domain_base and domain_base != brand_base:
                    if any(kw in domain_base for kw in _SUSPICIOUS_KEYWORDS):
                        findings.append(Finding(
                            title=f"Suspicious domain containing {brand['name']} brand name",
                            category=Category.BRAND_IMPERSONATION,
                            severity=Severity.MEDIUM,
                            description=(
                                f"The domain '{domain_lower}' contains the brand name "
                                f"'{brand_base}' along with suspicious keywords."
                            ),
                            evidence=f"Domain: {domain_lower}, Brand: {brand['domain']}",
                            recommendation=f"Verify this domain is officially associated with {brand['name']}.",
                            location=f"Domain: {domain_lower}",
                            confidence=0.7,
                            tags=["brand-keyword"],
                        ))
                        break

        return findings


def _extract_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain
