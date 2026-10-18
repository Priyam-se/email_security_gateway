import re
from urllib.parse import urlparse

# target brands frequently impersonated in phishing
COMMON_TARGETS = [
    "paypal", "microsoft", "google", "apple", "amazon",
    "netflix", "chase", "bankofamerica", "github", "facebook"
]

# common character substitutions used in typosquatting / homoglyphs
CHAR_SUBS = {
    "1": "l",
    "0": "o",
    "vv": "w",
    "rn": "m",
    "@": "a",
    "5": "s"
}


def normalize_domain(domain):
    """
    replaces visual substitute characters to find base brand imitation
    e.g. paypa1 -> paypal
    """
    clean = domain.lower()
    for fake, real in CHAR_SUBS.items():
        clean = clean.replace(fake, real)
    return clean


def analyze_url(url):
    findings = []
    penalty = 0

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return {"url": url, "findings": ["Invalid or unparseable URL"], "penalty": 10}

    # check for raw IP address in host
    if re.fullmatch(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        findings.append(f"Suspicious host: uses raw IP address instead of domain ({hostname})")
        penalty += 35

    # check normalized domain against common brand targets
    normalized = normalize_domain(hostname)
    for brand in COMMON_TARGETS:
        if brand in normalized and brand not in hostname:
            findings.append(f"Typosquatting detected: resembles '{brand}' using character substitution ({hostname})")
            penalty += 40
            break
        elif brand in hostname:
            # brand appears in subdomain or compound name e.g. paypal-verify-security.com
            # check if it's the authentic domain or a lookalike
            trusted_domain = f"{brand}.com"
            if hostname != trusted_domain and not hostname.endswith(f".{trusted_domain}"):
                findings.append(f"Deceptive domain: contains '{brand}' but is not an official domain ({hostname})")
                penalty += 30
                break

    # check for excessive subdomains (often used to obscure real host)
    parts = hostname.split(".")
    if len(parts) > 4:
        findings.append(f"Excessive subdomains ({len(parts)} levels): {hostname}")
        penalty += 15

    return {
        "url": url,
        "domain": hostname,
        "findings": findings,
        "penalty": penalty
    }


def scan_urls(url_list):
    """
    scans all urls found in the email and aggregates penalties
    """
    results = []
    total_penalty = 0

    for link in url_list:
        res = analyze_url(link)
        results.append(res)
        total_penalty += res["penalty"]

    # cap maximum url penalty at 60 points
    capped_penalty = min(total_penalty, 60)

    return {
        "scanned_count": len(url_list),
        "results": results,
        "total_penalty": capped_penalty
    }
