
import ipaddress
import re
from urllib.parse import urlsplit


# The exact feature order specified in the SDS.
FEATURE_ORDER = [
    "uses_https",
    "hostname_is_ip",
    "url_length",
    "subdomain_count",
    "suspicious_keyword_count",
    "special_char_count",
    "encoded_char_count",
    "has_at_symbol",
    "brand_misuse",
]

# Initial keyword configuration.
# We can refine this list during data preparation and testing.
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "confirm",
    "signin",
    "wallet",
    "payment",
]

SPECIAL_CHARACTERS = [
    "@", "-", "_", ".", "=", "?", "%", "&", "#"
]

# Known multi-part public suffixes for our initial
# subdomain-counting implementation.
# This list can be expanded and documented later.
MULTI_PART_SUFFIXES = {
    "co.ke", "or.ke", "go.ke", "ac.ke", "sc.ke",
    "com.au", "net.au", "org.au",
    "co.uk", "org.uk", "ac.uk",
    "co.in", "com.br", "co.za",
    "com.ng", "com.sg", "com.my",
}

# Brand configuration will be populated with verified
# brand names, aliases and legitimate domains.
BRAND_NAMES = {}


def is_ip_address(hostname):
    """Return True if the hostname is an IP address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def count_subdomains(hostname):
    """
    Estimate the number of subdomain labels.

    This initial implementation uses a configured list
    of common multi-part public suffixes.
    """
    hostname = hostname.lower().strip(".")

    if not hostname or is_ip_address(hostname):
        return 0

    labels = hostname.split(".")

    if len(labels) <= 2:
        return 0

    last_two = ".".join(labels[-2:])

    if last_two in MULTI_PART_SUFFIXES:
        return max(0, len(labels) - 3)

    return max(0, len(labels) - 2)


def count_suspicious_keywords(url_parts):
    """Count configured keyword occurrences."""
    text = " ".join([
        url_parts.hostname or "",
        url_parts.path or "",
        url_parts.query or "",
    ]).lower()

    count = 0

    for keyword in SUSPICIOUS_KEYWORDS:
        count += len(
            re.findall(re.escape(keyword.lower()), text)
        )

    return count


def count_special_characters(url):
    """Count configured special-character occurrences."""
    return sum(url.count(char) for char in SPECIAL_CHARACTERS)


def count_encoded_characters(url):
    """Count percent-encoded character sequences."""
    return len(re.findall(r"%[0-9a-fA-F]{2}", url))


def check_brand_misuse(url_parts):
    """
    Check for configured brand names or aliases outside
    their legitimate domains.

    Returns 0 until verified brand configurations are added.
    """
    hostname = (url_parts.hostname or "").lower()
    path = (url_parts.path or "").lower()

    searchable_text = hostname + " " + path

    for brand, details in BRAND_NAMES.items():
        names = [brand.lower()]
        names.extend(
            alias.lower()
            for alias in details.get("aliases", [])
        )

        legitimate_domains = details.get(
            "legitimate_domains", []
        )

        legitimate = any(
            hostname == domain.lower()
            or hostname.endswith("." + domain.lower())
            for domain in legitimate_domains
        )

        if legitimate:
            continue

        if any(name in searchable_text for name in names):
            return 1

    return 0


def extract_features(url):
    """
    Extract the nine features from a submitted URL.

    Returns a dictionary in the exact FEATURE_ORDER.
    This function does not open the URL or make network requests.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("A URL must be provided.")

    url = url.strip()
    parts = urlsplit(url)

    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    hostname = parts.hostname

    if not hostname:
        raise ValueError("The URL must contain a hostname.")

    hostname = hostname.lower()

    features = {
        "uses_https": int(parts.scheme.lower() == "https"),
        "hostname_is_ip": int(is_ip_address(hostname)),
        "url_length": len(url),
        "subdomain_count": count_subdomains(hostname),
        "suspicious_keyword_count": count_suspicious_keywords(parts),
        "special_char_count": count_special_characters(url),
        "encoded_char_count": count_encoded_characters(url),
        "has_at_symbol": int("@" in parts.netloc),
        "brand_misuse": check_brand_misuse(parts),
    }

    return {name: features[name] for name in FEATURE_ORDER}
