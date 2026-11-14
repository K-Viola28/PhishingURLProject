
import re
from urllib.parse import urlsplit


MAX_URL_LENGTH = 2048


def validate_url(url):
    """
    Validate a submitted URL without opening it
    or making any network requests.
    """

    if not isinstance(url, str):
        raise ValueError("The URL must be text.")

    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if len(url) > MAX_URL_LENGTH:
        raise ValueError("The URL is too long.")

    if re.search(r"\s", url):
        raise ValueError("The URL must not contain whitespace.")

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("The URL contains invalid control characters.")

    try:
        parts = urlsplit(url)

        if parts.scheme.lower() not in ("http", "https"):
            raise ValueError(
                "Only HTTP and HTTPS URLs are supported."
            )

        if not parts.netloc or not parts.hostname:
            raise ValueError(
                "The URL must contain a valid hostname."
            )

        # Accessing the port also checks whether it is valid.
        if parts.port is not None:
            if not 1 <= parts.port <= 65535:
                raise ValueError("The URL contains an invalid port.")

        hostname = parts.hostname

        if hostname.startswith(".") or hostname.endswith("."):
            raise ValueError("The hostname is invalid.")

        if ".." in hostname:
            raise ValueError("The hostname is invalid.")

    except ValueError:
        raise

    except Exception:
        raise ValueError("Please enter a valid URL.")

    return url
