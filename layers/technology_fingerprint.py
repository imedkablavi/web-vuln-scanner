from __future__ import annotations

import re
from typing import Any, Dict, List

from bs4 import BeautifulSoup


_VERSION_RE = re.compile(r"(?<!\d)(\d+(?:\.\d+){0,3})(?!\d)")


def _confidence(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def fingerprint_snapshot(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return conservative technology observations for one HTTP snapshot.

    The function uses response headers, cookie names, generator metadata and a
    small set of framework-specific HTML markers. Cookie values and page text
    are never copied into the result.
    """

    headers = {str(k).lower(): str(v) for k, v in (snapshot.get("headers") or {}).items()}
    text = str(snapshot.get("text") or "")
    set_cookies = list(snapshot.get("set_cookies") or [])
    observations: Dict[str, Dict[str, Any]] = {}

    def add(
        name: str,
        *,
        category: str,
        score: int,
        signal: str,
        version: str = "",
    ) -> None:
        current = observations.setdefault(
            name,
            {
                "name": name,
                "category": category,
                "score": 0,
                "signals": [],
                "version": "",
            },
        )
        current["score"] = max(int(current["score"]), int(score))
        if signal not in current["signals"]:
            current["signals"].append(signal)
        if version and not current.get("version"):
            current["version"] = version

    server = headers.get("server", "")
    server_lower = server.lower()
    server_patterns = (
        ("nginx", "Nginx"),
        ("apache", "Apache HTTP Server"),
        ("cloudflare", "Cloudflare"),
        ("microsoft-iis", "Microsoft IIS"),
        ("litespeed", "LiteSpeed"),
        ("caddy", "Caddy"),
    )
    for marker, name in server_patterns:
        if marker in server_lower:
            version_match = _VERSION_RE.search(server)
            add(
                name,
                category="web-server",
                score=75,
                signal=f"header:server:{marker}",
                version=version_match.group(1) if version_match else "",
            )

    powered = headers.get("x-powered-by", "")
    powered_lower = powered.lower()
    powered_patterns = (
        ("php", "PHP", "runtime"),
        ("asp.net", "ASP.NET", "framework"),
        ("express", "Express", "framework"),
        ("next.js", "Next.js", "framework"),
    )
    for marker, name, category in powered_patterns:
        if marker in powered_lower:
            version_match = _VERSION_RE.search(powered)
            add(
                name,
                category=category,
                score=80,
                signal=f"header:x-powered-by:{marker}",
                version=version_match.group(1) if version_match else "",
            )

    cookie_blob = "\n".join(str(value) for value in set_cookies)
    cookie_markers = (
        (r"(?:^|[;,\s])PHPSESSID=", "PHP", "runtime"),
        (r"(?:^|[;,\s])JSESSIONID=", "Java Servlet", "runtime"),
        (r"(?:^|[;,\s])ASP\.NET_SessionId=", "ASP.NET", "framework"),
        (r"(?:^|[;,\s])laravel_session=", "Laravel", "framework"),
        (r"(?:^|[;,\s])csrftoken=", "Django", "framework"),
        (r"(?:^|[;,\s])connect\.sid=", "Express", "framework"),
    )
    for pattern, name, category in cookie_markers:
        if re.search(pattern, cookie_blob, re.IGNORECASE):
            add(
                name,
                category=category,
                score=65,
                signal=f"cookie-name:{name.lower().replace(' ', '-')}",
            )

    if text:
        soup = BeautifulSoup(text[:1_000_000], "html.parser")
        generator = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
        generator_value = str(generator.get("content", "")) if generator else ""
        generator_lower = generator_value.lower()
        for marker, name in (
            ("wordpress", "WordPress"),
            ("drupal", "Drupal"),
            ("joomla", "Joomla"),
            ("ghost", "Ghost"),
        ):
            if marker in generator_lower:
                version_match = _VERSION_RE.search(generator_value)
                add(
                    name,
                    category="cms",
                    score=95,
                    signal=f"meta:generator:{marker}",
                    version=version_match.group(1) if version_match else "",
                )

        html_lower = text[:1_000_000].lower()
        markers = (
            ("/wp-content/", "WordPress", "cms", 90),
            ("/wp-includes/", "WordPress", "cms", 90),
            ("/_next/", "Next.js", "framework", 90),
            ("__next_data__", "Next.js", "framework", 95),
            ("/_nuxt/", "Nuxt", "framework", 90),
            ("ng-version=", "Angular", "framework", 90),
            ("data-reactroot", "React", "frontend", 70),
        )
        for marker, name, category, score in markers:
            if marker in html_lower:
                add(
                    name,
                    category=category,
                    score=score,
                    signal=f"html-marker:{marker}",
                )

    result = []
    for item in observations.values():
        score = int(item.pop("score"))
        item["confidence"] = _confidence(score)
        item["signals"] = sorted(item["signals"])
        result.append(item)
    return sorted(result, key=lambda item: (item["category"], item["name"]))
