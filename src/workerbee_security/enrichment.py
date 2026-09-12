import base64
import ipaddress
import json
import os
from typing import Any, Dict, Iterable, List
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from . import __version__


class EnrichmentError(RuntimeError):
    pass


def _request_json(url: str, headers: Dict[str, str], timeout: float) -> Dict[str, Any]:
    request = Request(url, headers={**headers, "User-Agent": f"workerbee-security/{__version__}"})
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(2_000_001)
            if len(payload) > 2_000_000:
                raise EnrichmentError("response exceeded 2 MB")
            decoded = json.loads(payload.decode("utf-8"))
    except HTTPError as exc:
        raise EnrichmentError(f"HTTP {exc.code}") from exc
    except URLError as exc:
        raise EnrichmentError(f"network error: {exc.reason}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnrichmentError("provider returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise EnrichmentError("provider returned an unexpected response")
    return decoded


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


class AbuseIPDB:
    name = "abuseipdb"

    def __init__(self, api_key: str, timeout: float) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def supports(self, indicator: Dict[str, Any]) -> bool:
        return indicator["type"] == "ip" and _public_ip(indicator["value"])

    def lookup(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        query = urlencode({"ipAddress": indicator["value"], "maxAgeInDays": 90})
        response = _request_json(
            f"https://api.abuseipdb.com/api/v2/check?{query}",
            {"Accept": "application/json", "Key": self.api_key},
            self.timeout,
        )
        data = response.get("data", {})
        if not isinstance(data, dict):
            raise EnrichmentError("provider response did not contain data")
        fields = (
            "abuseConfidenceScore",
            "countryCode",
            "domain",
            "isPublic",
            "isTor",
            "isWhitelisted",
            "isp",
            "lastReportedAt",
            "totalReports",
            "usageType",
        )
        return {field: data.get(field) for field in fields if field in data}


class VirusTotal:
    name = "virustotal"

    def __init__(self, api_key: str, timeout: float) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def supports(self, indicator: Dict[str, Any]) -> bool:
        kind = indicator["type"]
        return kind in {"domain", "md5", "sha1", "sha256", "url"} or (
            kind == "ip" and _public_ip(indicator["value"])
        )

    def _path(self, kind: str, value: str) -> str:
        if kind == "ip":
            return f"ip_addresses/{quote(value, safe='')}"
        if kind == "domain":
            return f"domains/{quote(value, safe='')}"
        if kind in {"md5", "sha1", "sha256"}:
            return f"files/{value}"
        url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
        return f"urls/{url_id}"

    def lookup(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        response = _request_json(
            f"https://www.virustotal.com/api/v3/{self._path(indicator['type'], indicator['value'])}",
            {"Accept": "application/json", "x-apikey": self.api_key},
            self.timeout,
        )
        data = response.get("data", {})
        attributes = data.get("attributes", {}) if isinstance(data, dict) else {}
        if not isinstance(attributes, dict):
            raise EnrichmentError("provider response did not contain attributes")
        fields = (
            "as_owner",
            "asn",
            "categories",
            "country",
            "last_analysis_date",
            "last_analysis_stats",
            "last_modification_date",
            "reputation",
            "tags",
            "times_submitted",
            "total_votes",
        )
        return {field: attributes.get(field) for field in fields if field in attributes}


def providers(names: Iterable[str], timeout: float) -> List[Any]:
    built = []
    for name in dict.fromkeys(names):
        if name == "abuseipdb":
            key = os.environ.get("ABUSEIPDB_API_KEY")
            if not key:
                raise EnrichmentError("ABUSEIPDB_API_KEY is required for AbuseIPDB")
            built.append(AbuseIPDB(key, timeout))
        elif name == "virustotal":
            key = os.environ.get("VIRUSTOTAL_API_KEY")
            if not key:
                raise EnrichmentError("VIRUSTOTAL_API_KEY is required for VirusTotal")
            built.append(VirusTotal(key, timeout))
        else:
            raise EnrichmentError(f"unknown enrichment provider: {name}")
    return built


def enrich(
    indicators: List[Dict[str, Any]],
    provider_names: Iterable[str],
    max_items: int = 25,
    timeout: float = 10.0,
) -> Dict[str, int]:
    clients = providers(provider_names, timeout)
    counts = {client.name: 0 for client in clients}

    for client in clients:
        for indicator in indicators:
            if counts[client.name] >= max_items:
                break
            if not client.supports(indicator):
                continue
            counts[client.name] += 1
            try:
                data = client.lookup(indicator)
                indicator["enrichment"][client.name] = {"status": "ok", "data": data}
            except EnrichmentError as exc:
                indicator["enrichment"][client.name] = {
                    "status": "error",
                    "error": str(exc),
                }
    return counts
