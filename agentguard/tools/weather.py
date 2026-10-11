"""Weather providers. The legacy tool.py ignored its `city` argument and always queried Bengaluru.
Here the requested location is honoured; an unknown location is an error, never a silent default."""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Callable

from ..errors import ToolError

# Synthetic, offline data (default). Values are fixed fakes, labelled as simulated.
_SIMULATED = {
    "bengaluru": (12.97, 77.59, 24.0, 61, "Partly cloudy"),
    "chennai": (13.08, 80.27, 31.0, 72, "Mainly clear"),
    "tokyo": (35.68, 139.69, 19.0, 55, "Overcast"),
    "london": (51.51, -0.13, 12.0, 80, "Light rain"),
    "goa": (15.30, 74.08, 30.0, 78, "Clear sky"),
}
_WMO = {0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast", 45: "Fog", 48: "Fog",
        51: "Light drizzle", 53: "Drizzle", 55: "Heavy drizzle", 61: "Light rain", 63: "Rain",
        65: "Heavy rain", 80: "Rain showers", 81: "Rain showers", 82: "Heavy rain showers", 95: "Thunderstorm"}


class SimulatedWeather:
    source = "simulated"

    def get(self, city: str) -> dict:
        row = _SIMULATED.get(city.strip().lower())
        if row is None:
            raise ToolError("UNKNOWN_LOCATION", f"no simulated data for '{city}'")
        lat, lon, t, h, d = row
        return {"location": city.strip().title(), "latitude": lat, "longitude": lon,
                "temperature_c": t, "humidity_pct": h, "description": d, "source": self.source}


class OpenMeteoWeather:
    """Live provider. Disabled by default. Outbound hosts are pinned to an allowlist and requests
    have a hard timeout. `fetch_json` is injectable so tests never touch the network."""
    source = "open-meteo"
    ALLOWED_HOSTS = frozenset({"geocoding-api.open-meteo.com", "api.open-meteo.com"})

    def __init__(self, fetch_json: Callable[[str], dict] | None = None, timeout: float = 4.0):
        self._fetch = fetch_json or self._default_fetch
        self.timeout = timeout

    def _check(self, url: str) -> None:
        p = urllib.parse.urlparse(url)
        if p.scheme != "https" or p.hostname not in self.ALLOWED_HOSTS:
            raise ToolError("EGRESS_BLOCKED", "destination not on the outbound allowlist")

    def _default_fetch(self, url: str) -> dict:
        self._check(url)
        with urllib.request.urlopen(url, timeout=self.timeout) as r:  # nosec - host pinned above
            return json.loads(r.read(200_000))

    def get(self, city: str) -> dict:
        geo_url = "https://geocoding-api.open-meteo.com/v1/search?" + urllib.parse.urlencode(
            {"name": city, "count": 1, "language": "en", "format": "json"})
        self._check(geo_url)
        geo = self._fetch(geo_url)
        results = geo.get("results") or []
        if not results:
            raise ToolError("UNKNOWN_LOCATION", f"location '{city}' not found")
        g = results[0]
        lat, lon = float(g["latitude"]), float(g["longitude"])
        wx_url = "https://api.open-meteo.com/v1/forecast?" + urllib.parse.urlencode(
            {"latitude": lat, "longitude": lon, "current": "temperature_2m,relative_humidity_2m,weather_code"})
        self._check(wx_url)
        cur = (self._fetch(wx_url) or {}).get("current") or {}
        try:
            return {"location": str(g.get("name", city)), "latitude": lat, "longitude": lon,
                    "temperature_c": float(cur["temperature_2m"]), "humidity_pct": float(cur["relative_humidity_2m"]),
                    "description": _WMO.get(int(cur["weather_code"]), "Unknown"), "source": self.source}
        except (KeyError, TypeError, ValueError) as e:
            raise ToolError("UPSTREAM_BAD_RESPONSE", "weather provider returned an unexpected payload") from e
