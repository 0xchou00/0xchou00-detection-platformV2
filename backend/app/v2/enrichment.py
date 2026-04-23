from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.v2.config import settings

try:
    import geoip2.database
except ImportError:  # pragma: no cover
    geoip2 = None


@dataclass(slots=True)
class EnrichedContext:
    geoip: dict[str, Any]
    asn: dict[str, Any]
    asset: dict[str, Any]
    user_identity: dict[str, Any]
    reputation: dict[str, Any]
    suppression: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "geoip": self.geoip,
            "asn": self.asn,
            "asset": self.asset,
            "user_identity": self.user_identity,
            "reputation": self.reputation,
            "suppression": self.suppression,
        }


class EnrichmentService:
    def __init__(self) -> None:
        self.assets = self._load_yaml(settings.assets_path).get("assets", [])
        self.identities = self._load_yaml(settings.identities_path).get("identities", [])
        self.reputation = self._load_yaml(settings.reputation_path).get("reputation", {})
        self.suppressions = self._load_yaml(settings.suppressions_path)
        self._city_reader = self._open_reader(settings.geoip_city_path)
        self._asn_reader = self._open_reader(settings.geoip_asn_path)

    def enrich(
        self,
        event_payload: dict[str, Any] | None = None,
        *,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        username: str | None = None,
        user_agent: str | None = None,
        source_type: str | None = None,
    ) -> dict[str, Any]:
        payload = event_payload or {}
        source_ip = source_ip or payload.get("source_ip")
        destination_ip = destination_ip or payload.get("destination_ip")
        destination_port = destination_port or payload.get("destination_port")
        username = username or payload.get("username") or payload.get("metadata", {}).get("username")
        user_agent = user_agent or payload.get("user_agent") or payload.get("metadata", {}).get("user_agent")

        context = EnrichedContext(
            geoip=self._geo_context(source_ip),
            asn=self._asn_context(source_ip),
            asset=self._asset_context(destination_ip, destination_port),
            user_identity=self._identity_context(username),
            reputation=self._reputation_context(source_ip),
            suppression=self._suppression_context(source_ip, username, user_agent),
        )
        return context.to_dict()

    def _geo_context(self, ip: str | None) -> dict[str, Any]:
        if not ip:
            return {"country": None, "city": None}
        if self._is_private(ip):
            return {"country": "LAB", "city": "PRIVATE"}
        if self._city_reader is None:
            return {"country": None, "city": None}
        try:
            city = self._city_reader.city(ip)
        except Exception:
            return {"country": None, "city": None}
        return {"country": city.country.iso_code, "city": city.city.name}

    def _asn_context(self, ip: str | None) -> dict[str, Any]:
        if not ip:
            return {"asn": None, "organization": None}
        if self._is_private(ip):
            return {"asn": 64512, "organization": "private-lab"}
        if self._asn_reader is None:
            return {"asn": None, "organization": None}
        try:
            asn = self._asn_reader.asn(ip)
        except Exception:
            return {"asn": None, "organization": None}
        return {"asn": asn.autonomous_system_number, "organization": asn.autonomous_system_organization}

    def _asset_context(self, destination_ip: str | None, destination_port: int | None) -> dict[str, Any]:
        for asset in self.assets:
            if destination_ip and asset.get("ip") != destination_ip:
                continue
            for service in asset.get("services", []):
                if destination_port and int(service.get("port")) == int(destination_port):
                    return {
                        "asset_id": asset.get("asset_id"),
                        "role": asset.get("role"),
                        "service_criticality": asset.get("service_criticality"),
                        "service_name": service.get("name"),
                    }
            if destination_ip and asset.get("ip") == destination_ip:
                return {
                    "asset_id": asset.get("asset_id"),
                    "role": asset.get("role"),
                    "service_criticality": asset.get("service_criticality"),
                    "service_name": None,
                }
        return {"asset_id": None, "role": None, "service_criticality": None, "service_name": None}

    def _identity_context(self, username: str | None) -> dict[str, Any]:
        if not username:
            return {"username": None, "display_name": None, "identity_type": None}
        for identity in self.identities:
            if identity.get("username") == username:
                return {
                    "username": username,
                    "display_name": identity.get("display_name"),
                    "identity_type": identity.get("identity_type"),
                }
        return {"username": username, "display_name": username, "identity_type": "unknown"}

    def _reputation_context(self, ip: str | None) -> dict[str, Any]:
        if not ip:
            return {"score": 0, "labels": []}
        entry = (self.reputation.get("suspicious_ips") or {}).get(ip, {})
        return {"score": int(entry.get("score", 0)), "labels": list(entry.get("labels") or [])}

    def _suppression_context(self, ip: str | None, username: str | None, user_agent: str | None) -> dict[str, Any]:
        allowlist = self.suppressions.get("allowlist", {})
        if ip and ip in (allowlist.get("source_ips") or []):
            return {"suppressed": True, "reason": "allowlisted_source_ip"}
        if username and username in (allowlist.get("usernames") or []):
            return {"suppressed": True, "reason": "allowlisted_username"}
        for rule in self.suppressions.get("suppression_rules", []):
            match = rule.get("match", {})
            ua_fragment = match.get("user_agent_contains")
            if ua_fragment and ua_fragment.lower() in str(user_agent or "").lower():
                return {"suppressed": True, "reason": rule.get("name", "suppression_rule")}
        return {"suppressed": False, "reason": None}

    def _open_reader(self, path: Path):
        if geoip2 is None or not path.exists():
            return None
        try:
            return geoip2.database.Reader(str(path))
        except Exception:
            return None

    def _load_yaml(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return payload if isinstance(payload, dict) else {}

    def _is_private(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_link_local
            or address.is_multicast
        )
