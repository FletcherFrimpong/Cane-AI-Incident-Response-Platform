"""Integration registry: maps platform names to client classes and metadata."""

from app.integrations.base_client import BaseIntegrationClient
from app.integrations.microsoft_graph import MicrosoftGraphClient
from app.integrations.microsoft_sentinel import MicrosoftSentinelClient
from app.integrations.microsoft_defender import MicrosoftDefenderClient
from app.integrations.threat_intel import VirusTotalClient, AbuseIPDBClient


# Registry of all supported platform integrations
INTEGRATION_REGISTRY: dict[str, type[BaseIntegrationClient]] = {
    "microsoft_graph": MicrosoftGraphClient,
    "microsoft_sentinel": MicrosoftSentinelClient,
    "microsoft_defender": MicrosoftDefenderClient,
    "virustotal": VirusTotalClient,
    "abuseipdb": AbuseIPDBClient,
}


def get_integration_class(platform: str) -> type[BaseIntegrationClient] | None:
    """Get the integration client class for a platform."""
    return INTEGRATION_REGISTRY.get(platform)


def get_all_platform_info() -> list[dict]:
    """Get metadata for all supported platforms."""
    platforms = []
    for name, cls in INTEGRATION_REGISTRY.items():
        platforms.append({
            "platform": name,
            "display_name": cls.display_name,
            "description": cls.description,
            "auth_type": cls.auth_type,
            "required_credentials": cls.required_credentials,
            "optional_config": cls.optional_config,
            "capabilities": cls.capabilities,
        })
    return platforms
