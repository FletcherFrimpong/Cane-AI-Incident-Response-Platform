"""Integration registry: maps platform names to client classes and metadata."""

from app.integrations.base_client import BaseIntegrationClient
from app.integrations.crowdstrike import CrowdStrikeClient
from app.integrations.elastic import ElasticClient
from app.integrations.fortinet import FortiGateClient
from app.integrations.geoip import GeoIpClient
from app.integrations.greynoise import GreyNoiseClient
from app.integrations.guardduty import GuardDutyClient
from app.integrations.hybrid_analysis import HybridAnalysisClient
from app.integrations.jira import JiraClient
from app.integrations.microsoft_defender import MicrosoftDefenderClient
from app.integrations.microsoft_graph import MicrosoftGraphClient
from app.integrations.microsoft_sentinel import MicrosoftSentinelClient
from app.integrations.misp import MispClient
from app.integrations.okta import OktaClient
from app.integrations.opencti import OpenCtiClient
from app.integrations.opsgenie import OpsgenieClient
from app.integrations.pagerduty import PagerDutyClient
from app.integrations.paloalto import PaloAltoClient
from app.integrations.rdap import RdapClient
from app.integrations.sentinelone import SentinelOneClient
from app.integrations.servicenow import ServiceNowClient
from app.integrations.slack import SlackClient
from app.integrations.splunk import SplunkClient
from app.integrations.teams import TeamsClient
from app.integrations.threat_intel import AbuseIPDBClient, VirusTotalClient
from app.integrations.urlscan import UrlscanClient
from app.integrations.webhook import GenericWebhookClient

_CLIENTS: list[type[BaseIntegrationClient]] = [
    # Response: carry out containment actions
    MicrosoftDefenderClient, MicrosoftGraphClient, MicrosoftSentinelClient,
    CrowdStrikeClient, SentinelOneClient, OktaClient, PaloAltoClient, FortiGateClient,
    # Threat intelligence and context
    VirusTotalClient, AbuseIPDBClient, GreyNoiseClient, UrlscanClient, RdapClient, GeoIpClient,
    HybridAnalysisClient, MispClient, OpenCtiClient,
    # Notifications and paging
    SlackClient, TeamsClient, PagerDutyClient, OpsgenieClient, GenericWebhookClient,
    # Ticketing
    JiraClient, ServiceNowClient,
    # Log and alert sources
    SplunkClient, ElasticClient, GuardDutyClient,
]

# Registry of all supported platform integrations, keyed by platform name
INTEGRATION_REGISTRY: dict[str, type[BaseIntegrationClient]] = {cls.platform_name: cls for cls in _CLIENTS}
assert len(INTEGRATION_REGISTRY) == len(_CLIENTS), "two connectors share a platform_name"


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
            "optional_credentials": cls.optional_credentials,
            "optional_config": cls.optional_config,
            "capabilities": cls.capabilities,
            "category": cls.category,
            "actions": sorted(cls.actions),
            "enriches": list(cls.enriches),
            "provides_context": list(cls.provides_context),
        })
    return platforms
