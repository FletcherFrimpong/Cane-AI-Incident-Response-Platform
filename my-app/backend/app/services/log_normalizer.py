"""
Log normalizer for Azure Sentinel ASIM schema log types.
Each normalizer extracts common fields from schema-specific structures
into the flat LogEvent columns while preserving raw data in JSONB.
"""

from datetime import datetime
from typing import Any
from dateutil import parser as date_parser


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return date_parser.isoparse(value)
    return datetime.utcnow()


def _extract_severity(data: dict, default: str = "info") -> str:
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
        "info": "info",
        "0": "info",
        "1": "info",
        "2": "low",
        "3": "medium",
        "4": "high",
        "5": "critical",
        "8": "high",
        "10": "critical",
    }
    for field in ["AlertSeverity", "Severity", "LogSeverity", "ThreatSeverity", "EventLevelName", "Level"]:
        val = data.get(field)
        if val is not None:
            val_str = str(val).lower().strip()
            if val_str in severity_map:
                return severity_map[val_str]
    return default


def _safe_ip(value: Any) -> str | None:
    if not value or str(value).strip() in ("", "-", "N/A", "null", "none"):
        return None
    ip = str(value).strip()
    # Basic validation - just check it looks like an IP
    parts = ip.split(".")
    if len(parts) == 4:
        return ip
    if ":" in ip:  # IPv6
        return ip
    return None


def normalize_security_alert(data: dict) -> dict:
    entities = data.get("Entities", [])
    source_ip = None
    host = None
    user_identity = None
    for entity in entities if isinstance(entities, list) else []:
        if isinstance(entity, dict):
            if entity.get("Type") == "ip" or "Address" in entity:
                source_ip = source_ip or entity.get("Address") or entity.get("Value")
            if entity.get("Type") == "host" or "HostName" in entity:
                host = host or entity.get("HostName") or entity.get("Value")
            if entity.get("Type") == "account" or "Name" in entity:
                user_identity = user_identity or entity.get("Name") or entity.get("Value")

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", data.get("ProviderName", "unknown")),
        "log_type": "SecurityAlert",
        "schema_id": "securityalert",
        "correlation_id": data.get("CorrelationId"),
        "severity": _extract_severity(data, "high"),
        "summary": data.get("DisplayName") or data.get("AlertName") or data.get("Description", ""),
        "source_ip": _safe_ip(source_ip),
        "destination_ip": None,
        "user_identity": user_identity,
        "host": host or data.get("CompromisedEntity"),
        "raw_data": data,
    }


def normalize_security_event(data: dict) -> dict:
    event_id = data.get("EventID", "")
    activity = data.get("Activity", "")
    summary = f"EventID {event_id}: {activity}" if event_id else activity

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", "unknown"),
        "log_type": "SecurityEvent",
        "schema_id": "securityevent",
        "correlation_id": data.get("CorrelationId"),
        "severity": _extract_severity(data, "info"),
        "summary": summary,
        "source_ip": _safe_ip(data.get("IpAddress") or data.get("SourceAddress")),
        "destination_ip": _safe_ip(data.get("DestinationAddress")),
        "user_identity": data.get("Account") or data.get("AccountName") or data.get("TargetUserName"),
        "host": data.get("Computer"),
        "raw_data": data,
    }


def normalize_signin_logs(data: dict) -> dict:
    location = data.get("LocationDetails", {})
    if isinstance(location, str):
        location = {}
    city = location.get("City", "") if isinstance(location, dict) else ""
    country = location.get("CountryOrRegion", "") if isinstance(location, dict) else ""
    loc_str = f"{city}, {country}".strip(", ")

    user_name = data.get("UserPrincipalName") or data.get("UserDisplayName") or data.get("Identity", "")
    summary = f"Sign-in: {user_name}"
    if loc_str:
        summary += f" from {loc_str}"

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", "Azure AD"),
        "log_type": "SignInLogs",
        "schema_id": "signinlogs",
        "correlation_id": data.get("CorrelationId"),
        "severity": _extract_severity(data, "info"),
        "summary": summary,
        "source_ip": _safe_ip(data.get("IPAddress")),
        "destination_ip": None,
        "user_identity": user_name,
        "host": None,
        "raw_data": data,
    }


def normalize_common_security_log(data: dict) -> dict:
    vendor = data.get("DeviceVendor", "")
    product = data.get("DeviceProduct", "")
    action = data.get("DeviceAction") or data.get("Activity", "")
    summary = f"{vendor} {product}: {action}".strip()

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", f"{vendor} {product}"),
        "log_type": "CommonSecurityLog",
        "schema_id": "commonsecuritylog",
        "correlation_id": data.get("CorrelationId"),
        "severity": _extract_severity(data, "info"),
        "summary": summary,
        "source_ip": _safe_ip(data.get("SourceIP")),
        "destination_ip": _safe_ip(data.get("DestinationIP")),
        "user_identity": data.get("SourceUserName"),
        "host": data.get("Computer") or data.get("DeviceName"),
        "raw_data": data,
    }


def normalize_email_events(data: dict) -> dict:
    subject = data.get("Subject", "")
    sender = data.get("SenderMailFromAddress") or data.get("SenderDisplayName", "")
    recipient = data.get("RecipientEmailAddress", "")
    direction = data.get("EmailDirection", "")
    threat = data.get("ThreatTypes", "")
    summary = f"Email {direction}: '{subject}' from {sender} to {recipient}"
    if threat:
        summary += f" [Threat: {threat}]"

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated", data.get("Timestamp"))),
        "source_system": data.get("SourceSystem", "Microsoft Defender for Office 365"),
        "log_type": "EmailEvents",
        "schema_id": "emailevents",
        "correlation_id": data.get("CorrelationId"),
        "severity": "high" if threat else "info",
        "summary": summary,
        "source_ip": _safe_ip(data.get("SenderIPv4")),
        "destination_ip": None,
        "user_identity": recipient,
        "host": None,
        "raw_data": data,
    }


def normalize_email_attachment_info(data: dict) -> dict:
    filename = data.get("FileName", "")
    threat = data.get("ThreatTypes", "")
    summary = f"Email attachment: {filename}"
    if threat:
        summary += f" [Threat: {threat}]"

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated", data.get("Timestamp"))),
        "source_system": data.get("SourceSystem", "Microsoft Defender for Office 365"),
        "log_type": "EmailAttachmentInfo",
        "schema_id": "emailattachmentinfo",
        "correlation_id": data.get("CorrelationId"),
        "severity": "high" if threat else "info",
        "summary": summary,
        "source_ip": None,
        "destination_ip": None,
        "user_identity": data.get("RecipientEmailAddress"),
        "host": None,
        "raw_data": data,
    }


def normalize_email_url_info(data: dict) -> dict:
    url = data.get("Url", "")
    domain = data.get("UrlDomain", "")
    threat = data.get("ThreatTypes", "")
    summary = f"Email URL: {domain or url}"
    if threat:
        summary += f" [Threat: {threat}]"

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated", data.get("Timestamp"))),
        "source_system": data.get("SourceSystem", "Microsoft Defender for Office 365"),
        "log_type": "EmailUrlInfo",
        "schema_id": "emailurlinfo",
        "correlation_id": data.get("CorrelationId"),
        "severity": "high" if threat else "info",
        "summary": summary,
        "source_ip": None,
        "destination_ip": None,
        "user_identity": None,
        "host": None,
        "raw_data": data,
    }


def normalize_dns_events(data: dict) -> dict:
    query_name = data.get("Name", "")
    query_type = data.get("QueryType", "")
    threat = data.get("IndicatorThreatType", "")
    summary = f"DNS query: {query_name} ({query_type})"
    if threat:
        summary += f" [Threat: {threat}]"

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", "unknown"),
        "log_type": "DNSEvents",
        "schema_id": "dnsevents",
        "correlation_id": data.get("CorrelationId"),
        "severity": "high" if threat else "info",
        "summary": summary,
        "source_ip": _safe_ip(data.get("ClientIP")),
        "destination_ip": _safe_ip(data.get("IPAddresses")),
        "user_identity": None,
        "host": data.get("Computer"),
        "raw_data": data,
    }


def normalize_app_service_http_logs(data: dict) -> dict:
    method = data.get("CsMethod", "")
    uri = data.get("CsUriStem", "")
    status = data.get("ScStatus", "")
    summary = f"HTTP {method} {uri} → {status}"

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", "Azure App Service"),
        "log_type": "AppServiceHTTPLogs",
        "schema_id": "appservicehttplogs",
        "correlation_id": data.get("CorrelationId"),
        "severity": _extract_severity(data, "info"),
        "summary": summary,
        "source_ip": _safe_ip(data.get("CIp")),
        "destination_ip": None,
        "user_identity": data.get("CsUsername"),
        "host": data.get("CsHost"),
        "raw_data": data,
    }


def normalize_audit_logs(data: dict) -> dict:
    operation = data.get("OperationName") or data.get("ActivityDisplayName", "")
    initiated_by = data.get("InitiatedBy", {})
    actor = ""
    if isinstance(initiated_by, dict):
        user_info = initiated_by.get("user", {})
        if isinstance(user_info, dict):
            actor = user_info.get("userPrincipalName", "")
    summary = f"Audit: {operation}"
    if actor:
        summary += f" by {actor}"

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", "Azure AD"),
        "log_type": "AuditLogs",
        "schema_id": "auditlogs",
        "correlation_id": data.get("CorrelationId"),
        "severity": _extract_severity(data, "info"),
        "summary": summary,
        "source_ip": None,
        "destination_ip": None,
        "user_identity": actor or data.get("Identity"),
        "host": None,
        "raw_data": data,
    }


def normalize_office_activity(data: dict) -> dict:
    operation = data.get("Operation", "")
    workload = data.get("OfficeWorkload", "")
    user = data.get("UserId", "")
    summary = f"Office {workload}: {operation} by {user}"

    return {
        "tenant_id": data.get("TenantId", data.get("OrganizationId", "unknown")),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", "Microsoft 365"),
        "log_type": "OfficeActivity",
        "schema_id": "officeactivity",
        "correlation_id": data.get("CorrelationId"),
        "severity": _extract_severity(data, "info"),
        "summary": summary,
        "source_ip": _safe_ip(data.get("ClientIP")),
        "destination_ip": None,
        "user_identity": user,
        "host": None,
        "raw_data": data,
    }


def normalize_aws_cloudtrail(data: dict) -> dict:
    event_name = data.get("EventName", "")
    event_source = data.get("EventSource", "")
    user_name = data.get("UserIdentityUserName") or data.get("UserIdentityArn", "")
    summary = f"AWS {event_source}: {event_name}"
    if user_name:
        summary += f" by {user_name}"

    return {
        "tenant_id": data.get("TenantId", data.get("RecipientAccountId", "unknown")),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", "AWS CloudTrail"),
        "log_type": "AWSCloudTrail",
        "schema_id": "awscloudtrail",
        "correlation_id": data.get("CorrelationId"),
        "severity": _extract_severity(data, "info"),
        "summary": summary,
        "source_ip": _safe_ip(data.get("SourceIpAddress")),
        "destination_ip": None,
        "user_identity": user_name,
        "host": None,
        "raw_data": data,
    }


def normalize_event(data: dict) -> dict:
    event_id = data.get("EventID", "")
    source = data.get("Source", "")
    message = data.get("Message", data.get("RenderedDescription", ""))
    summary = f"Event {event_id} ({source}): {str(message)[:200]}"

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", "unknown"),
        "log_type": "Event",
        "schema_id": "event",
        "correlation_id": data.get("CorrelationId"),
        "severity": _extract_severity(data, "info"),
        "summary": summary,
        "source_ip": None,
        "destination_ip": None,
        "user_identity": data.get("UserName"),
        "host": data.get("Computer"),
        "raw_data": data,
    }


def normalize_heartbeat(data: dict) -> dict:
    computer = data.get("Computer", "")
    os_type = data.get("OSType", "")
    summary = f"Heartbeat: {computer} ({os_type})"

    return {
        "tenant_id": data.get("TenantId", "unknown"),
        "time_generated": _parse_timestamp(data.get("TimeGenerated")),
        "source_system": data.get("SourceSystem", "unknown"),
        "log_type": "Heartbeat",
        "schema_id": "heartbeat",
        "correlation_id": None,
        "severity": "info",
        "summary": summary,
        "source_ip": _safe_ip(data.get("ComputerIP")),
        "destination_ip": None,
        "user_identity": None,
        "host": computer,
        "raw_data": data,
    }


# Registry of normalizer functions keyed by schemaId
NORMALIZERS: dict[str, callable] = {
    "securityalert": normalize_security_alert,
    "securityevent": normalize_security_event,
    "signinlogs": normalize_signin_logs,
    "commonsecuritylog": normalize_common_security_log,
    "emailevents": normalize_email_events,
    "emailattachmentinfo": normalize_email_attachment_info,
    "emailurlinfo": normalize_email_url_info,
    "dnsevents": normalize_dns_events,
    "appservicehttplogs": normalize_app_service_http_logs,
    "auditlogs": normalize_audit_logs,
    "officeactivity": normalize_office_activity,
    "awscloudtrail": normalize_aws_cloudtrail,
    "event": normalize_event,
    "heartbeat": normalize_heartbeat,
}

# Also map by Type field values (some logs use these)
TYPE_TO_SCHEMA: dict[str, str] = {
    "SecurityAlert": "securityalert",
    "SecurityEvent": "securityevent",
    "SigninLogs": "signinlogs",
    "CommonSecurityLog": "commonsecuritylog",
    "EmailEvents": "emailevents",
    "EmailAttachmentInfo": "emailattachmentinfo",
    "EmailUrlInfo": "emailurlinfo",
    "DnsEvents": "dnsevents",
    "DNSEvents": "dnsevents",
    "AppServiceHTTPLogs": "appservicehttplogs",
    "AuditLogs": "auditlogs",
    "OfficeActivity": "officeactivity",
    "AWSCloudTrail": "awscloudtrail",
    "Event": "event",
    "Heartbeat": "heartbeat",
}


def normalize_log_event(schema_id: str, data: dict) -> dict:
    """Normalize a log event using the appropriate normalizer."""
    key = schema_id.lower().strip()
    if key not in NORMALIZERS:
        # Try the Type field in data
        type_field = data.get("Type", "")
        mapped = TYPE_TO_SCHEMA.get(type_field, "")
        if mapped in NORMALIZERS:
            key = mapped
        else:
            # Fallback: return a generic normalized event
            return {
                "tenant_id": data.get("TenantId", "unknown"),
                "time_generated": _parse_timestamp(data.get("TimeGenerated")),
                "source_system": data.get("SourceSystem", "unknown"),
                "log_type": schema_id,
                "schema_id": schema_id,
                "correlation_id": data.get("CorrelationId"),
                "severity": _extract_severity(data, "info"),
                "summary": f"Unknown log type: {schema_id}",
                "source_ip": None,
                "destination_ip": None,
                "user_identity": None,
                "host": data.get("Computer"),
                "raw_data": data,
            }

    return NORMALIZERS[key](data)


def get_supported_schemas() -> list[str]:
    """Return list of supported schema types."""
    return sorted(NORMALIZERS.keys())
