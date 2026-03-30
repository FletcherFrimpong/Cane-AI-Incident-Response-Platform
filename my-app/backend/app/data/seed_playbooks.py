"""
Seed data: 7 pre-built incident response playbooks based on NIST 800-61.
Each playbook follows the NIST phases:
  1. Detection & Analysis
  2. Containment
  3. Eradication
  4. Recovery
  5. Post-Incident Activity
"""


def get_seed_playbooks() -> list[dict]:
    """Return the 7 pre-built playbooks with their steps."""
    return [
        {
            "name": "Ransomware Response Playbook",
            "description": "NIST 800-61 based playbook for ransomware incidents. Covers detection, containment via network isolation, eradication of malware, recovery from backups, and post-incident hardening.",
            "framework": "nist_800_61",
            "attack_types": ["ransomware"],
            "steps": [
                {
                    "step_order": 1, "phase": "detection_analysis", "step_type": "info",
                    "title": "Initial Assessment",
                    "description": "Review the security alerts and log events to confirm ransomware activity. Look for:\n- File encryption patterns (.encrypted, .wcry, .locked extensions)\n- Ransom notes (README.txt, DECRYPT_INSTRUCTIONS)\n- Unusual process execution (PowerShell with bypass flags)\n- SMB exploitation attempts on port 445\n- C2 domain queries in DNS logs\n\nRef: NIST SP 800-61 Section 3.2 - Signs of an Incident",
                },
                {
                    "step_order": 2, "phase": "detection_analysis", "step_type": "human_decision",
                    "title": "Confirm Ransomware Variant",
                    "description": "Based on the indicators, identify the ransomware variant:\n1. Check file extensions against known ransomware families\n2. Search hash values on VirusTotal\n3. Review ransom note content for variant identification\n4. Check MITRE ATT&CK T1486 (Data Encrypted for Impact)\n\nIs this confirmed ransomware? Select: CONFIRMED / FALSE_POSITIVE / NEEDS_ESCALATION",
                },
                {
                    "step_order": 3, "phase": "containment", "step_type": "automated",
                    "title": "Isolate Affected Hosts",
                    "description": "Immediately isolate all affected machines from the network to prevent lateral spread. This uses Microsoft Defender for Endpoint to network-isolate the compromised hosts.",
                    "auto_action_type": "isolate_host",
                    "auto_action_params": {},
                    "requires_approval": True,
                    "timeout_minutes": 15,
                },
                {
                    "step_order": 4, "phase": "containment", "step_type": "automated",
                    "title": "Block C2 Domains and IPs",
                    "description": "Block all identified command-and-control (C2) IP addresses and domains at the firewall level using Microsoft Defender indicators.",
                    "auto_action_type": "block_ip",
                    "auto_action_params": {},
                    "requires_approval": True,
                },
                {
                    "step_order": 5, "phase": "containment", "step_type": "human_action",
                    "title": "Disable Compromised Accounts",
                    "description": "Disable all user accounts that show signs of compromise:\n1. Review sign-in logs for affected users\n2. Disable accounts via Azure AD\n3. Revoke all active sessions\n4. Force password reset for affected accounts\n5. Review and revoke any elevated privileges granted during the attack",
                },
                {
                    "step_order": 6, "phase": "containment", "step_type": "human_action",
                    "title": "Preserve Evidence",
                    "description": "Before eradication, preserve forensic evidence:\n1. Collect investigation packages from affected endpoints\n2. Export relevant log data from Sentinel\n3. Take memory dumps if possible\n4. Document the timeline of events\n5. Preserve ransom notes and encrypted file samples\n\nRef: NIST SP 800-61 Section 3.3.2 - Evidence Gathering",
                },
                {
                    "step_order": 7, "phase": "eradication", "step_type": "automated",
                    "title": "Run Full AV Scan",
                    "description": "Initiate a full antivirus scan on all affected and potentially affected machines to identify and remove ransomware components.",
                    "auto_action_type": "run_av_scan",
                    "auto_action_params": {"scan_type": "Full"},
                    "requires_approval": False,
                },
                {
                    "step_order": 8, "phase": "eradication", "step_type": "human_action",
                    "title": "Remove Ransomware Artifacts",
                    "description": "Manually verify and remove any remaining ransomware artifacts:\n1. Check for persistence mechanisms (scheduled tasks, registry keys, services)\n2. Remove dropped files and scripts\n3. Clean temporary directories\n4. Verify no backdoors were installed\n5. Check for lateral movement artifacts on adjacent systems",
                },
                {
                    "step_order": 9, "phase": "recovery", "step_type": "human_action",
                    "title": "Restore from Backups",
                    "description": "Restore affected systems and data from known-good backups:\n1. Verify backup integrity before restoration\n2. Ensure backups pre-date the initial compromise\n3. Restore systems in a staged manner\n4. Verify restored data is not encrypted/corrupted\n5. Test system functionality after restoration\n\nRef: NIST SP 800-61 Section 3.4 - Recovery",
                },
                {
                    "step_order": 10, "phase": "recovery", "step_type": "human_action",
                    "title": "Restore Network Access",
                    "description": "Gradually restore network access for cleaned systems:\n1. Remove network isolation for verified clean machines\n2. Re-enable user accounts with new passwords\n3. Monitor for any signs of re-infection\n4. Validate all security controls are functioning",
                },
                {
                    "step_order": 11, "phase": "post_incident", "step_type": "info",
                    "title": "Post-Incident Review",
                    "description": "Conduct a post-incident review within 72 hours:\n1. Document the complete incident timeline\n2. Identify root cause and initial access vector\n3. Assess the effectiveness of the response\n4. Update detection rules to catch similar attacks\n5. Review and update backup procedures\n6. Conduct lessons-learned session with the team\n\nRef: NIST SP 800-61 Section 3.5 - Post-Incident Activity",
                },
            ],
        },
        {
            "name": "Phishing Response Playbook",
            "description": "NIST 800-61 based playbook for phishing campaigns. Covers email analysis, credential compromise assessment, malware delivery chain analysis, and user notification.",
            "framework": "nist_800_61",
            "attack_types": ["phishing"],
            "steps": [
                {
                    "step_order": 1, "phase": "detection_analysis", "step_type": "info",
                    "title": "Analyze Phishing Email",
                    "description": "Examine the reported/detected phishing email:\n1. Review sender address and domain (check for spoofing)\n2. Analyze email headers for origin IP\n3. Check URLs against threat intelligence\n4. Analyze attachments in sandbox environment\n5. Identify all recipients who received the email\n6. Check detection method confidence\n\nRef: MITRE ATT&CK T1566 - Phishing",
                },
                {
                    "step_order": 2, "phase": "detection_analysis", "step_type": "human_decision",
                    "title": "Assess Impact Scope",
                    "description": "Determine the scope of the phishing campaign:\n- How many users received the email?\n- How many clicked the link or opened the attachment?\n- Were any credentials entered on the phishing page?\n- Was malware downloaded/executed?\n\nSelect impact level: CREDENTIALS_COMPROMISED / MALWARE_DELIVERED / EMAIL_ONLY / FALSE_POSITIVE",
                },
                {
                    "step_order": 3, "phase": "containment", "step_type": "automated",
                    "title": "Block Phishing URLs and Sender",
                    "description": "Block the malicious URLs and sender domains across the organization.",
                    "auto_action_type": "block_url",
                    "auto_action_params": {},
                    "requires_approval": True,
                },
                {
                    "step_order": 4, "phase": "containment", "step_type": "automated",
                    "title": "Reset Compromised Credentials",
                    "description": "Force password reset for all users who may have entered credentials on the phishing page.",
                    "auto_action_type": "force_password_reset",
                    "auto_action_params": {},
                    "requires_approval": True,
                },
                {
                    "step_order": 5, "phase": "containment", "step_type": "automated",
                    "title": "Revoke Active Sessions",
                    "description": "Revoke all active sessions for compromised accounts to prevent unauthorized access.",
                    "auto_action_type": "revoke_sessions",
                    "auto_action_params": {},
                    "requires_approval": False,
                },
                {
                    "step_order": 6, "phase": "eradication", "step_type": "human_action",
                    "title": "Remove Phishing Emails",
                    "description": "Purge the phishing email from all user mailboxes:\n1. Use Exchange/O365 Content Search to find all instances\n2. Delete the email from all mailboxes\n3. Block the sender domain in Exchange transport rules\n4. Add phishing indicators to threat intelligence\n5. Update email filtering rules",
                },
                {
                    "step_order": 7, "phase": "eradication", "step_type": "automated",
                    "title": "Scan for Delivered Malware",
                    "description": "Run AV scans on machines where attachments may have been opened.",
                    "auto_action_type": "run_av_scan",
                    "auto_action_params": {"scan_type": "Quick"},
                    "requires_approval": False,
                },
                {
                    "step_order": 8, "phase": "recovery", "step_type": "human_action",
                    "title": "Notify Affected Users",
                    "description": "Notify all affected users:\n1. Inform users who received the phishing email\n2. Instruct users who clicked to change passwords on all accounts\n3. Provide guidance on identifying phishing attempts\n4. Share the specific indicators of this campaign\n5. Offer additional security training",
                },
                {
                    "step_order": 9, "phase": "post_incident", "step_type": "info",
                    "title": "Post-Incident Review",
                    "description": "Review and improve defenses:\n1. Analyze why the email bypassed filters\n2. Update detection rules and email policies\n3. Consider additional security awareness training\n4. Review MFA enforcement for all accounts\n5. Document lessons learned\n\nRef: NIST SP 800-61 Section 3.5",
                },
            ],
        },
        {
            "name": "Data Exfiltration Response Playbook",
            "description": "NIST 800-61 based playbook for data exfiltration incidents. Covers data flow analysis, account containment, DLP review, and regulatory notification.",
            "framework": "nist_800_61",
            "attack_types": ["data_exfiltration"],
            "steps": [
                {
                    "step_order": 1, "phase": "detection_analysis", "step_type": "info",
                    "title": "Analyze Data Flow",
                    "description": "Investigate the suspected data exfiltration:\n1. Review network logs for large outbound data transfers\n2. Identify source and destination IPs\n3. Determine what data was accessed (database queries, file access)\n4. Review user activity and authentication logs\n5. Check for use of exfiltration tools (sqlcmd, curl, wget, cloud sync)\n6. Assess data classification of potentially exposed data\n\nRef: MITRE ATT&CK TA0010 - Exfiltration",
                },
                {
                    "step_order": 2, "phase": "detection_analysis", "step_type": "human_decision",
                    "title": "Confirm Data Exfiltration",
                    "description": "Based on the analysis, confirm the exfiltration:\n- What volume of data was transferred?\n- What type of data (PII, financial, intellectual property)?\n- Was this authorized activity or malicious?\n- Is the actor internal or external?\n\nSelect: CONFIRMED_EXTERNAL / CONFIRMED_INSIDER / SUSPICIOUS_NEEDS_INVESTIGATION / FALSE_POSITIVE",
                },
                {
                    "step_order": 3, "phase": "containment", "step_type": "automated",
                    "title": "Disable Compromised Account",
                    "description": "Immediately disable the account used for data exfiltration.",
                    "auto_action_type": "disable_account",
                    "auto_action_params": {},
                    "requires_approval": True,
                },
                {
                    "step_order": 4, "phase": "containment", "step_type": "automated",
                    "title": "Block Destination IPs",
                    "description": "Block the external IP addresses that received the exfiltrated data.",
                    "auto_action_type": "block_ip",
                    "auto_action_params": {},
                    "requires_approval": True,
                },
                {
                    "step_order": 5, "phase": "containment", "step_type": "human_action",
                    "title": "Revoke Database Access",
                    "description": "Review and revoke database access:\n1. Revoke all database credentials for the compromised account\n2. Rotate database passwords\n3. Review database audit logs\n4. Apply additional access restrictions\n5. Enable enhanced database monitoring",
                },
                {
                    "step_order": 6, "phase": "eradication", "step_type": "human_action",
                    "title": "Remove Persistence Mechanisms",
                    "description": "Check for and remove any persistence mechanisms:\n1. Review scheduled tasks and cron jobs\n2. Check for unauthorized SSH keys or API tokens\n3. Review service accounts and their permissions\n4. Audit recently created accounts or role assignments\n5. Check for data staging locations",
                },
                {
                    "step_order": 7, "phase": "recovery", "step_type": "human_action",
                    "title": "Assess Regulatory Impact",
                    "description": "Determine regulatory notification requirements:\n1. Identify what data was exposed (PII, PHI, PCI, etc.)\n2. Determine applicable regulations (GDPR, HIPAA, etc.)\n3. Calculate the number of affected individuals\n4. Consult with legal and compliance teams\n5. Prepare breach notification if required\n6. Document evidence for regulatory reporting",
                },
                {
                    "step_order": 8, "phase": "recovery", "step_type": "human_action",
                    "title": "Implement Enhanced Monitoring",
                    "description": "Set up enhanced monitoring:\n1. Create Sentinel analytics rules for similar patterns\n2. Enable DLP policies for sensitive data\n3. Implement network segmentation for sensitive databases\n4. Set up alerts for large data transfers\n5. Review and tighten least-privilege access controls",
                },
                {
                    "step_order": 9, "phase": "post_incident", "step_type": "info",
                    "title": "Post-Incident Review",
                    "description": "Conduct comprehensive review:\n1. Complete incident timeline documentation\n2. Root cause analysis\n3. Review DLP and access control effectiveness\n4. Update data classification policies\n5. Implement additional safeguards\n6. Lessons learned session",
                },
            ],
        },
        {
            "name": "DDoS Response Playbook",
            "description": "NIST 800-61 based playbook for Distributed Denial of Service attacks. Covers traffic analysis, mitigation activation, and service restoration.",
            "framework": "nist_800_61",
            "attack_types": ["ddos"],
            "steps": [
                {
                    "step_order": 1, "phase": "detection_analysis", "step_type": "info",
                    "title": "Confirm DDoS Attack",
                    "description": "Verify the DDoS attack:\n1. Review traffic patterns and volume anomalies\n2. Identify attack type (volumetric, protocol, application layer)\n3. Identify source IPs and geographic distribution\n4. Assess impact on service availability\n5. Check if this is a diversion for another attack\n\nRef: MITRE ATT&CK T1498 - Network Denial of Service",
                },
                {
                    "step_order": 2, "phase": "containment", "step_type": "automated",
                    "title": "Block Attack Source IPs",
                    "description": "Block the most aggressive source IPs identified in the attack.",
                    "auto_action_type": "block_ip",
                    "auto_action_params": {},
                    "requires_approval": True,
                },
                {
                    "step_order": 3, "phase": "containment", "step_type": "human_action",
                    "title": "Activate DDoS Mitigation",
                    "description": "Activate DDoS mitigation services:\n1. Enable Azure DDoS Protection advanced features\n2. Activate CDN-level protections\n3. Implement rate limiting on affected endpoints\n4. Enable geo-blocking for attack source regions if appropriate\n5. Contact ISP for upstream filtering if needed",
                },
                {
                    "step_order": 4, "phase": "containment", "step_type": "human_action",
                    "title": "Scale Infrastructure",
                    "description": "Scale infrastructure to absorb remaining traffic:\n1. Scale up application instances\n2. Enable auto-scaling policies\n3. Activate standby infrastructure\n4. Redirect traffic through CDN/WAF\n5. Communicate with stakeholders about service impact",
                },
                {
                    "step_order": 5, "phase": "recovery", "step_type": "human_action",
                    "title": "Restore Normal Operations",
                    "description": "Once attack subsides:\n1. Gradually remove temporary blocks\n2. Scale infrastructure back to normal\n3. Verify all services are functioning\n4. Check for any collateral damage\n5. Monitor for attack resumption",
                },
                {
                    "step_order": 6, "phase": "post_incident", "step_type": "info",
                    "title": "Post-Incident Review",
                    "description": "Review and harden:\n1. Analyze attack patterns and vectors\n2. Report source IPs to AbuseIPDB\n3. Review DDoS protection adequacy\n4. Update rate limiting and WAF rules\n5. Document lessons learned\n6. Consider DDoS protection service upgrade",
                },
            ],
        },
        {
            "name": "Unauthorized Access Response Playbook",
            "description": "NIST 800-61 based playbook for unauthorized access and privilege escalation incidents.",
            "framework": "nist_800_61",
            "attack_types": ["unauthorized_access", "brute_force", "lateral_movement"],
            "steps": [
                {
                    "step_order": 1, "phase": "detection_analysis", "step_type": "info",
                    "title": "Analyze Access Patterns",
                    "description": "Review unauthorized access indicators:\n1. Check for multiple failed login attempts\n2. Review successful logins from unusual locations\n3. Check for privilege escalation events (EventID 4672, 4728)\n4. Review conditional access policy violations\n5. Check for impossible travel scenarios\n6. Review MFA bypass attempts\n\nRef: MITRE ATT&CK TA0001 - Initial Access, TA0004 - Privilege Escalation",
                },
                {
                    "step_order": 2, "phase": "detection_analysis", "step_type": "human_decision",
                    "title": "Determine Scope of Compromise",
                    "description": "Assess the extent of unauthorized access:\n- Which accounts are compromised?\n- What systems were accessed?\n- Was privilege escalation successful?\n- Is there evidence of lateral movement?\n\nSelect: SINGLE_ACCOUNT / MULTIPLE_ACCOUNTS / ADMIN_COMPROMISE / FALSE_POSITIVE",
                },
                {
                    "step_order": 3, "phase": "containment", "step_type": "automated",
                    "title": "Disable Compromised Accounts",
                    "description": "Immediately disable all compromised user accounts.",
                    "auto_action_type": "disable_account",
                    "auto_action_params": {},
                    "requires_approval": True,
                },
                {
                    "step_order": 4, "phase": "containment", "step_type": "automated",
                    "title": "Revoke All Sessions",
                    "description": "Revoke all active sessions for compromised accounts.",
                    "auto_action_type": "revoke_sessions",
                    "auto_action_params": {},
                    "requires_approval": False,
                },
                {
                    "step_order": 5, "phase": "containment", "step_type": "automated",
                    "title": "Block Source IPs",
                    "description": "Block the IP addresses used for unauthorized access.",
                    "auto_action_type": "block_ip",
                    "auto_action_params": {},
                    "requires_approval": True,
                },
                {
                    "step_order": 6, "phase": "eradication", "step_type": "human_action",
                    "title": "Review and Revoke Permissions",
                    "description": "Audit and fix permissions:\n1. Review all role assignments made during the compromise period\n2. Revoke any unauthorized privilege escalations\n3. Audit OAuth app consents\n4. Review conditional access policies\n5. Check for newly created accounts\n6. Rotate service account credentials",
                },
                {
                    "step_order": 7, "phase": "recovery", "step_type": "human_action",
                    "title": "Restore Secure Access",
                    "description": "Re-enable accounts with enhanced security:\n1. Reset passwords for all compromised accounts\n2. Enforce MFA enrollment\n3. Review and enable conditional access policies\n4. Re-enable accounts one at a time with monitoring\n5. Notify users and provide security guidance",
                },
                {
                    "step_order": 8, "phase": "post_incident", "step_type": "info",
                    "title": "Post-Incident Review",
                    "description": "Strengthen access controls:\n1. Review password policies\n2. Enforce MFA for all accounts\n3. Implement conditional access based on risk\n4. Enable Identity Protection in Azure AD\n5. Set up alerts for suspicious sign-ins\n6. Document and share lessons learned",
                },
            ],
        },
        {
            "name": "Malware Infection Response Playbook",
            "description": "NIST 800-61 based playbook for malware infections including trojans, backdoors, and C2 communications.",
            "framework": "nist_800_61",
            "attack_types": ["malware"],
            "steps": [
                {
                    "step_order": 1, "phase": "detection_analysis", "step_type": "info",
                    "title": "Identify Malware",
                    "description": "Analyze the detected malware:\n1. Review alert details and detection method\n2. Identify file hash and check against VirusTotal\n3. Determine malware family and capabilities\n4. Check for C2 communication in DNS and network logs\n5. Identify infection vector (email, web, USB, etc.)\n6. Assess persistence mechanisms\n\nRef: MITRE ATT&CK TA0002 - Execution, TA0003 - Persistence",
                },
                {
                    "step_order": 2, "phase": "containment", "step_type": "automated",
                    "title": "Isolate Infected Machine",
                    "description": "Network-isolate the infected endpoint to prevent C2 communication and lateral movement.",
                    "auto_action_type": "isolate_host",
                    "auto_action_params": {},
                    "requires_approval": True,
                    "timeout_minutes": 10,
                },
                {
                    "step_order": 3, "phase": "containment", "step_type": "automated",
                    "title": "Block Malware Hash",
                    "description": "Add the malware file hash to the block list across the organization.",
                    "auto_action_type": "block_file_hash",
                    "auto_action_params": {},
                    "requires_approval": False,
                },
                {
                    "step_order": 4, "phase": "containment", "step_type": "automated",
                    "title": "Block C2 Infrastructure",
                    "description": "Block C2 domains and IPs at the network perimeter.",
                    "auto_action_type": "block_ip",
                    "auto_action_params": {},
                    "requires_approval": True,
                },
                {
                    "step_order": 5, "phase": "eradication", "step_type": "automated",
                    "title": "Full Antivirus Scan",
                    "description": "Run a full antivirus scan on the infected machine and potentially affected neighbors.",
                    "auto_action_type": "run_av_scan",
                    "auto_action_params": {"scan_type": "Full"},
                    "requires_approval": False,
                },
                {
                    "step_order": 6, "phase": "eradication", "step_type": "human_action",
                    "title": "Manual Malware Removal",
                    "description": "Perform manual cleanup:\n1. Remove persistence mechanisms\n2. Delete malware files and artifacts\n3. Clean registry entries\n4. Review and clean scheduled tasks\n5. Check for rootkit presence\n6. Verify no additional payloads were dropped",
                },
                {
                    "step_order": 7, "phase": "recovery", "step_type": "human_action",
                    "title": "Restore and Verify",
                    "description": "Restore the system:\n1. If clean, release from isolation\n2. If severely compromised, reimage from gold image\n3. Restore user data from backup\n4. Verify system integrity\n5. Monitor for re-infection\n6. Update endpoint protection signatures",
                },
                {
                    "step_order": 8, "phase": "post_incident", "step_type": "info",
                    "title": "Post-Incident Review",
                    "description": "Improve defenses:\n1. Analyze infection vector and close the gap\n2. Share IOCs with threat intelligence feeds\n3. Update detection rules\n4. Review endpoint protection configuration\n5. Assess need for additional security controls\n6. Document and share lessons learned",
                },
            ],
        },
        {
            "name": "Insider Threat Response Playbook",
            "description": "NIST 800-61 based playbook for insider threat incidents. Covers behavioral analysis, access review, HR coordination, and evidence preservation.",
            "framework": "nist_800_61",
            "attack_types": ["insider_threat"],
            "steps": [
                {
                    "step_order": 1, "phase": "detection_analysis", "step_type": "info",
                    "title": "Review Behavioral Indicators",
                    "description": "Analyze potential insider threat indicators:\n1. Unusual data access patterns (volume, time, sensitivity)\n2. Access to systems outside normal job function\n3. Use of personal email or cloud storage for company data\n4. After-hours access anomalies\n5. Large file downloads or prints\n6. Resignation or termination notices on file\n\nIMPORTANT: Coordinate with HR and Legal before taking action.",
                },
                {
                    "step_order": 2, "phase": "detection_analysis", "step_type": "human_decision",
                    "title": "Classify Insider Threat Type",
                    "description": "Determine the nature of the insider threat:\n- Malicious (intentional data theft or sabotage)\n- Negligent (accidental policy violation)\n- Compromised (external actor using insider credentials)\n\nSelect: MALICIOUS_INSIDER / NEGLIGENT / COMPROMISED_ACCOUNT / INSUFFICIENT_EVIDENCE",
                },
                {
                    "step_order": 3, "phase": "containment", "step_type": "human_action",
                    "title": "Coordinate with HR and Legal",
                    "description": "CRITICAL: Before technical containment, coordinate with:\n1. HR department - employment status, history, policies\n2. Legal counsel - evidence preservation requirements, privacy laws\n3. Management - approval for containment actions\n4. Ensure all actions comply with employee privacy regulations\n5. Document all decisions and approvals",
                },
                {
                    "step_order": 4, "phase": "containment", "step_type": "human_action",
                    "title": "Enhanced Monitoring",
                    "description": "With HR/Legal approval, implement enhanced monitoring:\n1. Enable detailed audit logging for the user\n2. Set up DLP alerts for the user's activity\n3. Monitor email and file sharing activity\n4. Track physical access logs\n5. Do NOT alert the subject of the investigation",
                },
                {
                    "step_order": 5, "phase": "containment", "step_type": "automated",
                    "title": "Restrict Access (if approved)",
                    "description": "With management and legal approval, restrict the insider's access to sensitive systems.",
                    "auto_action_type": "disable_account",
                    "auto_action_params": {},
                    "requires_approval": True,
                    "conditions": {"if_decision": "MALICIOUS_INSIDER"},
                },
                {
                    "step_order": 6, "phase": "eradication", "step_type": "human_action",
                    "title": "Preserve Digital Evidence",
                    "description": "Forensically preserve evidence:\n1. Create forensic images of relevant devices\n2. Export all user activity logs\n3. Preserve email archives\n4. Document chain of custody\n5. Secure all evidence per legal hold requirements",
                },
                {
                    "step_order": 7, "phase": "recovery", "step_type": "human_action",
                    "title": "Assess and Remediate Data Exposure",
                    "description": "Determine data impact:\n1. Identify all data accessed or exfiltrated\n2. Assess sensitivity and regulatory implications\n3. Determine if external parties received data\n4. Work with Legal on notification requirements\n5. Implement additional access controls",
                },
                {
                    "step_order": 8, "phase": "post_incident", "step_type": "info",
                    "title": "Post-Incident Review",
                    "description": "Strengthen insider threat program:\n1. Review DLP policies and effectiveness\n2. Enhance user behavior analytics\n3. Review access control and least privilege\n4. Update insider threat detection rules\n5. Improve off-boarding processes\n6. Consider security awareness training updates\n7. Document lessons learned (maintain confidentiality)",
                },
            ],
        },
    ]
