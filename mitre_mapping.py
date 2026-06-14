"""
mitre_mapping.py
================
Local MITRE ATT&CK® mapping table for common Windows Security Event IDs.

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics
and techniques based on real-world observations.

This module maps Windows Event IDs to ATT&CK techniques so that analysts
can quickly understand the adversary behavior associated with each log event.

Reference: https://attack.mitre.org/
"""

# ── MITRE Mapping Table ───────────────────────────────────────────────────────
# Format: EventID (string) → dict with technique details
MITRE_MAPPINGS = {
    "4624": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining "
            "Initial Access, Persistence, Privilege Escalation, or Defense Evasion. A successful "
            "login (4624) alone is not malicious, but in context with other events it may indicate "
            "credential reuse, lateral movement, or unauthorized access."
        ),
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "4625": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts when passwords "
            "are unknown or when password hashes are obtained. Multiple failed logon events (4625) "
            "from the same source are a strong indicator of a brute force or password spray attack."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "4688": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute commands, scripts, "
            "or binaries. Process creation events (4688) that show unusual executables such as "
            "cmd.exe, PowerShell, or scripting engines may indicate malicious code execution."
        ),
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "4720": {
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create an account to maintain access to victim systems. New account "
            "creation events (4720) that are unauthorized can indicate an attacker establishing "
            "persistence or creating a backdoor account for future access."
        ),
        "url": "https://attack.mitre.org/techniques/T1136/"
    },
    "4728": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "description": (
            "Adversaries may manipulate accounts to maintain access to victim systems. Adding a user "
            "to a privileged group (4728) such as 'Administrators' or 'Domain Admins' is a common "
            "technique for privilege escalation and establishing persistence."
        ),
        "url": "https://attack.mitre.org/techniques/T1098/"
    },
    "4732": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "description": (
            "A member was added to a security-enabled local group (4732). This may indicate "
            "privilege escalation or account manipulation by an adversary trying to gain "
            "elevated access to local resources."
        ),
        "url": "https://attack.mitre.org/techniques/T1098/"
    },
    "4648": {
        "technique_id": "T1550",
        "technique_name": "Use Alternate Authentication Material",
        "tactic": "Defense Evasion / Lateral Movement",
        "description": (
            "A logon was attempted using explicit credentials (4648). This can indicate pass-the-hash, "
            "pass-the-ticket, or credential forwarding attacks where an adversary uses captured "
            "credentials to authenticate to other systems."
        ),
        "url": "https://attack.mitre.org/techniques/T1550/"
    },
    "default": {
        "technique_id": "N/A",
        "technique_name": "No Direct Mapping",
        "tactic": "Unknown",
        "description": (
            "This event does not have a direct MITRE ATT&CK mapping in the current database. "
            "Manual analysis is recommended to determine if this event has security relevance."
        ),
        "url": "https://attack.mitre.org/"
    }
}


def get_mitre_info(event_id: str) -> dict:
    """
    Look up the MITRE ATT&CK technique for a given Windows Event ID.

    Args:
        event_id: The Windows Security Event ID as a string (e.g., "4625")

    Returns:
        A dict with technique_id, technique_name, tactic, description, and url.
    """
    event_id = str(event_id).strip()
    return MITRE_MAPPINGS.get(event_id, MITRE_MAPPINGS["default"])
