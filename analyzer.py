"""
analyzer.py
===========
The core AI reasoning engine for SOC Copilot.

This module sends each security event to the Claude AI API and asks it to:
  1. Summarize what happened
  2. Explain why this event matters from a security perspective
  3. Identify if this could indicate malicious activity
  4. Recommend what an analyst should investigate next
  5. Suggest remediation actions

The goal is to give beginner SOC analysts AI-assisted explanations that
help them understand security events in plain English.
"""

import json
import urllib.request
import urllib.error
from mitre_mapping import get_mitre_info
from severity_engine import calculate_severity

# ── Optional Splunk HEC integration ──────────────────────────────────────────
# Set by app.py at startup when SPLUNK_HEC_TOKEN is configured.
# When None (the default), all Splunk forwarding calls are silently skipped
# and the application behaves exactly as it did before the integration.
splunk_client = None

# ── Event ID Descriptions ─────────────────────────────────────────────────────
EVENT_DESCRIPTIONS = {
    "4624": "Successful Account Logon",
    "4625": "Failed Account Logon",
    "4688": "New Process Created",
    "4720": "New User Account Created",
    "4728": "Member Added to Security-Enabled Global Group",
    "4732": "Member Added to Security-Enabled Local Group",
    "4648": "Logon Attempt Using Explicit Credentials",
}


def build_ai_prompt(event: dict, severity: dict, mitre: dict) -> str:
    """
    Build a detailed prompt for Claude AI to analyze a single security event.

    This prompt instructs Claude to act as a SOC analyst and provide
    a structured, beginner-friendly analysis of the event.
    """
    event_id = str(event.get('EventID', 'Unknown'))
    event_name = EVENT_DESCRIPTIONS.get(event_id, f"Event ID {event_id}")

    # Build a readable summary of the event's key fields
    event_summary_lines = []
    important_fields = [
        'EventID', 'TimeCreated', 'SubjectUserName', 'TargetUserName',
        'LogonType', 'IpAddress', 'WorkstationName', 'NewProcessName',
        'CommandLine', 'GroupName', 'ComputerName'
    ]
    for field in important_fields:
        if event.get(field) and event[field] not in ['', '-', 'N/A', None]:
            event_summary_lines.append(f"  {field}: {event[field]}")

    event_details = "\n".join(event_summary_lines) if event_summary_lines else "  (No additional details available)"

    prompt = f"""You are a senior SOC (Security Operations Center) analyst helping a beginner analyst understand a Windows Security Event.

Here is the event you need to analyze:

EVENT INFORMATION:
  Event ID: {event_id} — {event_name}
  Severity: {severity['level']} (Score: {severity['score']}/100)
  MITRE ATT&CK: {mitre['technique_id']} — {mitre['technique_name']} ({mitre['tactic']})

EVENT DETAILS:
{event_details}

Please provide a structured security analysis in the following JSON format ONLY (no other text):

{{
  "summary": "One sentence explaining what happened in plain English.",
  "security_explanation": "2-3 sentences explaining why this type of event matters from a security perspective. Explain it like you're talking to someone new to cybersecurity.",
  "threat_assessment": "2-3 sentences explaining whether this specific event looks suspicious or benign, and what patterns would make it more or less concerning.",
  "investigation_steps": [
    "Step 1: First thing the analyst should check",
    "Step 2: Second investigation action",
    "Step 3: Third investigation action"
  ],
  "remediation": [
    "Remediation action 1",
    "Remediation action 2"
  ],
  "analyst_tip": "One practical tip or 'watch out for' note that would help a beginner analyst understand this event type better."
}}

Be specific, practical, and educational. Use plain English. Avoid jargon without explanation."""

    return prompt


def call_claude_api(prompt: str) -> dict:
    """
    Call the Anthropic Claude API to analyze a security event.

    Returns a dict with the AI analysis, or a fallback dict if the API call fails.
    """
    api_url = "https://api.anthropic.com/v1/messages"

    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 1000,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    headers = {
        "Content-Type": "application/json"
    }

    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(api_url, data=data, headers=headers, method='POST')

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))

            # Extract the text content from Claude's response
            if result.get('content') and len(result['content']) > 0:
                raw_text = result['content'][0].get('text', '')

                # Parse the JSON response from Claude
                try:
                    analysis = json.loads(raw_text)
                    return analysis
                except json.JSONDecodeError:
                    # If Claude didn't return valid JSON, wrap the text
                    return {
                        "summary": raw_text[:200] if raw_text else "Analysis completed.",
                        "security_explanation": raw_text,
                        "threat_assessment": "See full response above.",
                        "investigation_steps": ["Review the AI response above for guidance."],
                        "remediation": ["Follow standard incident response procedures."],
                        "analyst_tip": "Always correlate events with other log sources."
                    }

    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else str(e)
        raise Exception(f"API HTTP Error {e.code}: {error_body}")
    except urllib.error.URLError as e:
        raise Exception(f"Network error calling API: {str(e)}")
    except Exception as e:
        raise Exception(f"Unexpected error calling API: {str(e)}")


def get_fallback_analysis(event: dict, severity: dict, event_name: str) -> dict:
    """
    Provide a rule-based fallback analysis when the AI API is unavailable.
    This ensures the tool still works without an API key for demos.
    """
    event_id = str(event.get('EventID', 'Unknown'))
    account = event.get('TargetUserName') or event.get('SubjectUserName') or 'Unknown'

    fallbacks = {
        "4624": {
            "summary": f"User '{account}' successfully logged into the system.",
            "security_explanation": (
                "Event 4624 is generated every time a user successfully logs in. "
                "While a single login is usually normal, analysts look for logins at "
                "unusual hours, from unexpected locations, or to sensitive systems."
            ),
            "threat_assessment": (
                f"This specific login by '{account}' appears to be a standard authentication event. "
                "It becomes more suspicious if it occurs after multiple failures (4625 events), "
                "from an unusual IP, or outside normal business hours."
            ),
            "investigation_steps": [
                "Check the logon time — is it within normal working hours?",
                "Verify the source IP/workstation is expected for this user",
                "Look for 4625 events (failed logins) before this successful login"
            ],
            "remediation": [
                "If unauthorized, disable the account immediately",
                "Reset the account password and review recent activity"
            ],
            "analyst_tip": "A single 4624 is usually benign. Always look at the pattern around it — what happened before and after?"
        },
        "4625": {
            "summary": f"Failed login attempt for account '{account}'.",
            "security_explanation": (
                "Event 4625 means someone tried to log in with wrong credentials. "
                "A few failed logins are normal (people forget passwords), but many "
                "failures in a short time suggest a brute force or password spray attack."
            ),
            "threat_assessment": (
                f"The failed login for '{account}' warrants monitoring. "
                "If this is one of several failures, it could indicate credential stuffing or brute force. "
                "Check if the account is a privileged account or service account, which increases risk."
            ),
            "investigation_steps": [
                "Count total failed logins for this account in the last hour",
                "Check if the same IP is failing against multiple accounts (spray attack)",
                f"Verify if account '{account}' is a real user or a service account"
            ],
            "remediation": [
                "If volume is high (5+), consider temporarily locking the account",
                "Block the source IP if it's external and repeated",
                "Enable multi-factor authentication (MFA) for the targeted account"
            ],
            "analyst_tip": "The 'Failure Reason' field in 4625 tells you WHY it failed — wrong password vs. disabled account vs. account doesn't exist."
        },
        "4688": {
            "summary": f"A new process was created on the system.",
            "security_explanation": (
                "Event 4688 is logged whenever a new program or command is executed. "
                "Attackers use processes like PowerShell, cmd.exe, or scripts to run malicious code. "
                "This event helps analysts see exactly what programs ran and who ran them."
            ),
            "threat_assessment": (
                "Process creation events need context. A user opening Chrome is harmless. "
                "An automated system running PowerShell with encoded commands is very suspicious. "
                f"Review the 'NewProcessName' and 'CommandLine' fields carefully."
            ),
            "investigation_steps": [
                "Identify the process name and whether it's expected on this system",
                "Review the full command line arguments for suspicious flags or encoded content",
                "Check the parent process — what launched this process?"
            ],
            "remediation": [
                "If malicious, isolate the endpoint from the network immediately",
                "Kill the suspicious process and run endpoint detection/antivirus scan",
                "Review recently installed software and scheduled tasks"
            ],
            "analyst_tip": "Watch for PowerShell with '-EncodedCommand' or '-enc' flags — these are commonly used to hide malicious commands in Base64 encoding."
        },
        "4720": {
            "summary": f"A new user account '{account}' was created.",
            "security_explanation": (
                "Event 4720 is generated when a new Windows user account is created. "
                "Attackers sometimes create accounts to maintain persistent access to systems "
                "even if their original foothold is discovered and removed."
            ),
            "threat_assessment": (
                f"The creation of account '{account}' should be verified with IT/HR. "
                "Unauthorized account creation is a sign of persistence — an attacker "
                "setting up a backdoor they can use later."
            ),
            "investigation_steps": [
                f"Verify with HR or IT if '{account}' is a legitimate new employee or service account",
                "Check who created the account (SubjectUserName field)",
                "Review if this account was immediately added to any groups (look for 4728 events)"
            ],
            "remediation": [
                "If unauthorized, disable the account immediately and preserve for forensics",
                "Review all actions performed by the account creator",
                "Audit all user accounts created in the past 30 days"
            ],
            "analyst_tip": "Always cross-reference new account creation with your HR/IT ticketing system. Legitimate accounts should have a corresponding ticket."
        },
        "4728": {
            "summary": f"User '{account}' was added to a privileged security group.",
            "security_explanation": (
                "Event 4728 means someone was added to a high-privilege group like 'Domain Admins'. "
                "This gives the added account significant power over the entire network. "
                "Unauthorized privilege escalation is one of the most dangerous attack steps."
            ),
            "threat_assessment": (
                f"Adding '{account}' to a privileged group is a HIGH severity event. "
                "If this was not authorized through a formal change request, it must be "
                "investigated immediately as potential privilege escalation or insider threat."
            ),
            "investigation_steps": [
                "Verify this change was approved via your change management process",
                "Identify WHO made this change (SubjectUserName) and verify their authorization",
                "Review all recent activity by the newly elevated account"
            ],
            "remediation": [
                "If unauthorized, remove the account from the group immediately",
                "Review and audit all actions taken since the account was elevated",
                "Investigate the account that made the change for compromise"
            ],
            "analyst_tip": "Privilege escalation (like this event) is step 4 in most attack chains. If you see this, look backward for the initial access — you may have already been breached."
        }
    }

    return fallbacks.get(event_id, {
        "summary": f"Windows Security Event {event_id} was logged.",
        "security_explanation": "This event was recorded by the Windows Security Audit system. Review the event details for more context.",
        "threat_assessment": f"Severity assessed as {severity['level']}. Manual review recommended.",
        "investigation_steps": [
            "Review the event details and correlate with other events",
            "Check if this event type is expected in your environment",
            "Consult Windows Security Event documentation for Event ID " + event_id
        ],
        "remediation": ["Follow your organization's incident response procedures."],
        "analyst_tip": "Use Microsoft's official Event ID documentation or Sigma rules to understand unusual event IDs."
    })


def analyze_events(raw_events: list) -> list:
    """
    Analyze a list of raw security events using AI and rule-based reasoning.

    For each event:
      1. Calculate severity score
      2. Look up MITRE ATT&CK mapping
      3. Call Claude AI for analysis (with fallback if unavailable)

    Args:
        raw_events: List of event dicts from the parsed log file.

    Returns:
        List of enriched event dicts with analysis added.
    """
    analyzed = []

    for i, event in enumerate(raw_events):
        event_id = str(event.get('EventID', 'Unknown'))
        event_name = EVENT_DESCRIPTIONS.get(event_id, f"Event ID {event_id}")

        # Step 1: Calculate severity
        severity = calculate_severity(event)

        # Step 2: Get MITRE mapping
        mitre = get_mitre_info(event_id)

        # Step 3: Get AI analysis (with fallback)
        try:
            prompt = build_ai_prompt(event, severity, mitre)
            analysis = call_claude_api(prompt)
        except Exception as e:
            # If AI call fails, use the rule-based fallback
            print(f"[analyzer] AI call failed for event {i+1}, using fallback: {e}")
            analysis = get_fallback_analysis(event, severity, event_name)

        # Step 4: Combine everything into an enriched event
        enriched = {
            'index': i + 1,
            'event_id': event_id,
            'event_name': event_name,
            'raw': event,
            'severity': severity,
            'mitre': mitre,
            'analysis': analysis
        }
        analyzed.append(enriched)

        # Step 5: Forward to Splunk HEC if configured (fully optional, non-fatal)
        if splunk_client is not None:
            try:
                splunk_client.send_event(enriched)
            except Exception as exc:
                # Log but never raise — a Splunk outage must not interrupt analysis
                print(f"[analyzer] Splunk send failed for event {i+1} (non-fatal): {exc}")

    return analyzed
