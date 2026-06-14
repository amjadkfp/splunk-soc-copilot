"""
report_generator.py
===================
Generates a professional security investigation report from analyzed events.

The report includes:
  - Executive summary
  - Severity breakdown
  - Top events requiring attention
  - Investigation checklist
  - Remediation recommendations
  - Statistics

This gives analysts a structured output they can use to brief leadership
or document their investigation.
"""

from datetime import datetime


def generate_report(analyzed_events: list) -> dict:
    """
    Generate a structured security report from a list of analyzed events.

    Args:
        analyzed_events: List of enriched event dicts from analyzer.py

    Returns:
        A dict containing the full report data.
    """

    if not analyzed_events:
        return {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': 'No events were provided for analysis.',
            'statistics': {},
            'top_events': [],
            'investigation_checklist': [],
            'remediation_recommendations': []
        }

    # ── Calculate Statistics ──────────────────────────────────────────────────
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Informational': 0
    }

    event_type_counts = {}
    mitre_techniques = {}
    suspicious_events = []

    for event in analyzed_events:
        # Count by severity
        level = event['severity']['level']
        severity_counts[level] = severity_counts.get(level, 0) + 1

        # Count by event type
        event_name = event['event_name']
        event_type_counts[event_name] = event_type_counts.get(event_name, 0) + 1

        # Track MITRE techniques
        technique = f"{event['mitre']['technique_id']} — {event['mitre']['technique_name']}"
        if event['mitre']['technique_id'] != 'N/A':
            mitre_techniques[technique] = mitre_techniques.get(technique, 0) + 1

        # Collect suspicious events (High or Critical)
        if level in ('High', 'Critical'):
            suspicious_events.append(event)

    total_events = len(analyzed_events)
    suspicious_count = severity_counts['Critical'] + severity_counts['High']

    # ── Build Executive Summary ───────────────────────────────────────────────
    if severity_counts['Critical'] > 0:
        risk_level = 'CRITICAL'
        summary_line = (
            f"CRITICAL ALERT: {severity_counts['Critical']} critical event(s) detected. "
            "Immediate investigation is required."
        )
    elif severity_counts['High'] > 0:
        risk_level = 'HIGH'
        summary_line = (
            f"HIGH RISK: {severity_counts['High']} high-severity event(s) detected. "
            "These should be investigated as soon as possible."
        )
    elif severity_counts['Medium'] > 0:
        risk_level = 'MEDIUM'
        summary_line = (
            f"MEDIUM RISK: {severity_counts['Medium']} medium-severity event(s) detected. "
            "Review these events and monitor for escalation."
        )
    else:
        risk_level = 'LOW'
        summary_line = (
            f"LOW RISK: {total_events} events analyzed. "
            "No high-risk indicators were found in this log set."
        )

    # ── Build Investigation Checklist ─────────────────────────────────────────
    checklist = []

    if severity_counts['Critical'] > 0 or severity_counts['High'] > 0:
        checklist.append({
            'priority': 'IMMEDIATE',
            'action': f"Investigate the {suspicious_count} High/Critical event(s) flagged in this report.",
            'why': 'High and Critical events indicate potential security incidents requiring fast response.'
        })

    # Check for failed login patterns
    failed_login_events = [e for e in analyzed_events if e['event_id'] == '4625']
    if len(failed_login_events) >= 3:
        checklist.append({
            'priority': 'HIGH',
            'action': f"Investigate {len(failed_login_events)} failed login events — possible brute force attack.",
            'why': 'Multiple failed logins from the same source or against the same account indicate brute force.'
        })

    # Check for new user creation
    new_user_events = [e for e in analyzed_events if e['event_id'] == '4720']
    if new_user_events:
        accounts = [e['raw'].get('TargetUserName', 'Unknown') for e in new_user_events]
        checklist.append({
            'priority': 'HIGH',
            'action': f"Verify new account creation(s): {', '.join(accounts)}",
            'why': 'Unauthorized account creation is a common persistence technique used by attackers.'
        })

    # Check for privilege escalation
    priv_events = [e for e in analyzed_events if e['event_id'] == '4728']
    if priv_events:
        accounts = [e['raw'].get('TargetUserName', 'Unknown') for e in priv_events]
        checklist.append({
            'priority': 'CRITICAL',
            'action': f"Verify privilege group changes for: {', '.join(accounts)}",
            'why': 'Unauthorized privilege escalation can give attackers full control of the domain.'
        })

    # Check for suspicious processes
    process_events = [e for e in analyzed_events if e['event_id'] == '4688']
    if process_events:
        checklist.append({
            'priority': 'MEDIUM',
            'action': f"Review {len(process_events)} process creation event(s) for malicious activity.",
            'why': 'Attackers use scripting interpreters (PowerShell, cmd) to execute malicious code.'
        })

    # Always add general checklist items
    checklist.append({
        'priority': 'STANDARD',
        'action': 'Correlate these events with network logs, EDR telemetry, and threat intelligence feeds.',
        'why': 'Single log sources rarely tell the full story. Cross-source correlation reveals attack chains.'
    })
    checklist.append({
        'priority': 'STANDARD',
        'action': 'Preserve all relevant logs and evidence according to your incident response policy.',
        'why': 'Evidence preservation is critical for forensic analysis and potential legal proceedings.'
    })

    # ── Build Remediation Recommendations ────────────────────────────────────
    remediations = []

    if failed_login_events:
        remediations.append({
            'category': 'Authentication Security',
            'action': 'Enable Multi-Factor Authentication (MFA) for all user accounts, especially remote access.',
            'priority': 'High'
        })
        remediations.append({
            'category': 'Account Protection',
            'action': 'Configure account lockout policies: lock after 5 failed attempts for 30 minutes.',
            'priority': 'High'
        })

    if priv_events or new_user_events:
        remediations.append({
            'category': 'Privilege Management',
            'action': 'Review and enforce least-privilege principles. Remove unnecessary admin rights.',
            'priority': 'Critical'
        })
        remediations.append({
            'category': 'Change Management',
            'action': 'Require formal approval for any privilege changes or new account creation.',
            'priority': 'High'
        })

    if process_events:
        remediations.append({
            'category': 'Endpoint Security',
            'action': 'Deploy and tune an Endpoint Detection & Response (EDR) solution.',
            'priority': 'Medium'
        })
        remediations.append({
            'category': 'Application Control',
            'action': 'Consider implementing PowerShell Constrained Language Mode and script block logging.',
            'priority': 'Medium'
        })

    # General recommendations
    remediations.append({
        'category': 'Monitoring',
        'action': 'Ensure Windows Advanced Audit Policy is configured to capture all relevant event IDs.',
        'priority': 'Medium'
    })
    remediations.append({
        'category': 'Incident Response',
        'action': 'Update your Incident Response Plan to include runbooks for the event types found in this report.',
        'priority': 'Low'
    })

    # ── Assemble the Full Report ──────────────────────────────────────────────
    return {
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'risk_level': risk_level,
        'summary': summary_line,
        'statistics': {
            'total_events': total_events,
            'suspicious_events': suspicious_count,
            'severity_breakdown': severity_counts,
            'event_types': event_type_counts,
            'mitre_techniques': mitre_techniques
        },
        'top_events': [
            {
                'index': e['index'],
                'event_id': e['event_id'],
                'event_name': e['event_name'],
                'severity_level': e['severity']['level'],
                'severity_score': e['severity']['score'],
                'summary': e['analysis'].get('summary', 'See full analysis.')
            }
            for e in suspicious_events[:5]  # Top 5 most critical events
        ],
        'investigation_checklist': checklist,
        'remediation_recommendations': remediations
    }
