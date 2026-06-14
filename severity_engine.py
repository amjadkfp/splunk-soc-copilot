"""
severity_engine.py
==================
Severity scoring engine for Windows Security Events.

This module assigns a severity level and numeric score to each event based on:
  - The Event ID
  - Contextual risk factors (e.g., privileged accounts, suspicious process names)

Severity Levels:
  Critical    (score 90–100) — Immediate investigation required
  High        (score 70–89)  — Investigate as soon as possible
  Medium      (score 40–69)  — Worth reviewing; monitor for patterns
  Low         (score 20–39)  — Likely benign, low risk
  Informational (score 0–19) — Normal activity, logged for audit purposes
"""

# ── Base Severity Scores by Event ID ─────────────────────────────────────────
# These are starting scores that can be adjusted by context
BASE_SCORES = {
    "4624": 10,   # Successful login — usually normal, but watch for off-hours/unusual sources
    "4625": 50,   # Failed login — medium risk; high risk in volume
    "4688": 35,   # Process creation — depends heavily on which process
    "4720": 75,   # New user created — high risk if unauthorized
    "4728": 80,   # User added to privileged group — very high risk if unauthorized
    "4732": 75,   # Member added to local security group
    "4648": 60,   # Explicit credential logon — suspicious in many contexts
}

# ── Known Malicious / Suspicious Processes ───────────────────────────────────
HIGH_RISK_PROCESSES = [
    'mimikatz', 'meterpreter', 'cobaltstrike', 'empire',
    'invoke-', 'encodedcommand', '-enc ', 'downloadstring',
    'iex(', 'invoke-expression'
]

MEDIUM_RISK_PROCESSES = [
    'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
    'bitsadmin.exe', 'wmic.exe', 'psexec.exe', 'at.exe', 'schtasks.exe'
]

# ── Privileged/Sensitive Account Names ───────────────────────────────────────
PRIVILEGED_ACCOUNTS = [
    'administrator', 'admin', 'root', 'system',
    'domain admins', 'enterprise admins', 'schema admins', 'backup operators'
]


def calculate_severity(event: dict) -> dict:
    """
    Calculate the severity score and level for a single security event.

    Args:
        event: A dict representing a parsed Windows Security Event.

    Returns:
        A dict with 'score' (int 0-100), 'level' (string), and 'reason' (string).
    """
    event_id = str(event.get('EventID', '')).strip()
    score = BASE_SCORES.get(event_id, 15)  # Default to 15 (Informational) for unknown events
    reasons = []

    # ── Event-Specific Context Analysis ──────────────────────────────────────

    if event_id == '4625':
        # Failed login — check for privileged account targeting
        target = str(event.get('TargetUserName', '')).lower()
        if any(p in target for p in PRIVILEGED_ACCOUNTS):
            score += 25
            reasons.append('Failed login targeting a privileged account')
        else:
            reasons.append('Standard failed login attempt')

    elif event_id == '4688':
        # Process creation — evaluate the process name
        process_name = str(event.get('NewProcessName', '')).lower()
        cmd_line = str(event.get('CommandLine', '')).lower()

        if any(h in process_name or h in cmd_line for h in HIGH_RISK_PROCESSES):
            score = 95  # Override to Critical
            reasons.append('High-risk process or known offensive tool detected')
        elif any(m in process_name for m in MEDIUM_RISK_PROCESSES):
            score = max(score, 55)
            reasons.append(f'Scripting interpreter or admin tool launched: {process_name}')
        else:
            reasons.append('Standard process creation')

    elif event_id == '4720':
        # New account — check if it targets a sensitive naming pattern
        new_account = str(event.get('TargetUserName', '')).lower()
        if any(p in new_account for p in ['admin', 'svc', 'service', 'backup']):
            score += 15
            reasons.append('New account name matches privileged/service naming pattern')
        else:
            reasons.append('New user account was created')

    elif event_id == '4728':
        # Added to privileged group
        group = str(event.get('TargetUserName', 'Unknown Group')).lower()
        if any(p in group for p in ['domain admins', 'enterprise admins', 'administrators']):
            score = 95  # Critical — top-tier group modification
            reasons.append('User added to Domain Admins or Enterprise Admins — critical change')
        else:
            reasons.append('User added to a privileged security group')

    elif event_id == '4624':
        # Successful login — check for suspicious logon types
        logon_type = str(event.get('LogonType', ''))
        if logon_type == '3':  # Network logon
            score = 25
            reasons.append('Network logon (Type 3) — watch for lateral movement patterns')
        elif logon_type == '10':  # RemoteInteractive (RDP)
            score = 35
            reasons.append('Remote Desktop (RDP) logon — verify this is authorized')
        else:
            reasons.append('Successful interactive logon')

    elif event_id == '4648':
        reasons.append('Explicit credentials used — potential pass-the-hash or credential forwarding')
        score = max(score, 60)

    else:
        reasons.append('Event logged for audit purposes')

    # ── Cap the score at 100 ──────────────────────────────────────────────────
    score = min(score, 100)

    # ── Map numeric score to severity level ───────────────────────────────────
    if score >= 90:
        level = 'Critical'
    elif score >= 70:
        level = 'High'
    elif score >= 40:
        level = 'Medium'
    elif score >= 20:
        level = 'Low'
    else:
        level = 'Informational'

    return {
        'score': score,
        'level': level,
        'reason': '; '.join(reasons) if reasons else 'Standard event'
    }
