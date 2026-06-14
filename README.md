# 🛡️ SOC Copilot — AI-Powered Security Log Investigation Agent

> **Microsoft Agents League Hackathon** | Reasoning Agents Track

A beginner-friendly web application that acts as an AI Security Operations Center (SOC) analyst. Upload Windows Security Event Logs, and SOC Copilot uses Claude AI to explain what happened, assess threats, map to MITRE ATT&CK, and recommend investigation steps — all in plain English.

---

## 🎯 Project Overview

Security logs are complex and cryptic. Beginner SOC analysts often spend hours trying to understand what a Windows Event ID means and whether it's a real threat.

**SOC Copilot bridges that gap** by combining:
- **Rule-based severity scoring** — Fast, deterministic analysis of event types
- **AI reasoning (Claude API)** — Human-readable explanations and multi-step investigation guidance
- **MITRE ATT&CK mapping** — Connect events to the global adversary behavior framework
- **Threat Hunt engine** — Automated pattern detection for brute force, privilege escalation, and more

---

## ✨ Features

| Feature | Description |
|---|---|
| 📤 Log Upload | Upload JSON or CSV Windows Security Event logs |
| 🤖 AI Analysis | Per-event AI explanations using Claude Sonnet |
| 🎯 Severity Scoring | Automatic 0–100 scoring with Critical/High/Medium/Low/Informational levels |
| 🗺️ MITRE ATT&CK | Maps each event to ATT&CK technique ID, name, tactic, and description |
| 🔍 Threat Hunt | One-click scan for brute force, privilege escalation, and suspicious processes |
| 📊 Dashboard | Live counters for total, suspicious, and critical events |
| 📄 Security Report | Full investigation checklist and remediation recommendations |
| 🖥️ Dark Terminal UI | Professional SOC-themed interface with severity-coded color system |
| 📱 Responsive | Works on desktop and mobile browsers |

### Supported Windows Event IDs
| Event ID | Description | MITRE Technique |
|---|---|---|
| 4624 | Successful Logon | T1078 — Valid Accounts |
| 4625 | Failed Logon | T1110 — Brute Force |
| 4688 | Process Created | T1059 — Command & Scripting Interpreter |
| 4720 | User Account Created | T1136 — Create Account |
| 4728 | Member Added to Privileged Group | T1098 — Account Manipulation |

---

## 🚀 Installation & Running (Windows 11)

### Prerequisites
- Python 3.12 or higher — [download](https://www.python.org/downloads/)

### Step 1 — Clone or Download
```
Download and extract the soc-copilot folder to your Desktop or any directory.
```

### Step 2 — Open Terminal
```
Press Win + R, type cmd, press Enter.
cd path\to\soc-copilot
```
Or right-click the folder in Explorer → "Open in Terminal"

### Step 3 — Create a Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate
```
You should see `(venv)` appear in your terminal prompt.

### Step 4 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 5 — Set Your API Key

**Windows (Command Prompt):**
```cmd
set ANTHROPIC_API_KEY=sk-ant-your-key-here
```

**Windows (PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-your-key-here"
```

> **Note:** If you don't have an API key, the app still works! It uses a built-in rule-based fallback engine for all analysis. The fallback provides detailed, educational explanations — perfect for demos.

### Step 6 — Run the App
```bash
python app.py
```

You should see:
```
============================================================
  SOC Copilot — AI Security Log Investigation Agent
  Starting server at http://127.0.0.1:5000
============================================================
```

### Step 7 — Open in Browser
Navigate to: **http://127.0.0.1:5000**

Click **"Try Sample Logs"** to immediately see a full demo with a simulated attack scenario.

---

## 📁 Project Structure

```
soc-copilot/
│
├── app.py                  ← Flask web server, API endpoints
├── analyzer.py             ← AI reasoning engine 
├── mitre_mapping.py        ← MITRE ATT&CK technique lookup table
├── severity_engine.py      ← Severity scoring (0–100) with context analysis
├── report_generator.py     ← Security report and checklist generator
│
├── requirements.txt        ← Python dependencies
├── README.md               ← This file
│
├── templates/
│   └── index.html          ← Single-page web interface (Bootstrap 5)
│
├── static/                 ← Static assets (CSS/JS if needed)
│
├── sample_logs/
│   └── windows_security_events.json  ← 12 sample events with a simulated attack chain
│
└── uploads/                ← Temporary file storage (auto-cleaned after analysis)
```

---

## 🧠 How the AI Reasoning Works

SOC Copilot demonstrates **multi-step AI reasoning** by chaining these steps for every event:

```
1. Parse Event
   └─ Extract Event ID, user, timestamp, IP, process name

2. Severity Engine
   └─ Calculate 0–100 risk score based on event type + context
      (e.g., failed login against "administrator" = higher score)

3. MITRE ATT&CK Mapping
   └─ Map Event ID → Technique ID, Name, Tactic, Description

4. Claude AI Prompt
   └─ Send structured context to Claude Sonnet
      - Event details
      - Pre-calculated severity
      - MITRE context
   └─ Claude returns JSON with:
      - summary, security_explanation, threat_assessment
      - investigation_steps (3 steps)
      - remediation actions
      - analyst_tip

5. Threat Hunt (on demand)
   └─ Pattern analysis across ALL events:
      - Count failed logins per account (brute force)
      - Detect privilege escalation events
      - Flag suspicious process names
```

---

## 🔒 Sample Attack Scenario

The included sample logs (`windows_security_events.json`) simulate a **realistic attack chain**:

1. **Brute Force** — 6 failed logins against the Administrator account
2. **Successful Access** — Attacker authenticates from IP 192.168.1.45
3. **Malicious PowerShell** — Encoded PowerShell command executes a download cradle
4. **Backdoor Account** — New account `svc_backdoor` created
5. **Privilege Escalation** — `svc_backdoor` added to Domain Admins group
6. **Normal Activity** — Legitimate user `jsmith` logging in (baseline)

This mirrors real-world attack patterns mapped to the MITRE ATT&CK framework.

---

## 🖼️ Screenshots

> 

| Screen | Description |
|---|---|
| Welcome Screen | Dark terminal-themed landing with ASCII art |
| Event Analysis | Per-event AI analysis with severity badges |
| Threat Hunt | Automated pattern detection results |
| Report View | Investigation checklist and remediation guide |
| MITRE ATT&CK | Technique cards with links to official MITRE site |

---

## 🚀 Future Improvements

- [ ] **Live SIEM Integration** — Connect to Splunk, Elastic, or Microsoft Sentinel
- [ ] **Sigma Rule Support** — Parse and apply community detection rules
- [ ] **Timeline View** — Visualize attack progression chronologically
- [ ] **Multi-File Analysis** — Cross-correlate events from multiple log sources
- [ ] **Email Reports** — Export and send PDF investigation reports
- [ ] **Custom Rules Engine** — Let analysts define their own detection logic
- [ ] **User Accounts** — Save and compare historical investigations
- [ ] **Sysmon Support** — Full Sysmon event ID parsing (Event ID 1, 3, 7, etc.)
- [ ] **Network Log Analysis** — Extend to firewall and proxy logs

---

## 🤝 Built For

**Microsoft Agents League Hackathon — Reasoning Agents Track**

SOC Copilot demonstrates reasoning agents by:
- **Multi-step reasoning** over structured security data
- **Context-aware analysis** that adjusts severity based on event relationships
- **Decision support** that guides analysts through investigation steps
- **Human-readable explanations** that bridge AI insights and analyst understanding
- **Actionable outputs** — not just analysis, but specific steps to take next

---

## 📜 License

This project is intended for educational and demonstration purposes.

---

*Built with Python, Flask, Bootstrap 5, and optional AI-assisted analysis support. Includes Splunk integration, MITRE ATT&CK mapping, and threat hunting capabilities.*
