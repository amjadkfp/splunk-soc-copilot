███████╗ ██████╗  ██████╗     ██████╗ ██████╗ ██████╗ ██╗██╗      ██████╗ ████████╗
██╔════╝██╔═══██╗██╔════╝    ██╔════╝██╔═══██╗██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
███████╗██║   ██║██║         ██║     ██║   ██║██████╔╝██║██║     ██║   ██║   ██║   
╚════██║██║   ██║██║         ██║     ██║   ██║██╔═══╝ ██║██║     ██║   ██║   ██║   
███████║╚██████╔╝╚██████╗    ╚██████╗╚██████╔╝██║     ██║███████╗╚██████╔╝   ██║   
╚══════╝ ╚═════╝  ╚═════╝     ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝   
🛡️ SOC Copilot
AI-Powered Security Operations Center Platform










Detect threats. Investigate security events. Map attacker behavior. Generate actionable intelligence. Forward enriched findings to Splunk.










📋 Table of Contents
🎯 Overview	🖼️ Dashboard	✨ Features
🚀 Capabilities	🏆 Attack Scenario	📦 Installation
🧠 How It Works	🔒 Sample Scenario	🖼️ Screenshots
🗺️ Roadmap	📜 License	🛠️ Built With
🎯 Why SOC Copilot?
Transform raw Windows Security Event Logs into actionable security intelligence.
Built for SOC analysts, cybersecurity learners, and security teams.

Security analysts often face thousands of security events daily. Understanding whether an event represents normal activity or a potential attack requires significant time and expertise.

💡 SOC Copilot accelerates investigations by automatically handling the heavy lifting so analysts can focus on what matters most.

⚡ Accelerated Investigation Pipeline
Step	Action	Outcome
🎯	Prioritize suspicious events using severity scoring	Risk-based triage in seconds
🤖	Explain security events in plain English	No more decoding raw Event IDs
🗺️	Map attacker behavior to MITRE ATT&CK	Adversary context instantly
🔍	Detect attack patterns across multiple events	Catch chains, not just singles
📄	Generate investigation and remediation guidance	Actionable checklists on demand
🔗	Forward enriched findings to Splunk	Centralized SIEM correlation
🖼️ Interactive Dashboard Mockup
🌐 Explore the standalone SOC dashboard prototype




✨ Features
🚀 Everything You Need to Investigate Threats Like a Pro

📤 Windows Log Analysis
Upload and analyze Windows Security Event Logs (JSON/CSV)

🤖 AI-Assisted Investigation
Generate security explanations, threat assessments, and analyst guidance

🎯 Severity Scoring Engine
Risk-based scoring system with Critical, High, Medium, Low, and Informational classifications

🗺️ MITRE ATT&CK Mapping
Automatically map events to ATT&CK techniques, tactics, and adversary behaviors

🔍 Automated Threat Hunting
Detect brute force attacks, privilege escalation, suspicious accounts, and malicious processes

📊 SOC Dashboard
Interactive analyst dashboard with event statistics and severity breakdowns

📄 Investigation Reports
Generate investigation checklists and remediation recommendations

🔗 Splunk HEC Integration
Forward enriched security events and threat-hunt findings directly to Splunk

🛡️ Event Enrichment
Combine severity, MITRE context, AI analysis, and threat intelligence into a unified view

🖥️ SOC-Inspired Interface
Modern dark-themed cybersecurity dashboard designed for analysts

📱 Responsive Design
Optimized for desktop and mobile devices




🚀 Core Capabilities
🔍 Analysis	🗺️ Intelligence	🔗 Integration
Event Analysis	Threat Hunting	Splunk Integration
Severity Scoring	MITRE ATT&CK	AI Reasoning
Event Enrichment	Pattern Detection	Reporting

🔬 Security Event Analysis
Transform raw Windows Security Events into human-readable security insights.


🎯 Threat Hunting
Identify indicators of compromise including:


🎯 Detection	📝 Description
🔑 Brute Force Attacks	Repeated failed authentication attempts
⬆️ Privilege Escalation	Unauthorized group membership changes
⚡ Suspicious PowerShell Activity	Encoded or malicious command execution
👤 Unauthorized Account Creation	New accounts created outside normal provisioning
🛡️ Privileged Group Modifications	Changes to Domain Admins and other sensitive groups

🗺️ MITRE ATT&CK Intelligence
Understand attacker behavior through technique and tactic mapping aligned with the MITRE ATT&CK framework.


🔗 Splunk Integration
Forward enriched events, threat-hunting findings, severity scores, and investigation results to Splunk through HTTP Event Collector (HEC) for centralized monitoring and analysis.


🤖 AI-Powered Investigations
Leverage AI-assisted reasoning to generate:


📝 Output	🎯 Purpose
📋 Event Summaries	Quick understanding of what happened
🚨 Threat Assessments	Risk evaluation for each event
🔎 Investigation Steps	Analyst action items
👨‍💻 Analyst Recommendations	Expert guidance from AI
🛠️ Remediation Actions	Concrete fix steps
🏆 Sample Attack Scenario
🎬 SOC Copilot can detect and investigate a complete attack chain

SOC Copilot can detect and investigate a complete attack chain:


text

Copy
┌─────────────────────────────────────────────────────────────────────────┐

│                                                                         │

│   ① Brute Force Login Attempts ──►  Event ID 4625   [T1110]             │

│              │                                                          │

│              ▼                                                          │

│   ② Successful Account Compromise ──►  Event ID 4624  [T1078]           │

│              │                                                          │

│              ▼                                                          │

│   ③ PowerShell Command Execution ──►  Event ID 4688  [T1059]            │

│              │                                                          │

│              ▼                                                          │

│   ④ Unauthorized Account Creation ──►  Event ID 4720  [T1136]           │

│              │                                                          │

│              ▼                                                          │

│   ⑤ Privilege Escalation via Group Membership ──►  Event ID 4728 [T1098]│

│                                                                         │

└─────────────────────────────────────────────────────────────────────────┘

The platform correlates these events, maps them to MITRE ATT&CK techniques, generates investigation guidance, and produces a comprehensive security report.


📋 Supported Windows Event IDs
🎯 Event ID	📝 Description	🗺️ MITRE Technique
4624	Successful Logon	T1078 — Valid Accounts
4625	Failed Logon	T1110 — Brute Force
4688	Process Created	T1059 — Command & Scripting Interpreter
4720	User Account Created	T1136 — Create Account
4728	Member Added to Privileged Group	T1098 — Account Manipulation


📦 Installation & Running (Windows 11)
🛠️ Get up and running in 5 minutes

📋 Prerequisites
✅ Python 3.10 or higher installed
✅ Internet connection (optional, for AI-assisted analysis)
✅ Git (optional, for cloning the repository)

🔹 Step 1 — Clone or Download
bash

Copy
# Clone the repository

git clone https://github.com/YOUR_USERNAME/soc-copilot.git

cd soc-copilot


# Or download the ZIP file and extract it

🔹 Step 2 — Open Terminal
bash

Copy
# Press Win + R, type cmd, press Enter

cd path\to\splunk-soc-copilot


# Or right-click the folder in Explorer → "Open in Terminal"

🔹 Step 3 — Create a Virtual Environment
bash

Copy
# Create venv

python -m venv venv


# Activate it:
💡 You should see (venv) appear in your terminal prompt.


🔹 Step 4 — Install Dependencies
bash

Copy
pip install -r requirements.txt

🔹 Step 5 — Run SOC Copilot
🚀 Option	📝 Method	⭐ Recommended
A	Double-click start_soc_copilot.bat	⭐ Yes
B	Run python app.py from terminal	✅ Yes

Option A — One-Click Launcher (Recommended)

Double-click: start_soc_copilot.bat

Option B — Run from Terminal

bash

Copy
python app.py

🔹 Step 6 — Open in Browser
🌐 Navigate to: http://127.0.0.1:5000
💡 Click "Try Sample Logs" to immediately see a full demo with a simulated attack scenario.


🤖 Optional AI-Assisted Analysis
To enable AI-assisted analysis, configure your API key before starting the application.

⚠️ If no API key is configured, SOC Copilot will continue to operate using offline rule-based analysis.

📁 Project Structure
🗂️ Clean, Modular Architecture

text

Copy
soc-copilot/

│

├── 📄 app.py                  ← Flask web server, API endpoints

├── 🧠 analyzer.py             ← AI reasoning engine 

├── 🗺️ mitre_mapping.py        ← MITRE ATT&CK technique lookup table

├── 📊 severity_engine.py      ← Severity scoring (0–100) with context analysis

├── 📋 report_generator.py     ← Security report and checklist generator

│

├── 📦 requirements.txt        ← Python dependencies

├── 📖 README.md               ← This file

│

├── 🎨 templates/

│   └── index.html             ← Single-page web interface (Bootstrap 5)

│

├── 🖼️ static/                 ← Static assets (CSS/JS if needed)

│

├── 📊 sample_logs/

│   └── windows_security_events.json  ← 12 sample events with a simulated attack chain


🧠 How SOC Copilot Works
⚙️ Multi-Stage Analysis Pipeline

text

Copy
┌──────────────────────┐

│  Windows Security    │

│       Events         │

└──────────┬───────────┘

           │

           ▼

   ┌───────────────┐

   │ Event Parsing │

   └───────┬───────┘

           │

           ▼

   ┌─────────────────────┐

   │  Severity Scoring   │

   └───────┬─────────────┘

           │

           ▼

   ┌─────────────────────┐

   │ MITRE ATT&CK Mapping│

   └───────┬─────────────┘

           │

           ▼

   ┌──────────────────────────────┐

   │  AI-Assisted Investigation   │

   └───────┬──────────────────────┘

           │

           ▼

   ┌─────────────────────┐

   │   Threat Hunting    │

   └───────┬─────────────┘

           │

           ▼

   ┌─────────────────────┐

   │ Security Reporting  │

   └───────┬─────────────┘

           │

           ▼

   ┌─────────────────────┐

   │  Splunk Integration │

   └─────────────────────┘

🔬 The 7-Stage Pipeline

1️⃣ Event Parsing
SOC Copilot extracts key security information from uploaded logs, including:

🔑 Field	📝 Description
🆔 Event ID	Windows Security Event identifier
👤 Username	Account associated with the event
🌐 Source IP Address	Network origin of the activity
⏰ Timestamp	When the event occurred
⚙️ Process Name	Executable that triggered the event
💻 Computer Name	Host where the event was recorded

2️⃣ Severity Scoring Engine
Each event is assigned a risk score between 0–100 based on event type and contextual indicators.


🚨 Event	📊 Risk Level
✅ Successful Login (4624)	🟢 Low
❌ Failed Login (4625)	🟡 Medium–High
👤 New User Account Created (4720)	🟠 High
🛡️ Privileged Group Membership Change (4728)	🔴 Critical

3️⃣ MITRE ATT&CK Mapping
SOC Copilot maps Windows Security Events to MITRE ATT&CK techniques and tactics to provide adversary context.


🆔 Event ID	🗺️ Technique
4625	⚔️ T1110 – Brute Force
4624	🔑 T1078 – Valid Accounts
4688	💻 T1059 – Command & Scripting Interpreter
4720	👤 T1136 – Create Account
4728	🛡️ T1098 – Account Manipulation

4️⃣ AI-Assisted Investigation
The analysis engine combines:

📋 Event Details
📊 Severity Score
🗺️ MITRE ATT&CK Context
🚨 Threat Indicators
to generate:

📝 Security Event Summary
🚨 Threat Assessment
🔎 Investigation Steps
🛠️ Remediation Recommendations
👨‍💻 Analyst Guidance

5️⃣ Threat Hunting Engine
SOC Copilot analyzes events collectively to identify attack patterns and indicators of compromise.

Current detections include:

🔑 Brute Force Activity
⬆️ Privilege Escalation Attempts
⚡ Suspicious PowerShell Execution
👤 Unauthorized Account Creation
🛡️ Privileged Group Modifications

6️⃣ Security Reporting
The platform generates investigation-ready reports containing:

📊 Severity Overview
🗺️ MITRE ATT&CK Coverage
🔍 Threat Hunting Findings
📋 Investigation Checklist
🛠️ Recommended Actions

7️⃣ Splunk Integration
Enriched security events, threat assessments, MITRE ATT&CK mappings, and threat-hunting findings are forwarded to Splunk using the HTTP Event Collector (HEC), enabling centralized monitoring, searching, and visualization within a SIEM environment.



🔒 Sample Attack Scenario
🎬 The included sample logs simulate a realistic attack chain

The included sample logs (windows_security_events.json) simulate a realistic attack chain:


text

Copy
   ①  🔑 Brute Force ──►  6 failed logins against the Administrator account

              │

              ▼

   ②  ✅ Successful Access ──►  Attacker authenticates from IP 192.168.1.45

              │

              ▼

   ③  ⚡ Malicious PowerShell ──►  Encoded PowerShell command executes a download cradle

              │

              ▼

   ④  👤 Backdoor Account ──►  New account `svc_backdoor` created

              │

              ▼

   ⑤  ⬆️ Privilege Escalation ──►  `svc_backdoor` added to Domain Admins group

              │

              ▼

   ⑥  ✅ Normal Activity ──►  Legitimate user `jsmith` logging in (baseline)

💡 This mirrors real-world attack patterns mapped to the MITRE ATT&CK framework.

🖼️ Screenshots
🖼️ Screen	📷 Preview	📝 Description
🎬 Welcome Screen	
Dark terminal-themed landing with ASCII art
🔍 Event Analysis	
Per-event AI analysis with severity badges
🎯 Threat Hunt	
Automated pattern detection results
📋 Report View	
Investigation checklist and remediation guide
🗺️ MITRE ATT&CK	
Technique cards with links to official MITRE site
🚀 Future Roadmap
🌟 The Path Forward
Planned enhancements to expand SOC Copilot's threat detection, investigation, and SOC automation capabilities:


Status	Feature	Description
⬜	📊 Advanced Splunk Dashboards	Interactive security dashboards, visualizations, and alerting for enriched SOC Copilot events
⬜	☁️ Microsoft Sentinel Integration	Forward enriched findings to Microsoft Sentinel for cloud-native SOC operations
⬜	🔎 Elastic Security Integration	Support Elastic Stack for centralized security monitoring
⬜	📐 Sigma Rule Engine	Parse and apply community-driven Sigma detection rules
⬜	⏱️ Attack Timeline View	Visualize attacker activity and event progression chronologically
⬜	🔗 Multi-Source Correlation	Correlate Windows logs, Sysmon events, firewall logs, and authentication logs
⬜	📄 PDF & Executive Reports	Export investigation reports and incident summaries
⬜	⚙️ Custom Detection Rules	Allow analysts to create and manage custom detection logic
⬜	🔐 User Authentication & Case Management	Save investigations, track incidents, and manage analyst workflows
⬜	💻 Sysmon Support	Advanced endpoint visibility using Sysmon Event IDs and telemetry
⬜	🌐 Network Security Analysis	Support firewall, proxy, DNS, and network traffic logs
⬜	🧠 Threat Intelligence Integration	Enrich events with external IOC and threat intelligence feeds
⬜	🤖 SOAR Automation	Automated response actions such as IP blocking, account disabling, and alert escalation
⬜	📝 AI Incident Summarization	Generate executive-ready incident summaries and response recommendations


📜 License
🛡️ This project is intended for educational, research, and demonstration purposes.


This project showcases cybersecurity concepts including:

🪟 Windows Security Event Log analysis
🎯 Threat hunting & attack pattern detection
🗺️ MITRE ATT&CK mapping
🤖 AI-assisted investigations
📊 Security event enrichment
🔗 Splunk integration
⚠️ Users are responsible for ensuring compliance with applicable security policies, organizational requirements, and third-party service terms when deploying or modifying this project.



🛠️ Built With
🛠️ Technology	🎯 Purpose
🐍 Python	Core language
🌶️ Flask	Web framework
🎨 Bootstrap 5	UI framework
🤖 Claude AI (Optional)	AI-powered analysis
🔗 Splunk HEC	SIEM integration
🗺️ MITRE ATT&CK	Threat intelligence framework



🔐 Core Capabilities
SOC Copilot demonstrates how AI, threat detection, event enrichment, and SIEM integration can help security analysts investigate threats more efficiently.


🎯 Capability	📝 Description
🪟 Windows Security Event Log Analysis	Parse and enrich raw security events
🎯 Threat Hunting & Attack Pattern Detection	Identify IOCs across event chains
🗺️ MITRE ATT&CK Technique Mapping	Map events to adversary behaviors
🤖 AI-Assisted Security Investigations	Generate human-readable explanations
📊 Severity Scoring & Event Enrichment	Risk-based prioritization
📄 Security Reporting & Remediation Guidance	Actionable response playbooks
🔗 Splunk Integration for Centralized Monitoring	Forward enriched events to SIEM

🛡️ Made with passion for SOC analysts and the cybersecurity community
⭐ Star this repo if you find it useful!

📅 Last updated · 2026 · 🐛 Found a bug? Open an issue · 💡 Have an idea? Start a discussion
