"""
SOC Copilot: AI-Powered Security Log Investigation Agent
=========================================================
Main Flask application file.
This is the entry point for the web server.

Author: SOC Copilot Project
Target: Beginner SOC Analysts & Cybersecurity Students
"""

import os
import json
import csv
import io
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename

# Import our custom modules
import analyzer                          # imported as module so we can set analyzer.splunk_client
from analyzer import analyze_events
from report_generator import generate_report
from mitre_mapping import get_mitre_info
from severity_engine import calculate_severity
from splunk_hec import SplunkHECClient  # always importable; only instantiated when token is set

# ── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Configuration: where uploaded files are stored, max size 16 MB
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Make sure the uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file types for upload
ALLOWED_EXTENSIONS = {'json', 'csv'}

# ── Splunk HEC Configuration ──────────────────────────────────────────────────
# All three variables are read from the environment.  Sensible defaults are
# provided for SPLUNK_HEC_URL and SPLUNK_INDEX so only SPLUNK_HEC_TOKEN
# needs to be set to enable the integration.
#
#   export SPLUNK_HEC_URL="https://splunk.corp.example.com:8088"
#   export SPLUNK_HEC_TOKEN="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#   export SPLUNK_INDEX="soc_copilot"   # optional, defaults to "soc_copilot"
#
SPLUNK_HEC_URL   = os.environ.get('SPLUNK_HEC_URL',   'http://localhost:8088')
SPLUNK_HEC_TOKEN = os.environ.get('SPLUNK_HEC_TOKEN', '')
SPLUNK_INDEX     = os.environ.get('SPLUNK_INDEX',     'soc_copilot')

# Initialise the HEC client only when a token is present.
# When the token is absent the app behaves identically to the pre-Splunk version.
splunk_hec_client = None
if SPLUNK_HEC_TOKEN:
    try:
        splunk_hec_client = SplunkHECClient(
            hec_url=SPLUNK_HEC_URL,
            hec_token=SPLUNK_HEC_TOKEN,
            index=SPLUNK_INDEX,
            verify_ssl=False,
        )
        # Wire the client into the analyzer module so that every enriched
        # event is automatically forwarded to Splunk inside analyze_events().
        analyzer.splunk_client = splunk_hec_client
        print(
            f"[SOC Copilot] Splunk HEC enabled → {SPLUNK_HEC_URL}  "
            f"index={SPLUNK_INDEX}"
        )
    except Exception as exc:
        print(f"[SOC Copilot] Splunk HEC init failed (continuing without it): {exc}")
        splunk_hec_client = None


def allowed_file(filename):
    """Check if a file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_uploaded_file(filepath, filename):
    """
    Parse the uploaded log file (JSON or CSV) and return a list of event dicts.
    Supports both JSON arrays and CSV rows.
    """
    events = []

    if filename.endswith('.json'):
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Handle both a list of events or a single event dict
            if isinstance(data, list):
                events = data
            elif isinstance(data, dict):
                events = [data]

    elif filename.endswith('.csv'):
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(dict(row))

    return events


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve the main single-page interface."""
    return render_template('index.html')


@app.route('/api/splunk/status', methods=['GET'])
def splunk_status():
    """
    Report the current state of the Splunk HEC integration.

    Response JSON:
        {
          "connected": bool,   # True if HEC health check passed
          "url":       str,    # SPLUNK_HEC_URL (from env or default)
          "index":     str     # SPLUNK_INDEX (from env or default)
        }

    When SPLUNK_HEC_TOKEN is not set, ``connected`` is always ``False``
    and a human-readable message explains why.
    """
    if splunk_hec_client is None:
        return jsonify({
            'connected': False,
            'url':       SPLUNK_HEC_URL,
            'index':     SPLUNK_INDEX,
            'message':   'Splunk HEC is not configured — set the SPLUNK_HEC_TOKEN environment variable to enable it.',
        })

    connected = splunk_hec_client.test_connection()
    return jsonify({
        'connected': connected,
        'url':       SPLUNK_HEC_URL,
        'index':     SPLUNK_INDEX,
    })


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    API endpoint: accept a log file upload, parse it, run AI analysis,
    and return structured results as JSON.
    """
    # Check that a file was actually sent
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided. Please upload a JSON or CSV log file.'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Unsupported file type. Please upload .json or .csv files only.'}), 400

    # Save the file securely
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        # Step 1: Parse the raw log file into a list of event dicts
        raw_events = parse_uploaded_file(filepath, filename)

        if not raw_events:
            return jsonify({'error': 'No events found in the file. Check the file format.'}), 400

        # Step 2: Run the analysis engine on each event
        analyzed_events = analyze_events(raw_events)

        # Step 3: Generate the final summary report
        report = generate_report(analyzed_events)

        # Step 4: Return everything to the frontend
        return jsonify({
            'success': True,
            'total_events': len(analyzed_events),
            'events': analyzed_events,
            'report': report
        })

    except Exception as e:
        # Return a friendly error message
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

    finally:
        # Clean up: remove the uploaded file after processing
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route('/api/threat-hunt', methods=['POST'])
def threat_hunt():
    """
    API endpoint: accept analyzed events (from a previous /api/analyze call)
    and run the Threat Hunt logic to find patterns of suspicious behavior.
    """
    data = request.get_json()
    if not data or 'events' not in data:
        return jsonify({'error': 'No events provided for threat hunting.'}), 400

    events = data['events']

    # ── Threat Hunt Logic ──────────────────────────────────────────────────
    findings = []

    # Count failed logins per account
    failed_logins = {}
    for event in events:
        event_id = str(event.get('EventID', ''))
        account = event.get('TargetUserName') or event.get('SubjectUserName') or 'Unknown'
        if event_id == '4625':
            failed_logins[account] = failed_logins.get(account, 0) + 1

    # Flag accounts with 5 or more failed logins (brute force indicator)
    for account, count in failed_logins.items():
        if count >= 5:
            findings.append({
                'type': 'Brute Force Indicator',
                'severity': 'High',
                'description': f'Account "{account}" had {count} failed login attempts — possible brute force attack.',
                'recommendation': 'Investigate the source IP, consider locking the account, and review authentication logs.'
            })
        elif count >= 2:
            findings.append({
                'type': 'Repeated Login Failures',
                'severity': 'Medium',
                'description': f'Account "{account}" had {count} failed login attempts.',
                'recommendation': 'Monitor for further failures and verify with the account owner.'
            })

    # Check for new privileged user additions
    privileged_events = [e for e in events if str(e.get('EventID', '')) == '4728']
    for event in privileged_events:
        account = event.get('TargetUserName', 'Unknown')
        findings.append({
            'type': 'Privilege Escalation',
            'severity': 'High',
            'description': f'Account "{account}" was added to a privileged group (Event 4728).',
            'recommendation': 'Verify this change was authorized. If unexpected, investigate immediately.'
        })

    # Check for suspicious process creation (Event 4688)
    suspicious_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                            'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe']
    for event in events:
        if str(event.get('EventID', '')) == '4688':
            process = str(event.get('NewProcessName', '')).lower()
            for sus in suspicious_processes:
                if sus in process:
                    findings.append({
                        'type': 'Suspicious Process',
                        'severity': 'Medium',
                        'description': f'Suspicious process "{sus}" was launched (Event 4688).',
                        'recommendation': f'Review the command line arguments and the parent process for "{sus}".'
                    })
                    break

    if not findings:
        findings.append({
            'type': 'No Threats Found',
            'severity': 'Informational',
            'description': 'No significant threat patterns were detected in the provided events.',
            'recommendation': 'Continue monitoring. Consider uploading more logs for a broader view.'
        })

    # Forward each finding to Splunk HEC if integration is configured.
    # Failures are non-fatal — the API response is returned regardless.
    if splunk_hec_client is not None:
        for finding in findings:
            splunk_hec_client.send_threat_finding(finding)

    return jsonify({'success': True, 'findings': findings})


@app.route('/api/sample-logs')
def get_sample_logs():
    """Return sample log data for users to try without uploading a file."""
    sample_path = os.path.join('sample_logs', 'windows_security_events.json')
    if os.path.exists(sample_path):
        with open(sample_path, 'r') as f:
            return jsonify(json.load(f))
    return jsonify({'error': 'Sample logs not found.'}), 404


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 60)
    print("  SOC Copilot — AI Security Log Investigation Agent")
    print("  Starting server at http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5000)
