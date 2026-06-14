"""
splunk_hec.py
=============
Splunk HTTP Event Collector (HEC) integration for SOC Copilot.

Provides a client that forwards enriched security events and threat-hunt
findings to a Splunk instance over HEC. The integration is entirely optional:
if SPLUNK_HEC_TOKEN is not set, no client is initialised and the rest of
the app continues to work identically.

Usage (from app.py):
    from splunk_hec import SplunkHECClient
    client = SplunkHECClient(hec_url="https://splunk:8088",
                             hec_token="xxxx", index="soc_copilot")
    client.send_event(enriched_event)
    client.send_threat_finding(finding)

HEC reference: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
"""

import datetime
import logging

import requests
import urllib3

logger = logging.getLogger(__name__)


class SplunkHECClient:
    """
    Thin, fault-tolerant wrapper around the Splunk HTTP Event Collector API.

    Design principles
    -----------------
    * Every network call is wrapped in try/except — a Splunk outage must
      never crash the SOC Copilot application.
    * A single requests.Session is shared for connection reuse and consistent
      auth headers across all calls.
    * Timeouts are hard-coded to 5 s on every request.
    """

    # ── Initialisation ────────────────────────────────────────────────────────

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        index: str,
        verify_ssl: bool = False,
    ) -> None:
        """
        Args:
            hec_url:    Base URL of the Splunk HEC endpoint, e.g.
                        ``https://splunk.corp.example.com:8088``.
            hec_token:  Splunk HEC authentication token (created under
                        Settings → Data Inputs → HTTP Event Collector).
            index:      Target Splunk index (must already exist in Splunk).
            verify_ssl: Set to ``True`` if Splunk has a trusted TLS certificate.
                        Defaults to ``False`` because many on-premises Splunk
                        deployments use self-signed certs.
        """
        self.hec_url = hec_url.rstrip("/")
        self.index = index
        self.verify_ssl = verify_ssl

        # Suppress noisy InsecureRequestWarning when SSL verification is off
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Reusable session: auth header is set once and sent with every request
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Splunk {hec_token}",
                "Content-Type": "application/json",
            }
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _post(self, endpoint: str, payload: dict) -> bool:
        """
        POST *payload* (as JSON) to ``{hec_url}{endpoint}``.

        Returns ``True`` on an HTTP 2xx response, ``False`` on every other
        outcome. Errors are logged but never raised, so callers can continue
        safely.
        """
        url = f"{self.hec_url}{endpoint}"
        try:
            resp = self.session.post(
                url,
                json=payload,
                verify=self.verify_ssl,
                timeout=5,
            )
            if 200 <= resp.status_code < 300:
                return True

            logger.error(
                "[splunk_hec] HEC rejected payload: HTTP %d — %s",
                resp.status_code,
                resp.text[:300],
            )
            return False

        except requests.exceptions.ConnectionError as exc:
            logger.error(
                "[splunk_hec] Connection error — Splunk is unreachable at %s: %s",
                self.hec_url,
                exc,
            )
        except requests.exceptions.Timeout:
            logger.error(
                "[splunk_hec] Request to %s timed out after 5 s", self.hec_url
            )
        except requests.exceptions.RequestException as exc:
            logger.error("[splunk_hec] Unexpected error sending to Splunk: %s", exc)

        return False

    @staticmethod
    def _epoch(raw: dict) -> float:
        """
        Return a Unix epoch timestamp (float) for use in the HEC ``time`` field.

        Tries to parse ``raw['TimeCreated']`` (ISO-8601 string from Windows
        event logs).  Falls back to the current UTC time if the field is absent
        or cannot be parsed.

        Splunk expects epoch seconds with optional sub-second precision, e.g.
        ``1718012345.678``.
        """
        time_str = (raw or {}).get("TimeCreated")
        if time_str:
            try:
                # Strip trailing 'Z' and normalise the separator so
                # fromisoformat() accepts both "2024-01-15T09:30:00Z"
                # and "2024-01-15 09:30:00".
                normalised = str(time_str).rstrip("Z").replace("T", " ")
                dt = datetime.datetime.fromisoformat(normalised)
                # Treat as UTC if no timezone info is embedded
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt.timestamp()
            except (ValueError, AttributeError):
                pass  # fall through to utcnow

        return datetime.datetime.now(datetime.timezone.utc).timestamp()

    # ── Public API ────────────────────────────────────────────────────────────

    def send_event(self, enriched_event: dict) -> bool:
        """
        Forward a SOC Copilot enriched event to Splunk HEC.

        Accepts the dict produced by ``analyzer.analyze_events()``:

        .. code-block:: python

            {
              'index':      1,
              'event_id':   '4625',
              'event_name': 'Failed Account Logon',
              'raw':        { ...original Windows event fields... },
              'severity':   { 'score': 75, 'level': 'High', 'reason': '...' },
              'mitre':      { 'technique_id': 'T1110', 'technique_name': '...',
                              'tactic': '...', 'url': '...' },
              'analysis':   { 'summary': '...', 'threat_assessment': '...',
                              'investigation_steps': [...], 'remediation': [...] }
            }

        The HEC event body is a **flat** dict so analysts can filter with simple
        SPL without needing ``spath``:

            ``| search mitre_technique_id=T1110``
            ``| search severity=High splunk_severity>70``

        Returns ``True`` if Splunk accepted the event, ``False`` otherwise.
        """
        raw      = enriched_event.get("raw", {})
        severity = enriched_event.get("severity", {})
        mitre    = enriched_event.get("mitre", {})
        analysis = enriched_event.get("analysis", {})

        # Build a flat event body — key fields are promoted to the top level
        # so they are indexed as regular Splunk fields (no spath needed).
        event_body = {
            # ── Core identifiers ──────────────────────────────────────────
            "event_id":    enriched_event.get("event_id"),
            "event_name":  enriched_event.get("event_name"),
            "event_index": enriched_event.get("index"),

            # ── Severity — both human label and numeric score ──────────────
            # 'severity' matches the string level (Critical / High / …)
            # 'splunk_severity' is numeric so analysts can do range queries:
            #   | where splunk_severity >= 70
            "severity":        severity.get("level"),
            "splunk_severity": severity.get("score"),
            "severity_reason": severity.get("reason"),

            # ── MITRE ATT&CK — top-level for SPL filtering ─────────────────
            #   | search mitre_technique_id=T1110
            #   | search mitre_tactic="Credential Access"
            "mitre_technique_id":   mitre.get("technique_id"),
            "mitre_technique_name": mitre.get("technique_name"),
            "mitre_tactic":         mitre.get("tactic"),
            "mitre_url":            mitre.get("url"),

            # ── AI / rule-based analysis ───────────────────────────────────
            "summary":             analysis.get("summary"),
            "threat_assessment":   analysis.get("threat_assessment"),
            "investigation_steps": analysis.get("investigation_steps", []),
            "remediation":         analysis.get("remediation", []),

            # ── Promoted raw Windows event fields ─────────────────────────
            "EventID":          raw.get("EventID"),
            "TimeCreated":      raw.get("TimeCreated"),
            "SubjectUserName":  raw.get("SubjectUserName"),
            "TargetUserName":   raw.get("TargetUserName"),
            "IpAddress":        raw.get("IpAddress"),
            "WorkstationName":  raw.get("WorkstationName"),
            "LogonType":        raw.get("LogonType"),
            "NewProcessName":   raw.get("NewProcessName"),
            "CommandLine":      raw.get("CommandLine"),
            "ComputerName":     raw.get("ComputerName"),

            # ── Full raw event preserved for deep-dive searches ────────────
            "raw": raw,
        }

        # Strip None values to keep the payload tidy
        event_body = {k: v for k, v in event_body.items() if v is not None}

        hec_payload = {
            "time":       self._epoch(raw),
            "sourcetype": "soc_copilot",
            "index":      self.index,
            "event":      event_body,
        }

        return self._post("/services/collector/event", hec_payload)

    def send_threat_finding(self, finding: dict) -> bool:
        """
        Forward a Threat Hunt finding to Splunk HEC.

        Accepts the dicts produced by the ``/api/threat-hunt`` route:

        .. code-block:: python

            {
                'type':           'Brute Force Indicator',
                'severity':       'High',
                'description':    '...',
                'recommendation': '...',
            }

        Uses ``sourcetype=soc_copilot_threat`` so threat findings can be
        queried independently of raw events:

            ``sourcetype=soc_copilot_threat severity=High``

        Returns ``True`` if Splunk accepted the event, ``False`` otherwise.
        """
        event_body = {
            "finding_type":   finding.get("type"),
            "severity":       finding.get("severity"),
            "description":    finding.get("description"),
            "recommendation": finding.get("recommendation"),
            "source":         "soc_copilot_threat_hunt",
        }

        hec_payload = {
            "time":       datetime.datetime.now(datetime.timezone.utc).timestamp(),
            "sourcetype": "soc_copilot_threat",
            "index":      self.index,
            "event":      event_body,
        }

        return self._post("/services/collector/event", hec_payload)

    def test_connection(self) -> bool:
        """
        Verify that the Splunk HEC endpoint is reachable and accepting events.

        Sends a GET request to ``/services/collector/health``, which returns
        HTTP 200 when HEC is enabled and ready.  Returns ``True`` on success,
        ``False`` on any error or non-200 response.

        This call is safe to make at startup — it does not write any data to
        the Splunk index.
        """
        url = f"{self.hec_url}/services/collector/health"
        try:
            resp = self.session.get(
                url,
                verify=self.verify_ssl,
                timeout=5,
            )
            if resp.status_code == 200:
                logger.info(
                    "[splunk_hec] Health check OK — HEC is reachable at %s",
                    self.hec_url,
                )
                return True

            logger.warning(
                "[splunk_hec] Health check returned HTTP %d — verify token and index config",
                resp.status_code,
            )
            return False

        except requests.exceptions.ConnectionError as exc:
            logger.error(
                "[splunk_hec] Health check failed — cannot reach %s: %s",
                self.hec_url,
                exc,
            )
        except requests.exceptions.Timeout:
            logger.error(
                "[splunk_hec] Health check timed out — Splunk may be down or overloaded"
            )
        except requests.exceptions.RequestException as exc:
            logger.error("[splunk_hec] Health check error: %s", exc)

        return False
