# SOC Daily Queue – Mock Shift 01
**Date:** October 7, 2025  
**Analyst:** Jacob Taylor  
**Environment:** Splunk Enterprise (Mock Dataset)  

---

## Shift Overview
Monitored and triaged multiple alerts from endpoint, authentication, email, and network data sources within Splunk.  
Performed verification against threat intelligence feeds and local host logs to determine validity and impact.  
Two incidents escalated to Tier-2 for further forensic analysis.  

---

## Alert Queue Summary
| Time  | Alert Name | Source | Severity | Verdict | Notes |
|-------|-------------|---------|-----------|----------|--------|
| 08:45 | [Malware Detected – Mock](./triage_reports/malware_detected.md) | Endpoint | High | False Positive | Legitimate vendor patch quarantined by Defender |
| 09:30 | [SSH Brute Force – Mock](./triage_reports/ssh_bruteforce.md) | Authentication | Medium | True Negative | User failed logins after password reset via VPN |
| 10:50 | [Phishing Campaign – Mock](./triage_reports/phishing_campaign.md) | Email | High | True Positive | Confirmed credential-harvesting attempt |
| 13:00 | [Beaconing Behavior – Mock](./triage_reports/beaconing_behavior.md) | Network | High | True Positive | Repetitive HTTPS beacons to known C2 IP contained |

---

## Analyst Notes

### 08:45 – Malware Detected – Mock
- Reviewed Defender event logs and file hash `abcd1234efgh5678`.  
- Hash clean on VirusTotal; file matched internal vendor installer.  
- No process execution or persistence observed.  
- **Verdict:** False Positive — benign internal installer quarantined heuristically.  
- **Action:** Added hash to temporary allowlist; documented detection tuning request.

---

### 09:30 – SSH Brute Force – Mock
- Detected 40 failed SSH attempts from `203.0.113.25` within 10 minutes.  
- Cross-checked with authentication logs and VPN connection records.  
- Source IP resolved to internal VPN gateway; user `jsmith` recently reset password.  
- **Verdict:** True Negative — legitimate user behavior after password change.  
- **Action:** No containment required; updated runbook notes to include VPN context check.

---

### 10:50 – Phishing Campaign – Mock
- Multiple identical messages detected with subject `payroll_update.zip`.  
- Sender domain `hr-payroll-update.com` verified as newly registered and non-legitimate.  
- Attachment hash flagged malicious across several antivirus engines.  
- One user confirmed opening the ZIP before quarantine.  
- **Verdict:** True Positive — confirmed phishing attempt.  
- **Actions:** Blocked domain in mail gateway, quarantined all matching messages, initiated forced password resets, and escalated to Tier-2 for impact review.

---

### 13:00 – Beaconing Behavior – Mock
- Host `ENG-WIN10-02` exhibited recurring outbound connections to `203.0.113.45` every 60 seconds on port 443.  
- IP correlated with known C2 infrastructure in threat intel feed.  
- Sysmon logs showed repeated `curl` executions without user context.  
- **Verdict:** True Positive — active beaconing behavior confirmed.  
- **Actions:** Isolated host via UFW, blocked IP at firewall, escalated to Tier-2 for malware and memory analysis.

---

## Metrics
| Metric | Value |
|--------|--------|
| Total Alerts Reviewed | 4 |
| True Positives | 2 |
| False Positives | 1 |
| True Negatives | 1 |
| Escalations | 2 |
| Mean Time to Detect (MTTD) | ~15 minutes |
| Mean Time to Respond (MTTR) | ~40 minutes |

---

## End of Shift Summary
Shift completed with no active compromises remaining.  
Two true-positive incidents (phishing and beaconing) escalated to Tier-2 for deeper analysis.  
False and true-negative events documented with tuning recommendations.  
All endpoints and accounts verified secure prior to shift closure.

---

### Disclaimer
This project uses mock data and simulated alerts for educational purposes.  
Timestamps in screenshots may not align exactly with the written timeline due to lab replays and staged event generation.  
All artifacts were produced within a controlled environment to replicate authentic SOC analysis workflows.