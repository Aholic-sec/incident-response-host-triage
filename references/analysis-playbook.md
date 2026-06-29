# Host Triage Analysis Playbook

Use this playbook after a collector has produced an `IR-Logs-*` directory.

## 1. Intake

Read `manifest.json` first and record:

- OS type, hostname, collection time, script version, privilege level.
- Collector mode, collection profile, collection start/finish time, and host timezone if available.
- Encoding and code page from `manifest.json` and `system/encoding.txt`.
- Whether collection was administrator/root or standard user.
- Coverage matrix, critical gaps, command failures, missing tools, timeouts, and permission-denied results.
- Number of files collected and any empty or truncated critical logs.

State coverage limits early. For example: "Security event logs were unavailable under standard-user collection, so logon conclusions are limited."

If Windows logs appear garbled, check `system/encoding.txt`, `system/original_codepage.txt`, and `manifest.json`. Modern Windows output should be UTF-8. Legacy BAT output is UTF-8 best-effort; on older Chinese Windows, some command output may still need decoding with the original OEM code page such as CP936.

## 2. Host Profile

Build a concise profile before hunting:

- likely role: workstation, server, web server, database, build host, container host, jump host
- exposed services and listening ports
- local privileged users and remote-login groups
- high-value directories: web roots, data directories, backup paths, user profile paths
- security controls: Defender/EDR/firewall status, exclusions, disabled protections

## 3. Timeline

Create a timeline from these sources:

- account creation, group membership changes, password changes
- successful and failed logons, RDP/SSH sessions, sudo activity
- service creation, scheduled task or cron creation, systemd changes
- process execution and parent/child relationships
- recent executable/script file writes
- suspicious network connections
- security product alerts
- web access and error logs

Use absolute timestamps when available. If timestamps use local time, note the host timezone from system logs.

## 4. Evidence Cards

For each abnormal item, create an evidence card:

```text
Finding:
Severity: Critical | High | Medium | Low | Info
Confidence: Confirmed | High Suspicion | Suspicious | Needs Context | No Finding
Threat Category:
Evidence Source:
Evidence Snippet:
Why It Matters:
Related Evidence:
MITRE ATT&CK:
False-Positive Checks:
Recommended Verification:
```

Do not merge unrelated weak signals. Correlate only when time, account, process, path, network peer, or persistence mechanism reasonably connects them.

## 5. Correlation Rules

Raise severity when two or more evidence classes align:

- Process plus network: suspicious binary path and external C2/mining connection.
- File plus persistence: recent executable or script referenced by service, task, cron, Run key, systemd, or shell startup file.
- Account plus logon: newly created privileged user followed by RDP/SSH/sudo activity.
- Web access plus dropped file: upload request followed by new script in web root.
- Security tamper plus malware: Defender exclusion, disabled firewall, or stopped EDR near suspicious execution.
- Credential access plus lateral movement: LSASS dump/Mimikatz/LaZagne/procdump plus remote service/RDP/SSH evidence.
- Ransomware chain: backup deletion or shadow copy deletion plus mass file changes and ransom note.

## 6. Severity Guidance

- `Critical`: active malware, ransomware, confirmed credential theft, confirmed persistence with C2, or evidence of lateral movement from a privileged account.
- `High`: strong malicious tool or persistence evidence, suspicious external tunnel, miner, webshell, or new privileged account with remote login.
- `Medium`: suspicious binary/script in high-risk path, unusual service/task/cron, abnormal failed login volume, or suspicious admin tool needing context.
- `Low`: weak anomaly, stale artifact, incomplete evidence, or hardening issue.
- `Info`: inventory, coverage limits, and benign context.

## 7. Confidence Guidance

- `Confirmed`: independent evidence sources form a complete chain.
- `High Suspicion`: strong malware traits exist, but one link is missing.
- `Suspicious`: abnormal signal that could be legitimate.
- `Needs Context`: likely business or admin activity; ask asset owner.
- `No Finding`: checked available logs and found no clear issue.

## 8. Required Report Discipline

- Cite source log filenames for every finding.
- Quote only short snippets needed to prove the point.
- Separate "Observed Evidence" from "Assessment" and "Recommendation".
- Include false-positive considerations.
- Do not claim eradication unless cleanup evidence exists.
- Do not state attribution unless the supplied evidence supports it.
- Redact complete secrets, tokens, cookies, private keys, passwords, and API keys from reports.
- Treat dual-use tools as suspicious only when path, timing, account, command line, persistence, or network behavior supports abuse.
- Map confirmed and high-suspicion findings to MITRE ATT&CK where possible.

## 9. Structured Findings JSON

When the operator requests structured output, or when findings will feed case tracking, emit `findings.json` alongside the Markdown report:

```json
{
  "finding_id": "F-001",
  "title": "Suspicious service launches binary from user-writable path",
  "severity": "High",
  "confidence": "High Suspicion",
  "threat_category": "RAT or backdoor",
  "mitre_attack": [
    {"tactic": "Persistence", "technique": "T1543.003 Windows Service"}
  ],
  "evidence": [
    {"file": "persistence/services.txt", "snippet": "...", "timestamp": "..."}
  ],
  "false_positive_checks": ["Confirm whether the service is approved by the asset owner."],
  "recommended_next_steps": ["Preserve the binary and hash before cleanup."]
}
```

## 10. Follow-Up Recommendations

Recommend follow-up based on evidence:

- collect full memory image only when active compromise or credential theft is suspected
- preserve suspicious binaries and scripts with hashes before cleanup
- isolate host when confirmed C2, ransomware, or lateral movement is present
- rotate credentials when credential theft or privileged session compromise is suspected
- review adjacent hosts when lateral movement indicators appear
- preserve web logs and application logs when webshell or upload abuse is suspected
