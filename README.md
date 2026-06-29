# Incident Response Host Triage

Cross-agent host incident response triage skill and read-only collectors for Windows and Linux.

This repository is designed for two use cases:

1. Install the skill into an AI agent environment from a GitHub URL.
2. Download the collector scripts, run them on a target host, and analyze the generated `IR-Logs-*` directory with an AI agent.

## Safety

The collectors are read-only. They do not delete files, kill processes, quarantine samples, clear logs, change configuration, or upload data.

Generated `IR-Logs-*` directories may contain sensitive host information, including usernames, hostnames, command history, environment variables, tokens, cookies, API keys, SSH keys, cloud credentials, and application paths. Do not commit or publish collected logs. Redact secrets in reports and share only the minimum evidence required.

## Repository Layout

- `SKILL.md`: Codex skill entrypoint.
- `AGENT_GUIDE.md`: Cross-agent usage guide for other AI agents.
- `scripts/windows-ir-collector.bat`: Single Windows entrypoint. It auto-detects modern PowerShell support and falls back to built-in BAT commands on legacy systems.
- `scripts/windows-ir-collector.ps1`: Modern Windows collector used automatically by the BAT entrypoint when available.
- `scripts/linux-ir-collector.sh`: Linux collector for common Ubuntu, Debian, CentOS, RHEL-like systems.
- `references/analysis-playbook.md`: Analysis workflow and evidence standards.
- `references/malware-coverage.md`: Threat coverage and detection heuristics.
- `references/report-template.md`: Markdown report template.
- `schemas/ir-log-manifest.schema.json`: Manifest schema.
- `schemas/ir-findings.schema.json`: Optional structured findings schema for `findings.json`.

## Windows Collection

Copy these files to the target host in the same directory:

```text
windows-ir-collector.bat
windows-ir-collector.ps1
```

Run `windows-ir-collector.bat` as Administrator.

For old systems where PowerShell is unavailable or too old, `windows-ir-collector.bat` automatically uses its built-in BAT fallback mode. If only the BAT file is copied, fallback mode still runs with reduced coverage.

The script creates:

```text
IR-Logs-Windows-HOSTNAME-TIMESTAMP\
```

Modern PowerShell mode records command status, command timing, coverage, critical gaps, file hashes, and a sensitive-data warning in `manifest.json`. Legacy BAT fallback mode records reduced coverage and marks hash limitations explicitly.

When finished, the console displays a clear completion banner and waits for a key press.

For automation without pause:

```bat
windows-ir-collector.bat --no-pause
```

## Linux Collection

Copy `scripts/linux-ir-collector.sh` to the target host:

```sh
chmod +x linux-ir-collector.sh
./linux-ir-collector.sh
```

Run as root when possible for fuller coverage. Standard-user execution still works, but some logs and firewall/account details may be unavailable.

The script creates:

```text
IR-Logs-Linux-HOSTNAME-TIMESTAMP/
```

The Linux collector records command status, command timing, coverage, critical gaps, file hashes, audit/container/cloud credential metadata where available, and a sensitive-data warning in `manifest.json`.

## AI Analysis Prompt

After collection, provide the generated `IR-Logs-*` directory to an AI agent and use a prompt like:

```text
Use the incident-response-host-triage skill to analyze this IR-Logs directory.
Read manifest.json first, follow AGENT_GUIDE.md and references/analysis-playbook.md,
then generate an evidence-backed incident response report in Chinese.
Every finding must cite the original log file.
```

For automation or case tracking, ask the agent to emit both a Markdown report and `findings.json` with severity, confidence, MITRE ATT&CK mapping, evidence, false-positive checks, and next steps.

## Encoding Notes

Windows collectors write UTF-8 where possible.

- Modern PowerShell mode records `encoding=utf-8` and `codepage=65001`.
- Legacy BAT mode records `encoding=utf-8-best-effort`, `system/original_codepage.txt`, and `system/active_codepage.txt`.

If old localized Windows output still appears garbled, decode affected logs using the original OEM code page recorded by the collector, commonly CP936 on Simplified Chinese Windows.
