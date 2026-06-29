---
name: incident-response-host-triage
description: Cross-agent incident response host triage for Windows and Linux. Use when collecting read-only host evidence, reviewing logs produced by bundled IR collector scripts, analyzing suspicious processes, persistence, accounts, network connections, malware, webshells, miners, ransomware, RATs, Silver Fox-style social engineering malware, credential theft, rootkits, lateral movement, tunneling tools, or when generating evidence-backed incident response reports from host triage artifacts.
---

# Incident Response Host Triage

## Core Rule

Preserve evidence. Do not delete files, kill processes, quarantine samples, clear logs, modify configuration, or upload data unless the user explicitly asks for containment or cleanup.

## Quick Start

Use the bundled collector script for the target OS, then analyze the generated log directory:

- Windows: `scripts/windows-ir-collector.bat` auto-detects modern PowerShell support and falls back to built-in BAT commands on Windows Server 2003/2008 class systems.
- Linux: `scripts/linux-ir-collector.sh`

Each collector creates an `IR-Logs-*` directory with `manifest.json`, command output files, `command-index.tsv`, and error logs. Treat `manifest.json` as the entrypoint.

## Workflow

1. Confirm whether the user wants collection, analysis, or report writing.
2. If collecting evidence, provide the correct script and execution command for the target OS.
3. If analyzing logs, read `manifest.json` first, then follow `references/analysis-playbook.md`.
4. For malware classification and hunting coverage, use `references/malware-coverage.md`.
5. For the final deliverable, use `references/report-template.md`.
6. Cite original log filenames and exact evidence snippets or line references wherever possible.

## Task Routing

- `collection`: provide collector usage, privilege guidance, and sensitive-data handling notes.
- `analysis`: inspect `manifest.json`, `coverage`, `critical_gaps`, `command_failures`, and source logs before making findings.
- `report`: generate an evidence-backed Markdown report and, when useful, a structured `findings.json`.
- `containment-plan`: recommend containment only as a plan unless the user explicitly authorizes action.
- `cleanup`: require explicit operator approval and evidence preservation steps before deletion, quarantine, account disabling, or configuration changes.

## Cross-Agent Use

This skill is not Codex-only. For Claude, Gemini, local LLMs, Dify, Coze, Flowise, or other agents, start from `AGENT_GUIDE.md`. The guide defines the same workflow without relying on Codex skill mechanics.

## Analysis Standards

- Separate confirmed findings from suspicious items and business-context questions.
- Build a timeline before writing conclusions.
- Correlate weak signals across process, network, account, persistence, file, and event logs.
- Prefer behavior and evidence chains over single IOC matches.
- Mark missing logs, permission limitations, and command failures as coverage gaps.
- Keep remediation recommendations separate from observed evidence.
- Do not declare infection, attribution, or eradication from a single filename, IOC, or weak signal.
- Treat dual-use tools as suspicious only when timing, path, account, command line, persistence, or network behavior supports abuse.
- Map confirmed or high-confidence findings to MITRE ATT&CK tactics and techniques where possible.
- Redact secrets in reports: do not expose complete tokens, cookies, private keys, passwords, API keys, or long credential material.

## Report Output

Default to Markdown. Use Chinese for reports when the user writes in Chinese or asks for Chinese output. Include:

- triage scope and collection integrity
- key conclusions and severity
- host profile
- findings table
- detailed evidence analysis
- attack or infection timeline
- malware/threat family assessment
- impact assessment
- containment, eradication, recovery, and hardening recommendations
- appendix with source log references

When structured output is requested or downstream automation is likely, also provide `findings.json` with finding id, title, severity, confidence, ATT&CK mapping, evidence sources, false-positive checks, and next steps.
