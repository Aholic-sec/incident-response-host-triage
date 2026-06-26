# Cross-Agent Incident Response Host Triage Guide

This package can be used by any AI agent. Codex reads `SKILL.md`; other agents should read this file first.

## Purpose

Collect read-only evidence from Windows or Linux hosts, analyze the generated logs, and produce an evidence-backed incident response report. The package focuses on host triage for malware, miners, RATs, ransomware, webshell activity, credential theft, persistence, tunneling tools, lateral movement, rootkit indicators, and abnormal business-risk behaviors.

## Directory Map

- `scripts/windows-ir-collector.bat`: Single Windows collection entrypoint. It auto-detects whether modern PowerShell collection is available; otherwise it falls back to built-in BAT commands for Windows Server 2003/2008 class systems.
- `scripts/windows-ir-collector.ps1`: Companion modern collector used automatically by the BAT entrypoint on newer Windows systems.
- `scripts/linux-ir-collector.sh`: Linux collection entrypoint.
- `references/analysis-playbook.md`: Required analysis workflow and confidence model.
- `references/malware-coverage.md`: Threat categories and detection heuristics.
- `references/report-template.md`: Markdown report template.
- `schemas/ir-log-manifest.schema.json`: Expected shape of `manifest.json`.

## Collection Commands

Windows:

```bat
windows-ir-collector.bat
```

Linux:

```sh
chmod +x linux-ir-collector.sh
./linux-ir-collector.sh
```

Run as administrator/root when possible for fuller coverage. If elevated permissions are not available, run anyway and record the limitation.

## Safety Boundary

The bundled scripts are designed for read-only collection. They should not delete, modify, quarantine, kill, block, upload, or clean anything. If an agent proposes containment actions, it must separate them as recommendations and ask for explicit operator approval before execution.

## Required Analysis Flow

1. Read `manifest.json`.
2. Record OS, hostname, collection time, script version, privilege level, encoding/codepage, log count, and command failures.
3. Build a host profile: role, exposed services, accounts, privileged users, main runtime paths, network posture.
4. Build a timeline from logon events, account changes, process/service/task creation, file changes, network connections, and security alerts.
5. Create evidence cards for every abnormal item:
   - finding title
   - source file
   - evidence snippet
   - why it is abnormal
   - severity
   - confidence
   - likely threat category
   - next verification step
6. Correlate evidence into one or more incident chains.
7. Produce a Markdown report using `references/report-template.md`.

## Confidence Labels

- `Confirmed`: multiple independent evidence sources support malicious or unauthorized activity.
- `High Suspicion`: strong malicious traits exist, but one key link is missing.
- `Suspicious`: abnormal and worth investigation, but may be legitimate.
- `Needs Context`: likely needs business-owner confirmation.
- `No Finding`: no clear abnormality in available logs.

## Evidence Requirements

Do not state a host is infected without evidence. Every finding must cite at least one log file. Strong findings should cite two or more evidence types, such as process plus network, task plus file, account plus logon, or web access plus dropped file.

## Encoding Notes

Windows collectors write UTF-8 where possible. Modern PowerShell mode sets code page 65001 and records `encoding=utf-8`. Legacy BAT mode records `encoding=utf-8-best-effort` plus `system/original_codepage.txt`; if localized command output appears garbled, retry decoding affected logs with the original OEM code page, commonly CP936 on Simplified Chinese Windows.

## Report Language

Use the user's requested language. If not specified and the operator writes in Chinese, output a Chinese report.
