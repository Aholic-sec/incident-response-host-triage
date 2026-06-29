#!/usr/bin/env sh
set -u

SCRIPT_VERSION="2026.06.29"
COLLECTION_STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOST_SAFE="$(hostname 2>/dev/null | tr -c 'A-Za-z0-9_.-' '_' | sed 's/_$//')"
[ -n "$HOST_SAFE" ] || HOST_SAFE="UNKNOWNHOST"
TS="$(date -u +%Y%m%d-%H%M%S)"
OUTDIR="${PWD}/IR-Logs-Linux-${HOST_SAFE}-${TS}"

mkdir -p "$OUTDIR"/system "$OUTDIR"/accounts "$OUTDIR"/process "$OUTDIR"/network "$OUTDIR"/persistence "$OUTDIR"/events "$OUTDIR"/files "$OUTDIR"/security "$OUTDIR"/errors
printf 'file\tcommand\texit_code\tstatus\tstarted_utc\tfinished_utc\tduration_ms\n' > "$OUTDIR/command-index.tsv"
: > "$OUTDIR/errors/command-failures.tsv"

log() { printf '%s\n' "$*"; }

run_cmd() {
  rel="$1"; shift
  dest="$OUTDIR/$rel"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  started_s="$(date -u +%s)"
  printf '[%s] $ %s\n' "$started" "$*" > "$dest"
  if command -v "$1" >/dev/null 2>&1; then
    "$@" >> "$dest" 2>&1
    rc=$?
  else
    printf 'MISSING_COMMAND: %s\n' "$1" >> "$dest"
    rc=127
  fi
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  finished_s="$(date -u +%s)"
  duration_ms=$(( (finished_s - started_s) * 1000 ))
  if [ "$rc" -eq 0 ]; then status="ok"; elif [ "$rc" -eq 127 ]; then status="missing_tool"; elif [ "$rc" -eq 124 ]; then status="timeout"; elif grep -qiE 'permission denied|operation not permitted' "$dest"; then status="permission_denied"; else status="failed"; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$rel" "$*" "$rc" "$status" "$started" "$finished" "$duration_ms" >> "$OUTDIR/command-index.tsv"
  [ "$rc" -eq 0 ] || printf '%s\t%s\t%s\n' "$rel" "$*" "$rc" >> "$OUTDIR/errors/command-failures.tsv"
}

run_shell() {
  rel="$1"; desc="$2"; shift 2
  dest="$OUTDIR/$rel"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  started_s="$(date -u +%s)"
  printf '[%s] $ %s\n' "$started" "$desc" > "$dest"
  if command -v timeout >/dev/null 2>&1; then
    timeout 60 sh -c "$*" >> "$dest" 2>&1
  else
    sh -c "$*" >> "$dest" 2>&1
  fi
  rc=$?
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  finished_s="$(date -u +%s)"
  duration_ms=$(( (finished_s - started_s) * 1000 ))
  if [ "$rc" -eq 0 ]; then status="ok"; elif [ "$rc" -eq 127 ]; then status="missing_tool"; elif [ "$rc" -eq 124 ]; then status="timeout"; elif grep -qiE 'permission denied|operation not permitted' "$dest"; then status="permission_denied"; else status="failed"; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$rel" "$desc" "$rc" "$status" "$started" "$finished" "$duration_ms" >> "$OUTDIR/command-index.tsv"
  [ "$rc" -eq 0 ] || printf '%s\t%s\t%s\n' "$rel" "$desc" "$rc" >> "$OUTDIR/errors/command-failures.tsv"
}

log "[*] Linux IR collector $SCRIPT_VERSION"
log "[*] Output: $OUTDIR"
log "[*] Read-only collection. No cleanup, kill, quarantine, upload, or configuration change is performed."

run_cmd "system/uname.txt" uname -a
run_cmd "system/hostname.txt" hostname
run_cmd "system/uptime.txt" uptime
run_cmd "system/date.txt" date -u
run_cmd "system/id.txt" id
run_cmd "system/env.txt" env
run_shell "system/os_release.txt" "cat /etc/os-release and release files" "cat /etc/os-release 2>/dev/null; ls -l /etc/*release 2>/dev/null; cat /etc/*release 2>/dev/null"
run_cmd "system/df.txt" df -hT
run_cmd "system/mount.txt" mount
run_cmd "system/lsblk.txt" lsblk -a
run_shell "system/package_managers.txt" "package manager recent history" "ls -l /var/log/apt /var/log/yum.log /var/log/dnf.log 2>/dev/null; tail -n 300 /var/log/apt/history.log /var/log/yum.log /var/log/dnf.log 2>/dev/null; true"

run_shell "accounts/passwd_shadow_groups.txt" "account files metadata and safe account listing" "ls -l /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null; awk -F: '{print \$1,\$3,\$4,\$6,\$7}' /etc/passwd 2>/dev/null; awk -F: '\$3==0{print}' /etc/passwd 2>/dev/null; getent group sudo wheel admin 2>/dev/null; true"
run_shell "accounts/sudoers.txt" "sudoers configuration" "cat /etc/sudoers 2>/dev/null; find /etc/sudoers.d -maxdepth 1 -type f -print -exec sed -n '1,220p' {} \\; 2>/dev/null"
run_cmd "accounts/who.txt" who -a
run_cmd "accounts/w.txt" w
run_cmd "accounts/last.txt" last -a -n 200
run_cmd "accounts/lastb.txt" lastb -a -n 200
run_shell "accounts/ssh_authorized_keys.txt" "authorized_keys inventory" "find /root /home -maxdepth 3 -name authorized_keys -type f -print -exec ls -l {} \\; -exec sed -n '1,80p' {} \\; 2>/dev/null; true"

run_cmd "process/ps_auxfww.txt" ps auxfww
run_cmd "process/ps_ef.txt" ps -ef
run_shell "process/top_snapshot.txt" "top batch snapshot" "top -b -n 1 2>/dev/null || ps aux --sort=-%cpu | head -80"
run_cmd "process/pstree.txt" pstree -ap
run_shell "process/deleted_running_files.txt" "processes running deleted executables or libraries" "ls -l /proc/*/exe 2>/dev/null | grep deleted; find /proc/*/fd -lname '*deleted*' -ls 2>/dev/null | head -500"
run_shell "process/process_exe_paths.txt" "process executable paths" "for p in /proc/[0-9]*; do pid=\${p##*/}; exe=\$(readlink -f \"\$p/exe\" 2>/dev/null); cmd=\$(tr '\\0' ' ' < \"\$p/cmdline\" 2>/dev/null); [ -n \"\$exe\$cmd\" ] && printf '%s\\t%s\\t%s\\n' \"\$pid\" \"\$exe\" \"\$cmd\"; done; true"

run_cmd "network/ip_addr.txt" ip addr
run_cmd "network/ip_route.txt" ip route
run_cmd "network/ss_tulpn.txt" ss -tulpn
run_cmd "network/ss_antp.txt" ss -antp
run_cmd "network/netstat_antup.txt" netstat -antup
run_cmd "network/arp.txt" arp -an
run_shell "network/resolvers_hosts_proxy.txt" "dns hosts and proxy environment" "cat /etc/resolv.conf /etc/hosts 2>/dev/null; env | grep -Ei 'http_proxy|https_proxy|all_proxy|no_proxy' || true"
run_cmd "network/iptables.txt" iptables -S
run_shell "network/nftables.txt" "nftables ruleset" "nft list ruleset 2>/dev/null; true"
run_shell "network/ufw.txt" "ufw firewall status" "ufw status verbose 2>/dev/null; true"
run_cmd "network/firewalld.txt" firewall-cmd --list-all
run_cmd "network/lsof_network.txt" lsof -nP -i

run_cmd "persistence/systemctl_units.txt" systemctl list-units --type=service --all --no-pager
run_cmd "persistence/systemctl_unit_files.txt" systemctl list-unit-files --no-pager
run_cmd "persistence/systemctl_timers.txt" systemctl list-timers --all --no-pager
run_shell "persistence/systemd_unit_files.txt" "systemd unit files and recent changes" "find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -maxdepth 2 -type f -printf '%TY-%Tm-%Td %TH:%TM %m %u %g %p\\n' 2>/dev/null | sort -r | head -1000"
run_shell "persistence/systemd_enabled_unit_contents.txt" "enabled systemd unit contents" "for u in \$(systemctl list-unit-files --state=enabled --no-legend 2>/dev/null | awk '{print \$1}' | head -200); do echo '### UNIT:' \$u; systemctl cat \$u 2>/dev/null; done; true"
run_shell "persistence/init_rc_cron.txt" "init rc cron persistence" "ls -la /etc/init.d /etc/rc.local /etc/rc*.d 2>/dev/null; cat /etc/rc.local 2>/dev/null; find /etc/cron* -maxdepth 2 -type f -print -exec sed -n '1,220p' {} \\; 2>/dev/null; true"
run_shell "persistence/user_crontabs.txt" "user crontabs" "for u in \$(cut -d: -f1 /etc/passwd 2>/dev/null); do echo '###' \$u; crontab -l -u \$u 2>/dev/null; done; true"
run_shell "persistence/shell_startup_files.txt" "shell startup files" "find /root /home -maxdepth 3 \\( -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' -o -name '.zshrc' -o -name '.ssh' \\) -print -exec ls -ld {} \\; 2>/dev/null; cat /etc/profile /etc/bash.bashrc /etc/zsh/zshrc 2>/dev/null; true"
run_shell "persistence/ld_preload.txt" "dynamic loader preload and config" "ls -l /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null; cat /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d/* 2>/dev/null; true"
run_shell "persistence/ssh_pam_config.txt" "ssh and pam configuration" "sshd -T 2>/dev/null; cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null; grep -RhsE 'pam_tally|faillock|PermitRootLogin|PasswordAuthentication|AuthorizedKeys' /etc/pam.d /etc/security 2>/dev/null; true"

run_shell "events/auth_logs_tail.txt" "auth secure syslog messages journal recent logs" "tail -n 1200 /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null; true"
run_cmd "events/journal_auth_recent.txt" journalctl --since "14 days ago" -u ssh -u sshd --no-pager
run_shell "events/journal_security_recent.txt" "journal security keywords recent" "journalctl --since '14 days ago' --no-pager 2>/dev/null | grep -Ei 'sudo|sshd|Failed password|Accepted password|Invalid user|useradd|groupadd|passwd|cron|systemd|segfault|audit|apparmor|selinux|docker|containerd|kubelet' | tail -n 3000; true"
run_shell "events/auditd_recent.txt" "auditd logs and rules" "auditctl -l 2>/dev/null; ausearch -ts recent 2>/dev/null | tail -n 1500; tail -n 1500 /var/log/audit/audit.log /var/log/audit/audit.log.* 2>/dev/null; true"
run_shell "events/sudo_ssh_grep.txt" "grep sudo ssh failed password accepted password" "grep -RhiE 'sudo|sshd|Failed password|Accepted password|Invalid user|session opened|useradd|groupadd|passwd' /var/log/auth.log* /var/log/secure* /var/log/messages* 2>/dev/null | tail -n 1500"
run_shell "events/web_access_errors_tail.txt" "web access and error logs tail" "find /var/log -maxdepth 4 -type f \\( -iname '*access*log*' -o -iname '*error*log*' \\) -print -exec tail -n 300 {} \\; 2>/dev/null; true"

run_shell "files/recent_tmp_var_home_web.txt" "recent executable/script/archive files in high-risk paths" "find /tmp /var/tmp /dev/shm /root /home /var/www /usr/local /opt -xdev -type f \\( -perm -111 -o -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.php' -o -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.aspx' -o -iname '*.elf' -o -iname '*.so' -o -iname '*.jar' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.gz' \\) -mtime -30 -printf '%TY-%Tm-%Td %TH:%TM %m %u %g %s %p\\n' 2>/dev/null | sort -r | head -2000"
run_shell "files/suspicious_names.txt" "suspicious filenames and tool names" "find /tmp /var/tmp /dev/shm /root /home /var/www /usr/local /opt -xdev -type f 2>/dev/null | grep -Eai 'xmrig|xmr|miner|kinsing|kdevtmpfsi|mimikatz|lazagne|linpeas|pspy|frpc|frps|nps|npc|ngrok|chisel|earthworm|ew_for|socat|masscan|zmap|hydra|readme|lockbit|blackcat|wannacry|shell.php|wso|c99|r57|b374k' | head -1000"
run_shell "files/suid_sgid.txt" "suid and sgid files" "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -printf '%TY-%Tm-%Td %TH:%TM %m %u %g %s %p\\n' 2>/dev/null | sort -r | head -1000"
run_shell "files/history_files.txt" "shell history snippets" "find /root /home -maxdepth 3 \\( -name '.*history' -o -name '.mysql_history' -o -name '.psql_history' \\) -type f -print -exec tail -n 200 {} \\; 2>/dev/null; true"

run_cmd "security/loaded_modules.txt" lsmod
run_shell "security/kernel_module_files.txt" "recent kernel module files" "find /lib/modules -type f -mtime -60 -printf '%TY-%Tm-%Td %TH:%TM %m %u %g %s %p\\n' 2>/dev/null | sort -r | head -1000"
run_shell "security/system_binary_integrity_clues.txt" "recent changes to common system binary dirs" "find /bin /sbin /usr/bin /usr/sbin -xdev -type f -mtime -30 -printf '%TY-%Tm-%Td %TH:%TM %m %u %g %s %p\\n' 2>/dev/null | sort -r | head -1000"
run_shell "security/container_runtime.txt" "container runtime inventory" "docker ps -a 2>/dev/null; docker images 2>/dev/null; crictl ps -a 2>/dev/null; crictl images 2>/dev/null; podman ps -a 2>/dev/null; true"
run_shell "security/container_details.txt" "container privilege mount and kubelet clues" "docker ps -aq 2>/dev/null | head -100 | xargs -r docker inspect 2>/dev/null; podman ps -aq 2>/dev/null | head -100 | xargs -r podman inspect 2>/dev/null; crictl pods 2>/dev/null; crictl ps -a 2>/dev/null; ls -la /etc/kubernetes /var/lib/kubelet /etc/cni/net.d 2>/dev/null; find /etc/kubernetes/manifests -maxdepth 1 -type f -print -exec sed -n '1,220p' {} \\; 2>/dev/null; true"
run_shell "security/cloud_dev_secret_metadata.txt" "cloud and developer credential file metadata without secret contents" "find /root /home -maxdepth 4 \\( -path '*/.aws/*' -o -path '*/.azure/*' -o -path '*/.config/gcloud/*' -o -name 'kubeconfig' -o -name 'config' -path '*/.kube/*' -o -name '.npmrc' -o -name '.pypirc' -o -path '*/.docker/config.json' -o -name '.env' \\) -type f -printf '%TY-%Tm-%Td %TH:%TM %m %u %g %s %p\\n' 2>/dev/null | sort -r | head -1000"
run_shell "security/security_controls.txt" "selinux apparmor and security control status" "getenforce 2>/dev/null; sestatus 2>/dev/null; aa-status 2>/dev/null; systemctl status auditd --no-pager 2>/dev/null; systemctl status falcon-sensor wazuh-agent ossec td-agent filebeat auditbeat --no-pager 2>/dev/null; true"

generate_manifest() {
  py=""
  if command -v python3 >/dev/null 2>&1; then py="python3"; elif command -v python >/dev/null 2>&1; then py="python"; fi
  if [ -n "$py" ]; then
    "$py" - "$OUTDIR" "$SCRIPT_VERSION" "$COLLECTION_STARTED_UTC" <<'PY'
import datetime, getpass, hashlib, json, os, socket, sys
root, version, started_utc = sys.argv[1], sys.argv[2], sys.argv[3]
files = []
for base, _, names in os.walk(root):
    for name in names:
        path = os.path.join(base, name)
        if name == "manifest.json":
            continue
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            files.append({
                "path": os.path.relpath(path, root).replace(os.sep, "/"),
                "size": os.path.getsize(path),
                "sha256": h.hexdigest(),
            })
        except OSError:
            pass
fail_path = os.path.join(root, "errors", "command-failures.tsv")
failures = []
if os.path.exists(fail_path):
    with open(fail_path, "r", errors="replace") as f:
        failures = [line.rstrip("\n") for line in f if line.strip()]
commands = []
idx_path = os.path.join(root, "command-index.tsv")
if os.path.exists(idx_path):
    with open(idx_path, "r", errors="replace") as f:
        header = f.readline()
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 7:
                file, command, exit_code, status, started, finished, duration = parts[:7]
                try:
                    exit_code = int(exit_code)
                except ValueError:
                    pass
                try:
                    duration = int(duration)
                except ValueError:
                    pass
                commands.append({
                    "file": file,
                    "command": command,
                    "exit_code": exit_code,
                    "status": status,
                    "started_utc": started,
                    "finished_utc": finished,
                    "duration_ms": duration,
                })
coverage = {}
for domain in ("system", "accounts", "process", "network", "persistence", "events", "files", "security"):
    prefix = domain + "/"
    domain_commands = [c for c in commands if str(c.get("file", "")).startswith(prefix)]
    if not domain_commands:
        coverage[domain] = "missing"
    elif any(c.get("status") in ("failed", "timeout", "permission_denied") for c in domain_commands):
        coverage[domain] = "partial"
    else:
        coverage[domain] = "complete"
critical_gaps = []
if os.geteuid() != 0:
    critical_gaps.append("Collector was not run as root; auth logs, process ownership, firewall, container, and protected path visibility may be limited.")
if any("auditd_recent" in f for f in failures):
    critical_gaps.append("auditd logs or rules were unavailable; process/account audit conclusions are limited.")
if any("container" in f for f in failures):
    critical_gaps.append("Container runtime details were unavailable or incomplete.")
finished_utc = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
manifest = {
    "schema": "ir-log-manifest/v1",
    "schema_version": 2,
    "script_name": "linux-ir-collector.sh",
    "script_version": version,
    "collector_mode": "posix-sh",
    "os_type": "linux",
    "hostname": socket.gethostname(),
    "collected_at_utc": finished_utc,
    "collection_started_utc": started_utc,
    "collection_finished_utc": finished_utc,
    "collection_profile": "standard",
    "output_directory": root,
    "privilege": "root" if os.geteuid() == 0 else "standard-user",
    "collector_user": getpass.getuser(),
    "read_only": True,
    "network_upload_performed": False,
    "sensitive_data_warning": True,
    "coverage": coverage,
    "critical_gaps": critical_gaps,
    "commands": commands,
    "command_failures": failures,
    "files": sorted(files, key=lambda x: x["path"]),
}
with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, ensure_ascii=False, indent=2)
PY
  else
    {
      printf '{\n'
      printf '  "schema": "ir-log-manifest/v1",\n'
      printf '  "schema_version": 2,\n'
      printf '  "script_name": "linux-ir-collector.sh",\n'
      printf '  "script_version": "%s",\n' "$SCRIPT_VERSION"
      printf '  "collector_mode": "posix-sh-fallback",\n'
      printf '  "os_type": "linux",\n'
      printf '  "hostname": "%s",\n' "$(hostname 2>/dev/null)"
      printf '  "collected_at_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf '  "collection_started_utc": "%s",\n' "$COLLECTION_STARTED_UTC"
      printf '  "collection_finished_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf '  "collection_profile": "standard",\n'
      printf '  "output_directory": "%s",\n' "$OUTDIR"
      if [ "$(id -u)" = "0" ]; then printf '  "privilege": "root",\n'; else printf '  "privilege": "standard-user",\n'; fi
      printf '  "read_only": true,\n'
      printf '  "network_upload_performed": false,\n'
      printf '  "sensitive_data_warning": true,\n'
      printf '  "coverage": {"system":"partial","accounts":"partial","process":"partial","network":"partial","persistence":"partial","events":"partial","files":"partial","security":"partial"},\n'
      printf '  "critical_gaps": ["Python unavailable; manifest file hashes and command records are reduced."],\n'
      printf '  "command_failures_file": "errors/command-failures.tsv",\n'
      printf '  "files_index_file": "command-index.tsv"\n'
      printf '}\n'
    } > "$OUTDIR/manifest.json"
  fi
}

generate_manifest
log "[*] Done. Review $OUTDIR/manifest.json"
