#!/bin/bash

# ==========================================================
#  Linux Threat Hunting Script
#  (Dirty gets more info not relevant for this hunt but future may help)
# ==========================================================

OUTDIR="/home/champuser/Desktop/hunt_results_full"
mkdir -p "$OUTDIR"

echo "[+] Starting Threat Hunting..."
echo "[+] Results saved to $OUTDIR"
echo ""

# ----------------------------------------------------------
echo "===== List Running Processes ====="
# ----------------------------------------------------------
echo "[*] Running: ps -ef"
ps -ef > "$OUTDIR/$(hostname)-processes.txt"

echo "[*] Running: ps aux"
ps aux > "$OUTDIR/$(hostname)-processes-aux.txt"

echo "[*] Running: ps aux | grep suspicious"
ps aux | grep -E 'suspicious_updater|data_collector' > "$OUTDIR/$(hostname)-suspicious-procs.txt"

# ----------------------------------------------------------
echo "===== List Network Sockets ====="
# ----------------------------------------------------------
echo "[*] Running: netstat -plunt"
netstat -plunt > "$OUTDIR/$(hostname)-netstat.txt" 2>/dev/null

echo "[*] Running: ss -tulnp"
ss -tulnp > "$OUTDIR/$(hostname)-ss.txt"

echo "[*] Running: sudo lsof -i :4444"
sudo lsof -i :4444 > "$OUTDIR/$(hostname)-port4444.txt"

echo "[*] Running: sudo lsof -i :8888"
sudo lsof -i :8888 > "$OUTDIR/$(hostname)-port8888.txt"

echo "[*] Running: sudo lsof -i :31337"
sudo lsof -i :31337 > "$OUTDIR/$(hostname)-port31337.txt"

# ----------------------------------------------------------
echo "===== User Enumeration ====="
# ----------------------------------------------------------
echo "[*] Running: cat /etc/passwd"
cat /etc/passwd > "$OUTDIR/$(hostname)-passwd.txt"

echo "[*] Running: grep -v '/nologin' /etc/passwd"
grep -v '/nologin\|/false' /etc/passwd > "$OUTDIR/$(hostname)-valid-users.txt"

echo "[*] Running: id svc_backup (will fail if missing)"
id svc_backup > "$OUTDIR/id-svc_backup.txt" 2>/dev/null

echo "[*] Running: id admin_temp"
id admin_temp > "$OUTDIR/id-admin_temp.txt" 2>/dev/null

echo "[*] Running: id webadmin"
id webadmin > "$OUTDIR/id-webadmin.txt" 2>/dev/null

# ----------------------------------------------------------
echo "===== Group Enumeration ====="
# ----------------------------------------------------------
echo "[*] Running: cat /etc/group"
cat /etc/group > "$OUTDIR/$(hostname)-groups.txt"

echo "[*] Running: getent group remoteadmins"
getent group remoteadmins > "$OUTDIR/getent-remoteadmins.txt"

echo "[*] Running: getent group backupoperators_custom"
getent group backupoperators_custom > "$OUTDIR/getent-backupoperators_custom.txt"

echo "[*] Running: getent group sudo"
getent group sudo > "$OUTDIR/getent-sudo.txt"

# ----------------------------------------------------------
echo "===== Cron Enumeration ====="
# ----------------------------------------------------------
echo "[*] Running: sudo crontab -l"
sudo crontab -l > "$OUTDIR/root-crontab.txt" 2>/dev/null

echo "[*] Running: ls -la /etc/cron.*"
ls -la /etc/cron.* > "$OUTDIR/cron-dirs.txt"

echo "[*] Running: cat /etc/crontab"
cat /etc/crontab > "$OUTDIR/etc-crontab.txt"

# ----------------------------------------------------------
echo "===== Service Enumeration ====="
# ----------------------------------------------------------
echo "[*] Running: systemctl list-units --type=service"
systemctl list-units --type=service > "$OUTDIR/services.txt"

echo "[*] Running: systemctl status system-update-custom"
systemctl status system-update-custom > "$OUTDIR/service-system-update-custom.txt" 2>/dev/null

echo "[*] Running: systemctl cat system-update-custom"
systemctl cat system-update-custom > "$OUTDIR/service-cat-system-update-custom.txt" 2>/dev/null

# ----------------------------------------------------------
echo "===== SUID Hunting ====="
# ----------------------------------------------------------
echo "[*] Running: sudo find / -perm -4000 -type f"
sudo find / -perm -4000 -type f 2>/dev/null > "$OUTDIR/suid.txt"

echo "[*] Running: ls -la /tmp/find_backup"
ls -la /tmp/find_backup > "$OUTDIR/tmp-find_backup.txt" 2>/dev/null

# ----------------------------------------------------------
echo "===== World-Writable Files ====="
# ----------------------------------------------------------
echo "[*] Running: sudo find /tmp /opt -type f -perm 0777"
sudo find /tmp /opt -type f -perm 0777 > "$OUTDIR/world-writable.txt" 2>/dev/null

echo "[*] Running: ls -la /tmp/system_config.txt"
ls -la /tmp/system_config.txt > "$OUTDIR/tmp-system_config.txt" 2>/dev/null

echo "[*] Running: ls -la /opt/credentials.txt"
ls -la /opt/credentials.txt > "$OUTDIR/opt-credentials.txt" 2>/dev/null

# ----------------------------------------------------------
echo "===== Bash History ====="
# ----------------------------------------------------------
echo "[*] Running: sudo cat /root/.bash_history"
sudo cat /root/.bash_history > "$OUTDIR/root-bash-history.txt" 2>/dev/null

echo "[*] Running: reading user bash_history files"
for user_home in /home/*; do
    if [ -f "$user_home/.bash_history" ]; then
        echo "---- History for $(basename "$user_home") ----" >> "$OUTDIR/user-bash-history.txt"
        cat "$user_home/.bash_history" >> "$OUTDIR/user-bash-history.txt"
    fi
done

# ----------------------------------------------------------
echo "===== Directory Scans ====="
# ----------------------------------------------------------
echo "[*] Running: ls -la /tmp"
ls -la /tmp > "$OUTDIR/tmp-list.txt"

echo "[*] Running: ls -la /opt"
ls -la /opt > "$OUTDIR/opt-list.txt"

echo "[*] Running: ls -la /var/tmp"
ls -la /var/tmp > "$OUTDIR/var-tmp-list.txt"

# ----------------------------------------------------------
echo "[+] Script Completed."
echo "[+] Check results in: $OUTDIR"
# ----------------------------------------------------------
