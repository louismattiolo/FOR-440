#!/bin/bash

OUT="/home/$SUDO_USER/Desktop/hunt_results_clean"
mkdir -p "$OUT"

echo "[+] Running simplified threat hunt..."
echo "[+] Output saved to: $OUT"
echo ""

#############################
# 01 - SUSPICIOUS USERS
#############################
echo "=== Suspicious Users ===" | tee "$OUT/01-users.txt"
grep -E 'svc_backup|admin_temp|webadmin' /etc/passwd | tee -a "$OUT/01-users.txt"
echo "" | tee -a "$OUT/01-users.txt"
echo "[*] User details:" | tee -a "$OUT/01-users.txt"
id svc_backup 2>/dev/null | tee -a "$OUT/01-users.txt"
id admin_temp 2>/dev/null | tee -a "$OUT/01-users.txt"
id webadmin 2>/dev/null | tee -a "$OUT/01-users.txt"

echo ""

#############################
# 02 - SUSPICIOUS GROUPS
#############################
echo "=== Suspicious Groups ===" | tee "$OUT/02-groups.txt"
grep -E 'remoteadmins|backupoperators_custom' /etc/group | tee -a "$OUT/02-groups.txt"
echo "" | tee -a "$OUT/02-groups.txt"
echo "[*] Sudo group membership:" | tee -a "$OUT/02-groups.txt"
getent group sudo | tee -a "$OUT/02-groups.txt"

echo ""

#############################
# 03 - BAD NETWORK PORTS
#############################
echo "=== Suspicious Ports and Listeners ===" | tee "$OUT/03-network.txt"
sudo netstat -tulnp | grep -E '4444|8888|31337' | tee -a "$OUT/03-network.txt"
echo "" | tee -a "$OUT/03-network.txt"

echo "[*] Processes using these ports:" | tee -a "$OUT/03-network.txt"
sudo lsof -i :4444 | tee -a "$OUT/03-network.txt"
sudo lsof -i :8888 | tee -a "$OUT/03-network.txt"
sudo lsof -i :31337 | tee -a "$OUT/03-network.txt"

echo ""

#############################
# 04 - SUSPICIOUS PROCESSES
#############################
echo "=== Suspicious Processes ===" | tee "$OUT/04-processes.txt"
ps aux | grep -E 'suspicious_updater|data_collector' | grep -v grep | tee -a "$OUT/04-processes.txt"

echo ""

#############################
# 05 - MALICIOUS SERVICE
#############################
echo "=== Malicious Service ===" | tee "$OUT/05-services.txt"
systemctl status system-update-custom 2>/dev/null | tee -a "$OUT/05-services.txt"
echo "" | tee -a "$OUT/05-services.txt"
systemctl cat system-update-custom 2>/dev/null | tee -a "$OUT/05-services.txt"

echo ""

#############################
# 06 - MALICIOUS CRON JOBS
#############################
echo "=== Malicious Cron Jobs ===" | tee "$OUT/06-cron.txt"
sudo crontab -l | grep -E 'system_maintenance|data_backup' | tee -a "$OUT/06-cron.txt"

echo ""

#############################
# 07 - SUSPICIOUS FILES
#############################
echo "=== Suspicious Files ===" | tee "$OUT/07-files.txt"

echo "[*] /tmp/system_config.txt:" | tee -a "$OUT/07-files.txt"
ls -la /tmp/system_config.txt 2>/dev/null | tee -a "$OUT/07-files.txt"

echo "" | tee -a "$OUT/07-files.txt"
echo "[*] /opt/credentials.txt:" | tee -a "$OUT/07-files.txt"
ls -la /opt/credentials.txt 2>/dev/null | tee -a "$OUT/07-files.txt"

echo ""

#############################
# 08 - SUID BACKDOOR
#############################
echo "=== SUID Backdoor ===" | tee "$OUT/08-suid.txt"
ls -la /tmp/find_backup 2>/dev/null | tee -a "$OUT/08-suid.txt"

echo ""
echo "[+] Done."
