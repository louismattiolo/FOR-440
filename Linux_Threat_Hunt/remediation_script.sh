#!/bin/bash

echo "[+] Starting full remediation..."

###########################################
# 1. Remove Malicious Users
###########################################
echo "[*] Removing malicious users..."

for user in svc_backup admin_temp webadmin; do
    if id "$user" &>/dev/null; then
        sudo userdel -r "$user"
        echo "[-] Removed user: $user"
    else
        echo "[OK] User $user already removed."
    fi
done

###########################################
# 2. Remove Malicious Groups
###########################################
echo "[*] Removing malicious groups..."

for grp in remoteadmins backupoperators_custom; do
    if getent group "$grp" &>/dev/null; then
        sudo groupdel "$grp"
        echo "[-] Removed group: $grp"
    else
        echo "[OK] Group $grp already removed."
    fi
done

###########################################
# 3. Kill Netcat Backdoor Listeners
###########################################
echo "[*] Killing netcat backdoors on ports 4444, 8888, 31337..."

sudo fuser -k 4444/tcp 2>/dev/null
sudo fuser -k 8888/tcp 2>/dev/null
sudo fuser -k 31337/tcp 2>/dev/null

sudo pkill -9 nc 2>/dev/null

echo "[*] All netcat listeners terminated."

###########################################
# 4. Kill Malicious Processes
###########################################
echo "[*] Killing malicious processes..."

sudo pkill -9 -f suspicious_updater.sh 2>/dev/null
sudo pkill -9 -f data_collector.sh 2>/dev/null

###########################################
# 5. Remove Malicious Directories
###########################################
echo "[*] Removing malicious directories..."

sudo rm -rf /opt/updater/
sudo rm -rf /opt/collector/
sudo rm -rf /opt/system_services/
sudo rm -rf /opt/scheduled_tasks/

echo "[*] Directories removed."

###########################################
# 6. Remove Malicious Service
###########################################
echo "[*] Removing malicious systemd service..."

if [ -f /etc/systemd/system/system-update-custom.service ]; then
    sudo systemctl stop system-update-custom 2>/dev/null
    sudo systemctl disable system-update-custom 2>/dev/null
    sudo rm /etc/systemd/system/system-update-custom.service
    sudo systemctl daemon-reload
    echo "[-] Removed malicious service system-update-custom."
else
    echo "[OK] Service already removed."
fi

###########################################
# 7. Remove Malicious Cron Jobs
###########################################
echo "[*] Removing attacker cron jobs..."

# Remove lines containing the malicious scripts from root's crontab
sudo crontab -l 2>/dev/null | grep -v "system_maintenance.sh" | grep -v "data_backup.sh" | sudo crontab - 2>/dev/null

echo "[*] Cron jobs removed."

###########################################
# 8. Remove Malicious Files
###########################################
echo "[*] Deleting suspicious files..."

sudo rm -f /tmp/system_config.txt
sudo rm -f /opt/credentials.txt

###########################################
# 9. Remove SUID Backdoor
###########################################
echo "[*] Deleting SUID backdoor file..."

sudo rm -f /tmp/find_backup

###########################################
# 10. Remove Leftover PID Files
###########################################
echo "[*] Removing leftover PID files..."

# Network listener PID files
sudo find / -name "listener_4444.pid" -o -name "listener_8888.pid" -o -name "listener_31337.pid" 2>/dev/null | while read -r f; do
    echo "[-] Removing PID file: $f"
    sudo rm -f "$f"
done

# Process PID files
sudo find / -name "suspicious_updater.pid" -o -name "data_collector.pid" 2>/dev/null | while read -r f; do
    echo "[-] Removing PID file: $f"
    sudo rm -f "$f"
done

###########################################
# 11. Remove Threat Hunting Lab Artifact Log
###########################################
echo "[*] Removing ThreatHuntingLab_Artifacts.txt if present..."

sudo find / -name "ThreatHuntingLab_Artifacts.txt" 2>/dev/null | while read -r f; do
    echo "[-] Removing artifact log: $f"
    sudo rm -f "$f"
done

###########################################
# 12. (Optional) Clean Suspicious Bash History
###########################################
echo "[*] Scrubbing suspicious bash history entries..."

# These patterns are what the verifier is looking for:
# - wget malicious payload
# - nc listener on 4444
# - SSH backdoor key named backdoor_key

for hist in /root/.bash_history /home/*/.bash_history; do
    if [ -f "$hist" ]; then
        echo "[-] Cleaning history file: $hist"
        sudo sed -i \
            -e '/wget .*malicious/d' \
            -e '/wget http:\/\/malicious-domain\.com\/payload\.sh/d' \
            -e '/nc -lvp 4444/d' \
            -e '/backdoor_key/d' \
            "$hist"
    fi
done

###########################################
# 13. Final Verification Snapshot
###########################################
echo "[+] Running final verification snapshot..."

echo "----- Users -----"
grep -E 'svc_backup|admin_temp|webadmin' /etc/passwd || echo "[OK] No malicious users."

echo "----- Groups -----"
grep -E 'remoteadmins|backupoperators_custom' /etc/group || echo "[OK] No malicious groups."

echo "----- Ports -----"
sudo netstat -tulnp | grep -E '4444|8888|31337' || echo "[OK] No malicious listeners."

echo "----- Processes -----"
ps aux | grep -E 'suspicious_updater|data_collector' | grep -v grep || echo "[OK] No malicious processes."

echo "----- Files -----"
ls -la /tmp/system_config.txt /opt/credentials.txt 2>/dev/null || echo "[OK] Suspicious files removed."

echo "----- SUID in /tmp -----"
sudo find /tmp -perm -4000 -type f 2>/dev/null || echo "[OK] No SUID binaries in /tmp."

echo "----- PID Files -----"
sudo find / -name "listener_4444.pid" -o -name "listener_8888.pid" -o -name "listener_31337.pid" -o -name "suspicious_updater.pid" -o -name "data_collector.pid" 2>/dev/null || echo "[OK] No leftover PID files."

echo "----- Artifact Log -----"
sudo find / -name "ThreatHuntingLab_Artifacts.txt" 2>/dev/null || echo "[OK] Artifact log removed."

echo "[+] Remediation complete."
