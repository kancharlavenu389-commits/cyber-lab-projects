Project: Manual Exploitation & Network Analysis of vsftpd 2.3.4
🎯 Objective
To demonstrate the exploitation of a known backdoor in an outdated FTP service, perform manual credential dumping, and analyze the resulting unencrypted network traffic.
🛠️ Environment
Attacker Machine: Kali Linux
Target Machine: Metasploitable 2 (Isolated Host-Only Network)
Analysis Tools: Nmap, Netcat (nc), Wireshark
🔴 Phase 1: Offensive Execution (Red Team)
Initial reconnaissance via Nmap identified Port 21 open, running vsftpd 2.3.4.
While the standard Metasploit module can automate this exploit, I opted for a manual connection to demonstrate the underlying mechanics. The vsftpd 2.3.4 vulnerability allows an attacker to trigger a backdoor by sending a username containing a :) sequence. This opens a secret listener on Port 6200.
![msf](https://github.com/user-attachments/assets/bc0371c1-1954-4de6-b59b-eea2e204df9a)

![nc](https://github.com/user-attachments/assets/9546bdaa-0758-4ea7-9f48-d36614881d9b)

Result: Successfully bypassed automated tools, connected directly to Port 6200 via Netcat, and achieved a root shell. Executed credential dumping by reading the /etc/shadow file.
🔵 Phase 2: Traffic Analysis (Blue Team)
To understand the defensive footprint of FTP, I utilized Wireshark to capture the network traffic during a standard authentication attempt.
![wireshark](https://github.com/user-attachments/assets/f236bb46-2b85-43a8-8190-7babbf146ccb)

Result: The packet capture explicitly demonstrates that standard FTP transmits credentials (USER and PASS) in cleartext, making it highly susceptible to packet sniffing and credential harvesting on local networks.
🛡️ Remediation Strategy
Immediate: Disable the vsftpd service and block Port 21 on the host firewall.
Long-Term: Migrate all file transfer operations to SFTP (SSH File Transfer Protocol) on Port 22, which encrypts the entire session, including authentication credentials.




Project: SSH Brute Force Simulation & Log Forensics
🎯 Objective
To execute a dictionary-based brute-force attack against an SSH service and perform defensive log analysis using command-line tools to identify the indicator of compromise.
🛠️ Environment
Attacker Machine: Kali Linux
Target Machine: Metasploitable 2
Analysis Tools: Hydra, Linux CLI (grep)
🔴 Phase 1: Offensive Execution (Red Team)
Identified an open SSH port (Port 22) on the target machine. Utilized an automated dictionary attack, passing a custom wordlist against the target user account to guess the credentials.
![hydra](https://github.com/user-attachments/assets/0bf0b536-e333-40aa-8f52-4bf2e2610717)

Result: Successfully cracked the SSH credentials by systematically guessing passwords until a valid authentication token was received, granting remote access.
🔵 Phase 2: Log Triage (Blue Team)
To simulate a SOC analyst's workflow, I accessed the target machine's raw authentication logs. I used the command grep "Failed password" /var/log/auth.log to parse the file and isolate malicious activity.
![grep](https://github.com/user-attachments/assets/27f0d30a-f11b-4693-b719-1a045fa39c75)

Result: The log analysis revealed a massive flood of failed login attempts originating from a single IP address within a very short timeframe. This clear pattern represents a True Positive indicator of an automated brute-force attack.
🛡️ Remediation Strategy
Implement account lockout policies (such as Fail2Ban) to temporarily block IP addresses after a set number of failed attempts.
Disable password authentication entirely in favor of cryptographic SSH Key-based authentication.
