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
![nc](https://github.com/user-attachments/assets/9546bdaa-0758-4ea7-9f48-d36614881d9b)

Result: Successfully bypassed automated tools, connected directly to Port 6200 via Netcat, and achieved a root shell. Executed credential dumping by reading the /etc/shadow file.
🔵 Phase 2: Traffic Analysis (Blue Team)
To understand the defensive footprint of FTP, I utilized Wireshark to capture the network traffic during a standard authentication attempt.
![wireshark](https://github.com/user-attachments/assets/f236bb46-2b85-43a8-8190-7babbf146ccb)

Result: The packet capture explicitly demonstrates that standard FTP transmits credentials (USER and PASS) in cleartext, making it highly susceptible to packet sniffing and credential harvesting on local networks.
🛡️ Remediation Strategy
Immediate: Disable the vsftpd service and block Port 21 on the host firewall.
Long-Term: Migrate all file transfer operations to SFTP (SSH File Transfer Protocol) on Port 22, which encrypts the entire session, including authentication credentials.
