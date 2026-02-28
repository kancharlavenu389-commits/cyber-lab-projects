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






Project 3: Web Application Command Injection & Log Triage
🎯 Objective
To exploit a flaw in a web application's input field to gain unauthorized access to the server's operating system and analyze the resulting footprints in the Apache web logs.
🛠️ Environment
Victim: DVWA (Damn Vulnerable Web Application) hosted on Metasploitable 2.
Security Level: Low (to demonstrate raw vulnerability).
🔴 Phase 1: The Hijack (Red Team)
I identified a "Ping" search box that was intended only for IP addresses. By using a semicolon (;) as a command separator, I successfully "injected" secondary Linux commands.
Command Used: 127.0.0.1; whoami; hostname; ls -la
![dvwa command](https://github.com/user-attachments/assets/75820bc6-aa6a-4621-a1d9-19d45797fd35)

Result: The web server executed my injected commands, revealing the system user as www-data. This confirmed Remote Code Execution (RCE).
🔵 Phase 2: The Footprint (Blue Team)
After the attack, I accessed the server's backend to see how the activity was recorded. I used tail /var/log/apache2/access.log to find the evidence.
![log](https://github.com/user-attachments/assets/85ef456f-f2af-41ef-8763-97128aa8cc85)

Result: The log clearly shows my Kali IP address sending the malicious whoami string. This demonstrates how a SOC analyst can trace a web-based attack back to its source.

Result: The log analysis revealed a massive flood of failed login attempts originating from a single IP address within a very short timeframe. This clear pattern represents a True Positive indicator of an automated brute-force attack.
🛡️ Remediation Strategy
Implement account lockout policies (such as Fail2Ban) to temporarily block IP addresses after a set number of failed attempts.
Disable password authentication entirely in favor of cryptographic SSH Key-based authentication.





Project 4: Database Exploitation (SQL Injection)
🎯 Objective
To demonstrate a SQL Injection (SQLi) attack on a web application to bypass query logic and extract the entire user database.
🛠️ Environment
Application: DVWA (Damn Vulnerable Web Application).
Vulnerability: SQL Injection (Level: Low).
🔴 Phase 1: Exploitation (Red Team)
I used a "Tautology" attack string (' OR '1'='1) in the User ID field. This forced the SQL query to always evaluate as "True," causing the database to return all records instead of a single ID.
![sql](https://github.com/user-attachments/assets/bee4eac1-d9ed-48db-a7ab-bae9a72b8d50)

Result: Successfully extracted a full list of usernames and IDs from the backend database.
🔵 Phase 2: Log Triage (Blue Team)
I inspected the Apache access.log to identify the URL-encoded attack signature.
![sql2](https://github.com/user-attachments/assets/8e65cea5-a6cb-4f6f-854a-6131dfa1e3d2)

Result: Identified the specific SQLi payload within the web traffic logs, a critical skill for threat hunting and incident response.
🛡️ Remediation
Prepared Statements: Use parameterized queries to ensure the database treats input as data, not executable code.
Input Sanitization: Implement strict filtering to block special characters like ', --, and ;.

Phase 3: Cryptanalysis (Hash Cracking)
The database dump revealed that passwords were encrypted using MD5 hashing. I extracted the hash for the admin user (5f4dcc3b5aa765d61d8327deb882cf99).
![crack](https://github.com/user-attachments/assets/da34344f-bffe-46b7-8907-95266c300991)

Result: By utilizing a Rainbow Table attack (via CrackStation), I successfully reversed the MD5 hash to discover the plain-text password: password. This highlights the critical flaw of using deprecated hashing algorithms like MD5 without salting.




# Project 5: Web Application Security Assessment (DVWA)

## 🎯 Objective
Conducted a comprehensive vulnerability assessment and penetration test of a PHP-based web application to identify, exploit, and remediate *OWASP Top 10* vulnerabilities.

## 🛠️ Technical Execution & Exploitation

### 🗄️ 1. Data Exfiltration (SQL Injection)
* *Attack:* Successfully performed *Union-based SQL Injection* to bypass application logic.
* *Result:* Exfiltrated sensitive user database tables, including MD5 password hashes.
* *Tooling:* Manual injection and *Burp Suite Proxy* for traffic manipulation.

### 💻 2. Remote Code Execution (Command Injection)
* *Attack:* Exploited insecure system calls to execute arbitrary OS commands.
* *Result:* Achieved unauthorized retrieval of system-level configuration files (e.g., /etc/passwd).
* *Impact:* Demonstrated the risk of complete server takeover via unsanitized input.
* ![cmd](https://github.com/user-attachments/assets/b2b8fcac-667b-4236-a1d0-8188f3d5c653)


### 🍪 3. Session Hijacking (XSS)
* *Attack:* Identified and exploited *Reflected and Stored XSS* flaws.
* *Result:* Executed arbitrary JavaScript to exfiltrate active session cookies (PHPSESSID).
* *Tooling:* Custom![xss](https://github.com/user-attachments/assets/9424d473-f655-48de-a18e-1064eb77fdb3)
 JS payloads injected into vulnerable web forms.

![sxx](https://github.com/user-attachments/assets/8e91c594-fa90-4b0b-8243-b71498639133)

 

### 🔑 4. Automated Attacks (Brute Force)
* *Attack:* Leveraged *Burp Suite Intruder* to conduct automated credential stuffing.
* *Analysis:* Utilized HTTP response length and status code analysis to identify successful authentication bypasses.
* ![brute](https://github.com/user-attachments/assets/dc74220e-6e3b-4898-9455-1927478d92e1)
* ![brute2](https://github.com/user-attachments/assets/f14a4170-b051-4588-942d-e374fdaf3685)
* ![brute3](https://github.com/user-attachments/assets/e9947e3c-cbb6-4f53-a577-0e4f09b6e898)




---

## 🛡️ Remediation & Defensive Advocacy
To harden application defenses, I documented the following mitigation strategies:
* *Parameterized Queries:* Implementation of prepared statements to eliminate SQLi.
* *Input Validation:* Strict allow-listing of user inputs for system commands.
* *Output Encoding:* Using context-aware encoding to prevent XSS execution.
* *Security Headers:* Implementation of *Content Security Policy (CSP)* and *HttpOnly/Secure* cookie flags.




# Project 6: Full-Chain System Compromise & Forensic Analysis (Web-to-Root)

## 🎯 Objective
To execute and document a complete attack lifecycle within a controlled Linux environment (Metasploitable 2). The assessment covers initial web exploitation, system-level privilege escalation, and post-incident forensic log analysis.

---

## 🔴 Phase 1: Offensive Execution (Red Team)

### 1. Initial Access via Command Injection
* *Vulnerability:* Unsanitized user input in the DVWA web application.
* *Exploit:* Injected OS commands (cat /etc/passwd) directly into the web interface URL parameters.
* *Result:* Achieved Remote Code Execution (RCE) and gained an initial shell as the low-privilege www-data service account.
* ![cmdexec](https://github.com/user-attachments/assets/d00ca8da-f69e-4c9a-b85b-3925fe7f4570)


### 2. Privilege Escalation (The "Root" Compromise)
* *Vulnerability:* Misconfigured *SUID (Set owner User ID)* permissions on the nmap binary.
* *Exploit:* Utilized nmap --interactive to break out of the restricted shell using the !sh escape sequence.
* *Result:* Successfully escalated privileges from www-data to full administrative control.
* *Verification:* 
![netcat](https://github.com/user-attachments/assets/6fae455b-1692-4dcb-850a-b67d52c774a2)

---

## 🔵 Phase 2: Forensic Detection (Blue Team)

### 1. Web Log Analysis (The Entry Point)
Successfully traced the attacker's initial entry by analyzing the Apache web server logs.
* *Query:* sudo cat /var/log/apache2/access.log | grep "cat"
* *Finding:* Identified clear-text OS commands (cat+/etc/passwd) embedded within HTTP GET requests, confirming the exact time and method of the command injection.
  > ![apche](https://github.com/user-attachments/assets/55ea1d07-952f-4475-88ee-89e33da483e7)


### 2. Auth Log Evasion & SUID Stealth
Conducted an audit of /var/log/auth.log to track the privilege escalation.
* *Finding:* The escalation to root left *zero footprints* in the standard authentication logs. 
* *Analysis:* Because the attack exploited a file permission flaw (SUID) rather than a standard authentication mechanism (like sudo or su), it successfully bypassed standard system logging. This highlights the critical danger of SUID vulnerabilities and the need for advanced process-monitoring tools (like Auditd) to detect stealthy lateral movement.

---

## 🛡️ Remediation Strategy
To harden the system against this attack chain, the following mitigations are required:
1. *Input Sanitization:* Implement strict allow-listing and shell-escaping functions on all web forms to prevent command chaining (e.g., ;, &&, |).
2. *Principle of Least Privilege:* Regularly audit system binaries (find / -perm -4000) and remove SUID bits from administrative tools like nmap, vim, or find that allow interactive shell escapes.
