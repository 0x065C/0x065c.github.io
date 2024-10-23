# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# John the Ripper

John the Ripper (often referred to as "John") is a fast password cracking tool designed to detect weak passwords. It supports various password hash types and offers a wide array of cracking techniques, from simple brute force to advanced attacks using wordlists and rules. This ultimate edition of the cheat sheet provides an exhaustive list of John the Ripper commands, detailed explanations, and advanced usage scenarios.

## Basic Syntax
```bash
john [options] <password_file>
```

## Core Options
- `--help`: Displays the help menu.
- `--format=<format>`: Specifies the hash format (e.g., `--format=raw-md5`, `--format=nt`).
- `--wordlist=<wordlist>`: Specifies a wordlist for a dictionary attack.
- `--rules`: Applies wordlist rules to mutate words in the wordlist.
- `--incremental`: Runs an incremental brute-force attack.
- `--single`: Uses a single-crack mode, focusing on username-based patterns.
- `--session=<name>`: Saves the session with a specific name for later resumption.
- `--restore=<name>`: Restores a saved session by name.
- `--show`: Shows the cracked passwords from the hash file.
- `--pot=<potfile>`: Specifies a pot file (a file where cracked hashes are stored).
- `--fork=<n>`: Forks the cracking process into `n` parallel processes.
- `--mask=<mask>`: Specifies a mask for pattern-based cracking.
- `--salts=<n>`: Limits the number of salts to use in the attack.
- `--incremental=<mode>`: Uses a specific incremental mode.
- `--min-length=<length>`: Specifies the minimum password length to attempt.
- `--max-length=<length>`: Specifies the maximum password length to attempt.
- `--mem-file-size=<size>`: Specifies the maximum size for wordlist in memory.
- `--no-log`: Disables logging.
- `--nolog`: Alternative command to disable logging.
- `--verbosity=<n>`: Sets the verbosity level of the output.

# Commands and Use Cases

#### Cracking Password Hashes

1. **Single Mode Attack**: Attempts to crack passwords based on the username or related information, which is effective against weak passwords.
    ```bash
    john --single <password_file>
    ```
2. **Wordlist Attack**: Uses a wordlist to attempt to crack the passwords. This method is highly effective when common passwords are used.
    ```bash
    john --wordlist=<wordlist> <password_file>
    ```
3. **Wordlist Attack with Rules**: Applies mutation rules to the words in the wordlist to generate variations, increasing the chances of cracking complex passwords.
    ```bash
    john --wordlist=<wordlist> --rules <password_file>
    ```
4. **Incremental Brute-Force Attack**: Performs an incremental brute-force attack, trying all possible character combinations up to a specified length.
    ```bash
    john --incremental <password_file>
    ```
5. **Masked Attack**: Uses a mask to limit the characters in each position of the password. This is useful when the format of the password is known (e.g., one uppercase letter, two lowercase letters, followed by three digits).
    ```bash
    john --mask=?u?l?l?d?d?d <password_file>
    ```
6. **Forked Cracking with Multiple Processes**: Splits the cracking process across multiple CPU cores for faster results.
    ```bash
    john --wordlist=<wordlist> --fork=4 <password_file>
    ```
7. **Restoring a Cracking Session**: Resumes a previously saved cracking session, useful when you need to interrupt and later continue a long-running cracking job.
    ```bash
    john --restore=<session_name>
    ```
8. **Showing Cracked Passwords**: Displays the passwords that have been cracked so far from the given hash file.
    ```bash
    john --show <password_file>
    ```
9. **Saving Cracked Passwords in a Specific Pot File**: Saves cracked passwords to a specific pot file, allowing for easy management and retrieval of results.
    ```bash
    john --pot=<potfile> <password_file>
    ```
10. **Custom Incremental Mode**: Uses a custom incremental mode defined in the `john.conf` file, allowing for targeted brute-force attacks based on specific character sets or lengths.
    ```bash
    john --incremental=<mode_name> <password_file>
    ```

#### Advanced Cracking Techniques

1. **Hybrid Attack (Wordlist + Brute-Force)**:  Combines wordlist and brute-force attacks, first trying the wordlist and then using brute-force on any remaining uncracked hashes.
    ```bash
    john --wordlist=<wordlist> --incremental <password_file>
    ```
2. **Cracking NTLM Hashes**: Targets NTLM hashes specifically, which are common in Windows environments.
    ```bash
    john --format=nt --wordlist=<wordlist> <password_file>
    ```
3. **Cracking MD5 Hashes**: Focuses on cracking MD5 hashes, often used in web applications and older systems.
    ```bash
    john --format=raw-md5 --wordlist=<wordlist> <password_file>
    ```
4. **Cracking ZIP File Passwords**: Extracts the password hash from a ZIP file and then attempts to crack it.
    ```bash
    zip2john <encrypted.zip> > ziphash.txt
    john --wordlist=<wordlist> ziphash.txt
    ```
5. **Cracking PDF File Passwords**: Extracts the password hash from a PDF file and then attempts to crack it.
    ```bash
    pdf2john.pl <encrypted.pdf> > pdfhash.txt
    john --wordlist=<wordlist> pdfhash.txt
    ```
6. **Cracking Encrypted SSH Private Keys**: Extracts the password hash from an SSH private key and then attempts to crack it.
    ```bash
    ssh2john <encrypted_id_rsa> > sshhash.txt
    john --wordlist=<wordlist> sshhash.txt
    ```
7. **Cracking RAR File Passwords**: Extracts the password hash from a RAR file and then attempts to crack it.
    ```bash
    rar2john <encrypted.rar> > rarhash.txt
    john --wordlist=<wordlist> rarhash.txt
    ```
8. **Distributed Cracking Across Multiple Systems**: Distributes the cracking process across multiple systems, specifying the node number and total nodes for distributed cracking.
    ```bash
    john --wordlist=<wordlist> --node=1/4 --fork=4 <password_file>
    ```
9. **Custom Wordlist Generation with Mask**: Generates a custom wordlist based on a mask, which can then be used for a targeted dictionary attack.
    ```bash
    john --stdout --mask=?u?l?l?d?d?d > custom_wordlist.txt
    ```
10. **Selective Cracking by Hash Type**: Focuses cracking efforts on a specific hash type, optimizing the process for the given format.
    ```bash
    john --format=raw-md5 --fork=4 <password_file>
    ```

#### Performance Optimization

1. **Using OpenMP for Parallel Processing**: Leverages OpenMP to parallelize the cracking process across multiple CPU cores.
    ```bash
    john --fork=8 <password_file>
    ```
2. **Optimizing Wordlist Size with Memory Limits**: Limits the memory used by the wordlist to prevent system slowdowns or crashes.
    ```bash
    john --wordlist=<large_wordlist> --mem-file-size=100MB <password_file>
    ```
3. **Using GPU Acceleration (Jumbo version)**: Utilizes GPU acceleration for faster password cracking, available in the Jumbo version of John the Ripper.
    ```bash
    john --format=nt-opencl --wordlist=<wordlist> <password_file>
    ```
4. **Benchmarking Cracking Speed**: Runs a benchmark test for 10 seconds to determine the optimal settings for cracking.
    ```bash
    john --test=10
    ```
5. **Limiting Salts for Faster Cracking**: Reduces the number of salts used in the attack, which can significantly speed up the process when dealing with large numbers of hashes.
    ```bash
    john --salts=1 --wordlist=<wordlist> <password_file>
    ```
6. **Adjusting Verbosity for Detailed Logging**: Increases verbosity to provide more detailed logging and feedback during the cracking process.
    ```bash
    john --wordlist=<wordlist> --verbosity=5 <password_file>
    ```
7. **Minimizing I/O Operations**: Disables logging to reduce I/O operations, which can improve performance in large-scale attacks.
    ```bash
    john --nolog --wordlist=<wordlist> <password_file>
    ```
8. **Cracking Multiple Hash Types Simultaneously**: Uses the dynamic format to crack multiple types of hashes in a single run.
    ```bash
    john --format=dynamic --wordlist=<wordlist> <password_file>
    ```
9. **Customizing Rules for Optimal Performance**: Applies optimized rules from the Jumbo version of John the Ripper for improved performance.
    ```bash
    john --wordlist=<wordlist> --rules=jumbo <password_file>
    ```
10. **Managing Sessions for Long-Running Jobs**: Saves the current session, allowing you to stop and resume long-running cracking jobs as needed.
    ```bash
    john --session=<session_name> --wordlist=<wordlist> <password_file>
    ```

# Penetration Testing Techniques

#### Password Hash Extraction

John the Ripper is often used in penetration testing scenarios where passwords need to be extracted and cracked.

1. **Extracting Password Hashes from /etc/shadow**: Combines `/etc/passwd` and `/etc/shadow` files into a format that John can crack.
    ```bash
    unshadow /etc/passwd /etc/shadow > shadow.txt
    john shadow.txt
    ```
2. **Extracting Password Hashes from Windows SAM**: Extracts password hashes from a Windows SAM file for cracking.
    ```bash
    samdump2 /mnt/windows/System32/config/SAM > samhash.txt
    john --format=nt samhash.txt
    ```
3. **Extracting Password Hashes from Active Directory**: Uses `secretsdump.py` to extract password hashes from Active Directory, then cracks them with John.
    ```bash
    secretsdump.py <domain>/<user>@<target> -hashes <LMhash>:<NThash> -outputfile hashdump
    john --format=nt hashdump
    ```
4. **Extracting Hashes from MySQL Databases**: Dumps password hashes from a MySQL database and cracks them.
    ```bash
    mysqldump -u root -p --databases mysql --tables user --no-create-info --skip-triggers --skip-add-locks --skip-comments > mysqlhashes.sql
    john --format=mysql --wordlist=<wordlist> mysqlhashes.sql
    ```
5. **Extracting Password Hashes from LDAP**: Extracts password hashes from an LDAP directory and attempts to crack them.
    ```bash
    ldapsearch -x -b "dc=example,dc=com" "(objectClass=posixAccount)" userPassword | grep userPassword | sed 's/userPassword: //' > ldappasswords.txt
    john --format=ldap --wordlist=<wordlist> ldappasswords.txt
    ```

#### Credential Harvesting

John the Ripper can be used to harvest and crack credentials in various penetration testing scenarios.

1. **Harvesting Passwords from a Web Application**: Uses `sqlmap` to extract password hashes from a web application and cracks them with John.
    ```bash
    sqlmap -u "http://target.com/vulnerable_param" --dump --output-dir=./
    john --wordlist=<wordlist> --format=raw-md5 dumped_hashes.txt
    ```
2. **Harvesting Passwords from Network Traffic**: Extracts FTP usernames from captured network traffic and uses them with John to crack passwords.
    ```bash
    tshark -r capture.pcap -Y "ftp.request.command == USER" -T fields -e ftp.request.arg > ftp_users.txt
    john --wordlist=<wordlist> ftp_users.txt
    ```
3. **Harvesting Passwords from a Compromised System**: Extracts password hashes from a compromised system using Meterpreter, then cracks them with John.
    ```bash
    meterpreter > hashdump
    john --wordlist=<wordlist> --format=nt hashdump.txt
    ```
4. **Harvesting Passwords from Encrypted Files**: Extracts and cracks password hashes from GPG-encrypted files.
    ```bash
    gpg2john <encrypted_file.gpg> > gpghash.txt
    john --wordlist=<wordlist> gpghash.txt
    ```
5. **Harvesting Passwords from Encrypted Archives**: Extracts password hashes from 7z-encrypted archives and cracks them.
    ```bash
    7z2john.pl <encrypted.7z> > 7zhash.txt
    john --wordlist=<wordlist> 7zhash.txt
    ```

#### Defense Evasion and Bypassing Protections

John the Ripper includes techniques for evading detection and bypassing security measures during password cracking.

1. **Evading Account Lockouts**: Limits the run-time to avoid triggering account lockouts, then resumes after a delay.
    ```bash
    john --incremental --max-run-time=10 <password_file>
    sleep 60
    ```
2. **Bypassing Password Complexity Requirements**: Combines wordlist rules and masks to bypass password complexity requirements.
    ```bash
    john --wordlist=<wordlist> --rules=single --mask=?u?l?l?d?d?d <password_file>
    ```
3. **Cracking Passwords Without Detection**: Uses short cracking intervals and disables logging to minimize detection risk.
    ```bash
    john --incremental --max-run-time=5 --nolog <password_file>
    ```
4. **Stealth Cracking on Shared Systems**: Limits memory usage and disables logging for stealthier operation on shared systems.
    ```bash
    john --fork=2 --mem-file-size=50MB --nolog <password_file>
    ```
5. **Obfuscating Cracking Activities**: Uses multiple techniques to obfuscate the cracking process, reducing the chance of detection.
    ```bash
    john --wordlist=<wordlist> --rules --incremental --mem-file-size=100MB --nolog --verbosity=1 <password_file>
    ```

#### Post-Exploitation: Gaining Deeper Access

John the Ripper can be a crucial tool during post-exploitation phases, helping to gain deeper access to a compromised system.

1. **Cracking System Administrator Passwords**: Focuses on cracking the hashes of system administrator accounts to escalate privileges.
    ```bash
    john --format=nt --wordlist=<wordlist> <samhash.txt>
    ```
2. **Cracking Database Administrator Passwords**: Targets database administrator passwords to gain control over critical databases.
    ```bash
    john --format=mysql --wordlist=<wordlist> <mysqlhashes.txt>
    ```
3. **Cracking Passwords for Encrypted Communications**: Cracks SSH private key passphrases to gain access to encrypted communications.
    ```bash
    john --format=ssh --wordlist=<wordlist> <sshhash.txt>
    ```
4. **Cracking Passwords to Access Encrypted Volumes**: Targets encrypted volumes, such as LUKS, to gain access to stored data.
    ```bash
    luks2john <encrypted_volume.img> > luks_hash.txt
    john --wordlist=<wordlist> luks_hash.txt
    ```
5. **Using Cracked Passwords to Move Laterally**: Uses cracked passwords to move laterally within a network, accessing additional systems.
    ```bash
    cracked_password=$(john --show <password_file> | grep "<target_user>" | cut -d':' -f2)
    ssh <target_user>@<target_ip> -p 22
    ```

# Resources

|**Name**|**URL**|
|---|---|
|John the Ripper Documentation|https://www.openwall.com/john/doc/|
|John the Ripper GitHub Repository|https://github.com/openwall/john|
|Wordlists for John the Ripper|https://github.com/danielmiessler/SecLists|
|John the Ripper Jumbo Patch|https://github.com/magnumripper/JohnTheRipper|
|Cracking Passwords with John|https://www.kali.org/tools/john/|
|Optimizing John for Performance|https://www.openwall.com/john/doc/FAQ.shtml|
|Advanced John the Ripper Techniques|https://www.exploit-db.com/papers/12934|
|John the Ripper in CTFs|https://ctftime.org/writeups/overview/john|
|Automating Password Cracking with John|https://null-byte.wonderhowto.com/how-to/automate-your-password-cracking-with-john-ripper-0151843/|
|Defending Against John the Ripper|https://www.sans.org/white-papers/defense-mechanisms-against-password-cracking-986/|