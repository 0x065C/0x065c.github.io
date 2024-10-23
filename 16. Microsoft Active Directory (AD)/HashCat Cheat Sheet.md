# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# HashCat

HashCat is a powerful password recovery tool that supports various hashing algorithms. It is known for its speed and efficiency, particularly when leveraging GPU acceleration. This ultimate edition cheat sheet provides a comprehensive overview of HashCat commands, usage scenarios, and advanced techniques.

## Basic Syntax
```bash
hashcat [options] -m <hash_type> -a <attack_mode> <hash_file> [wordlist|mask|directory] [additional_options]
```

## Core Options

- `-m <hash_type>`: Specifies the hash type (e.g., `0` for MD5, `1000` for NTLM, etc.).
- `-a <attack_mode>`: Defines the attack mode:
  - `0`: Dictionary attack.
  - `1`: Combination attack.
  - `3`: Brute-force attack (mask attack).
  - `6`: Hybrid Wordlist + Mask attack.
  - `7`: Hybrid Mask + Wordlist attack.
  - `9`: Association attack.
- `<hash_file>`: The file containing the hashes to crack.
- `<wordlist>`: A file containing potential passwords (for dictionary attacks).
- `<mask>`: Defines the pattern for brute-force attacks (e.g., `?a?a?a?a` for all printable ASCII characters).
- `-o <output_file>`: Specifies the file to save cracked passwords.
- `--session <session_name>`: Saves the session for later resumption.
- `--restore`: Resumes a saved session.
- `--show`: Displays the cracked passwords from a previous run.
- `--remove`: Removes cracked hashes from the hash file.
- `--username`: Treats the input file as having usernames in the format `username:hash`.
- `--increment`: Increases the length of the mask incrementally (used with brute-force attack).
- `--status`: Displays the status of the cracking process in real-time.
- `--force`: Forces HashCat to bypass warning messages.
- `--potfile-disable`: Disables writing to the `.pot` file.
- `--logfile-disable`: Disables writing to the log file.

### Hash Type Examples

- `0`: MD5
- `100`: SHA1
- `500`: md5crypt, MD5(Unix)
- `1000`: NTLM
- `1700`: SHA-512
- `1800`: sha512crypt, SHA512(Unix)
- `2100`: Domain Cached Credentials (DCC), MS Cache
- `3200`: bcrypt $2*$, Blowfish (Unix)
- `13721`: WPA/WPA2

# Commands and Use Cases

1. **Dictionary Attack (Mode 0)**: Cracks NTLM hashes using a dictionary attack with a specified wordlist.
    ```bash
    hashcat -m 1000 -a 0 <hash_file> <wordlist>
    ```
2. **Combination Attack (Mode 1)**: Combines entries from two wordlists to generate password candidates.
    ```bash
    hashcat -m 0 -a 1 <hash_file> <wordlist1> <wordlist2>
    ```
3. **Brute-Force Attack (Mask Attack, Mode 3)**: Performs a brute-force attack on NTLM hashes with a mask of four characters.
    ```bash
    hashcat -m 1000 -a 3 <hash_file> ?a?a?a?a
    ```
4. **Hybrid Wordlist + Mask Attack (Mode 6)**: Appends a three-digit numeric mask to each word in the wordlist.
    ```bash
    hashcat -m 0 -a 6 <hash_file> <wordlist> ?d?d?d
    ```
5. **Hybrid Mask + Wordlist Attack (Mode 7)**: Prepends a three-digit numeric mask to each word in the wordlist.
    ```bash
    hashcat -m 0 -a 7 <hash_file> ?d?d?d <wordlist>
    ```

### Advanced Usage

#### Optimizing Performance

1. **GPU Acceleration**: Utilizes both CPU and GPU for cracking, optimizing for speed.
    ```bash
    hashcat -m 1000 -a 0 -w 3 --opencl-device-types 1,2 <hash_file> <wordlist>
    ```
2. **Utilizing Multiple GPUs**: Leverages multiple GPUs to accelerate the cracking process.
    ```bash
    hashcat -m 0 -a 0 -w 3 --opencl-devices 1,2,3,4 <hash_file> <wordlist>
    ```
3. **Adjusting Workload Profiles**: Sets the workload profile to `4`, maximizing performance at the cost of system responsiveness.
    ```bash
    hashcat -m 1000 -a 0 -w 4 <hash_file> <wordlist>
    ```
4. **Tuning Kernel Loops and Acceleration**: Fine-tunes kernel acceleration and loop counts for optimal performance on specific hardware.
    ```bash
    hashcat -m 1000 -a 0 --kernel-accel=32 --kernel-loops=1024 <hash_file> <wordlist>
    ```

#### Session Management

1. **Saving and Restoring Sessions**: Saves the current session as `mysession` and allows restoring it later.
    ```bash
    hashcat -m 1000 -a 0 --session mysession <hash_file> <wordlist>
    # To restore:
    hashcat --restore --session mysession
    ```
2. **Monitoring Session Status**: Displays the status of the cracking session every 10 seconds.
    ```bash
    hashcat --status --status-timer=10 --session mysession
    ```
3. **Auto-Restart on Interruption**: Automatically restores and resumes the session if interrupted, with a 60-second delay between retries.
    ```bash
    hashcat -m 1000 -a 0 --session mysession --restore-timer=60 <hash_file> <wordlist>
    ```

#### Mask Attacks

1. **Custom Mask Definitions**: Defines a mask that includes one lowercase letter, one uppercase letter, one digit, one special character, followed by two digits.
    ```bash
    hashcat -m 1000 -a 3 <hash_file> ?l?u?d?s?d?d
    ```
2. **Incremental Mask Length**: Starts with a 4-character mask and incrementally increases it up to 8 characters.
    ```bash
    hashcat -m 1000 -a 3 --increment --increment-min=4 --increment-max=8 <hash_file> ?a?a?a?a?a?a?a?a
    ```
3. **Mask File**: Uses a predefined mask file to guide the brute-force attack.
    ```bash
    hashcat -m 0 -a 3 <hash_file> -i --increment-min=1 --increment-max=8 --custom-charset1=?l?d --custom-charset2=?u?s <mask_file>
    ```

#### Rule-Based Attacks

1. **Using Predefined Rules**: Applies a set of rules from `<rules_file>` to a dictionary attack.
    ```bash
    hashcat -m 1000 -a 0 -r <rules_file> <hash_file> <wordlist>
    ```
2. **Combining Rules with Masks**: Applies rules to the mask attack, enhancing its effectiveness.
    ```bash
    hashcat -m 1000 -a 3 -r <rules_file> <hash_file> ?a?a?a?a?a
    ```
3. **Writing Custom Rules**: Writes a custom rule to replace the character `$` with `@` in every word from the wordlist.
    ```bash
    echo 's$@' > custom.rule
    hashcat -m 1000 -a 0 -r custom.rule <hash_file> <wordlist>
    ```
4. **Chained Rule Files**: Chains multiple rule files together for a more complex attack strategy.
    ```bash
    hashcat -m 1000 -a 0 -r <rules_file1> -r <rules_file2> <hash_file> <wordlist>
    ```

#### Hybrid Attacks

1. **Hybrid Attack with Multiple Masks**: Combines a wordlist with an incrementing numeric mask, trying passwords like `password123`, `admin456`, etc.
    ```bash
    hashcat -m 1000 -a 6 <hash_file> <wordlist> ?d?d?d --increment
    ```
2. **Combining Hybrid with Rules**: Applies rules to a hybrid attack, generating even more password candidates.
    ```bash
    hashcat -m 1000 -a 7 -r <rules_file> <hash_file> ?d?d?d?d <wordlist>
    ```
3. **Advanced Hybrid Masking**: Customizes the hybrid attack by defining specific character sets for the mask.
    ```bash
    hashcat -m 1000 -a 6 <hash_file> <wordlist> ?u?d?s --custom-charset1=?u?s
    ```

#### Advanced Output Management

1. **Saving Cracked Passwords with Additional Information**: Saves cracked passwords along with their corresponding hashes in the specified format.
    ```bash
    hashcat -m 1000 -a 0 -o cracked.txt

 --outfile-format 2 <hash_file> <wordlist>
    ```
2. **Output to CSV Format**: Outputs the results in CSV format, making them easier to analyze in spreadsheets or databases.
    ```bash
    hashcat -m 1000 -a 0 -o cracked.csv --outfile-format 6 <hash_file> <wordlist>
    ```
3. **Log Only Cracked Hashes**: Displays and saves only the cracked hashes, filtering out the uncracked ones.
    ```bash
    hashcat -m 1000 -a 0 --show --outfile=cracked_only.txt <hash_file>
    ```
4. **Potfile Management**: Disables writing to the `.pot` file during the attack, useful for keeping the attack isolated.
    ```bash
    hashcat -m 1000 -a 0 --potfile-disable <hash_file> <wordlist>
    ```

#### Specialized Attacks

1. **Attack on Salted Hashes**: Attacks salted SHA1 hashes using a specified salt file.
    ```bash
    hashcat -m 20 -a 0 <hash_file> <wordlist> --salt-file=<salt_file>
    ```
2. **Cracking Wi-Fi Passwords (WPA/WPA2)**: Cracks WPA/WPA2 Wi-Fi passwords using a captured handshake file (`.hccapx`).
    ```bash
    hashcat -m 2500 -a 0 <.hccapx_file> <wordlist>
    ```
3. **Distributed Cracking with Multiple Hashes**: Divides the workload for distributed cracking, processing a specific range of hashes.
    ```bash
    hashcat -m 1000 -a 0 -o cracked.txt --potfile-disable --skip 1000000 --limit 500000 <hash_file> <wordlist>
    ```
4. **Attacking Encrypted Archives**: Cracks encrypted ZIP or RAR archives.
    ```bash
    hashcat -m 11300 -a 0 <hash_file> <wordlist>
    ```
5. **Bitlocker Volume Decryption**: Attacks a Bitlocker encrypted volume using the recovery password hash.
    ```bash
    hashcat -m 22100 -a 0 <hash_file> <wordlist>
    ```

# Penetration Testing Techniques

#### Offline Password Cracking

1. **Extracting Hashes from a Compromised System**: Dumps password hashes from the Windows SAM file.
    ```bash
    samdump2 /mnt/windows/SYSTEM /mnt/windows/SAM > hashes.txt
    ```
2. **Cracking NTLM Hashes**: Uses the popular `rockyou.txt` wordlist to crack NTLM hashes.
    ```bash
    hashcat -m 1000 -a 0 hashes.txt rockyou.txt
    ```
3. **Multi-Stage Cracking Strategy**: Combines dictionary attacks with custom wordlists and brute-force for comprehensive cracking.
    ```bash
    hashcat -m 1000 -a 0 hashes.txt <common_passwords_list>
    hashcat -m 1000 -a 0 hashes.txt <custom_wordlist>
    hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a
    ```

#### Online Attacks and Data Breaches

1. **Cracking Leaked Hashes from a Data Breach**: Uses a dictionary attack to crack MD5 hashes leaked in a data breach.
    ```bash
    hashcat -m 0 -a 0 leaked_hashes.txt rockyou.txt
    ```
2. **Targeted Password Guessing**: Targets a specific set of users with a combination of a wordlist and numeric mask.
    ```bash
    hashcat -m 1000 -a 6 hashes.txt custom_list.txt ?d?d?d
    ```
3. **Exploiting Password Reuse**: Cracks hashes assuming password reuse across multiple accounts.
    ```bash
    hashcat -m 0 -a 0 reused_hashes.txt <password_list>
    ```

#### Leveraging GPU and Cloud Resources

1. **GPU Cracking Optimization**: Optimizes the cracking process for GPUs, selecting the most aggressive workload profile.
    ```bash
    hashcat -m 1000 -a 3 --opencl-device-types 2 --workload-profile 4 hashes.txt ?a?a?a?a?a
    ```
2. **Using Cloud GPUs**: Deploys HashCat on cloud infrastructure (e.g., AWS, Google Cloud) with GPU instances for large-scale cracking.
    ```bash
    hashcat -m 1000 -a 0 -w 3 --opencl-device-types 2 --session cloud_crack hashes.txt rockyou.txt
    ```
3. **Distributed Cracking Across Multiple Systems**: Distributes the cracking task across multiple systems, effectively splitting the workload.
    ```bash
    hashcat -m 1000 -a 0 --skip 0 --limit 1000000 --session node1 hashes.txt rockyou.txt &
    hashcat -m 1000 -a 0 --skip 1000000 --limit 1000000 --session node2 hashes.txt rockyou.txt &
    hashcat -m 1000 -a 0 --skip 2000000 --limit 1000000 --session node3 hashes.txt rockyou.txt &
    ```

#### Defensive Measures Against HashCat

1. **Salting Passwords**: Demonstrates the added complexity of cracking salted hashes, making attacks more time-consuming.
    ```bash
    hashcat -m 5000 -a 0 salted_hashes.txt rockyou.txt --salt-file=salt.txt
    ```
2. **Increasing Password Length**: Shows the exponential increase in time required to brute-force longer passwords.
    ```bash
    hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a?a
    ```
3. **Using PBKDF2, bcrypt, or scrypt**: Illustrates the effectiveness of slow hashing algorithms in thwarting brute-force attacks.
    ```bash
    hashcat -m 3200 -a 0 bcrypt_hashes.txt rockyou.txt
    ```

# Resources

|**Name**|**URL**|
|---|---|
|HashCat Documentation|https://hashcat.net/wiki/doku.php?id=hashcat|
|HashCat Forums|https://hashcat.net/forum/|
|HashCat GitHub Repository|https://github.com/hashcat/hashcat|
|HashCat FAQ|https://hashcat.net/wiki/doku.php?id=frequently_asked_questions|
|Hash Type Reference|https://hashcat.net/wiki/doku.php?id=example_hashes|
|Rule-Based Attack Examples|https://hashcat.net/wiki/doku.php?id=rule_based_attack|
|Mask Attack Examples|https://hashcat.net/wiki/doku.php?id=mask_attack|
|Optimizing HashCat Performance|https://hashcat.net/wiki/doku.php?id=performance_tuning|
|Best Practices for Password Cracking|https://hashcat.net/wiki/doku.php?id=cracking_best_practice|
|Common Wordlists and Resources|https://github.com/danielmiessler/SecLists|