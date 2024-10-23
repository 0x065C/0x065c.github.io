# Index
- [[Metasploit]]
	- [[Metasploit Multi Handler]]
	- [[Meterpreter]]
	- [[Msfvenom]]
	- [[Searchsploit]]

# SearchSploit

SearchSploit is a command-line tool that provides direct access to Exploit Database (EDB). It is used to search through Exploit-DB’s repository of publicly available exploits and vulnerabilities, and is widely utilized by penetration testers and red teamers during vulnerability assessments and exploit development.

## Basic Syntax
```bash
searchsploit [options] <search_term>
```

## Core Options
- `-h`: Display help menu and show all available options.
- `-v`: Show verbose output with additional information.
- `-m <EDB_ID>`: Mirror (download) the exploit locally.
- `-p <EDB_ID>`: Locate exploit by Exploit-DB ID.
- `-w`: Open the exploit in a web browser (if available).
- `-t`: Perform a case-sensitive search.
- `-e`: Exact match (disables fuzzy searching).
- `-c <exploit_file>`: Perform a case-insensitive search within a specific file.
- `--author <author_name>`: Search exploits based on the author.
- `--id`: Display only the EDB-ID, ignoring other details.
- `--nmap`: Parse and search Nmap result files.
- `-u`: Update the Exploit Database repository (local copy).
- `-j`: Output the search results in JSON format.
- `--examine <CVE_ID>`: Perform a deeper inspection using CVE IDs.

## Advanced Search Options
- `-o`: Show only a list of found exploits.
- `--exclude <keyword>`: Exclude certain keywords from the search.
- `--mirror-all`: Download all exploits from the search result.
- `--color`: Enable colored output for better visibility.
- `--overflow`: Show results that might overflow the terminal screen.
- `-s`: Perform a silent search (minimal output).
- `--offline`: Use SearchSploit in offline mode without updating from the remote repository.
- `--cat <exploit_path>`: Display the content of an exploit in the terminal.

## Database Management Options
- `--remove <EDB_ID>`: Remove an entry by its Exploit-DB ID.
- `--add <exploit_file>`: Add a new exploit to the database manually.
- `--diff`: Compare local repository with the online database to show discrepancies.
- `--backup`: Create a backup of your local database.

## Search Syntax
- **Multiple Terms:** Search using multiple terms.
    ```bash
    searchsploit "apache tomcat"
    ```
- **Exact Phrase:** Use quotes for exact search.
    ```bash
    searchsploit "Windows 10"
    ```
- **AND Operator:** Combine multiple keywords with `AND`.
    ```bash
    searchsploit apache AND tomcat
    ```

# Commands and Use Cases

- **Update Exploit Database:** Updates the local copy of the exploit database.
    ```bash
    searchsploit -u
    ```
- **Basic Search:** Searches for exploits related to "WordPress".
    ```bash
    searchsploit wordpress
    ```
- **Search by Exploit-DB ID:** Searches for the exploit with EDB-ID `39446`.
    ```bash
    searchsploit -p 39446
    ```
- **Mirror (Download) Exploit:** Downloads the exploit with EDB-ID `44560`.
    ```bash
    searchsploit -m 44560
    ```
- **Search by CVE ID:** Searches for exploits related to CVE-2021-44228 (Log4Shell).
    ```bash
    searchsploit CVE-2021-44228
    ```
- **View Exploit Content:** Shows the contents of exploit `39446`.
    ```bash
    searchsploit -x 39446
    ```
- **Search in Exploit Titles Only:** Searches for "apache" in the exploit titles only.
    ```bash
    searchsploit -t apache
    ```
- **Search by Author:** Searches for exploits created by the author "John Doe".
    ```bash
    searchsploit --author "John Doe"
    ```
- **Export to JSON:** Exports search results in JSON format.
    ```bash
    searchsploit -j apache tomcat > results.json
    ```
- **Filter Out Results with Certain Keywords:** Searches for "apache" exploits but excludes any results related to "Windows".
    ```bash
    searchsploit apache --exclude "Windows"
    ```

#### Nmap Integration
SearchSploit can parse Nmap scan results to identify exploitable vulnerabilities based on detected services and software versions.

- **Parse Nmap XML:** Searches for exploits based on the services and versions detected by the Nmap scan.
    ```bash
    searchsploit --nmap nmap_scan.xml
    ```
- **Parse Nmap Grepable Output:** Parses an Nmap `.gnmap` file to search for related exploits.
    ```bash
    searchsploit --nmap nmap_scan.gnmap
    ```
- **Combine Nmap with CVE:** Filters Nmap results to show only CVE-related exploits.
    ```bash
    searchsploit --nmap nmap_scan.xml | grep CVE
    ```

#### Updating Exploit-DB and Custom Exploit Additions

1. **Update Exploit-DB:** Downloads the latest database updates from Exploit-DB.
    ```bash
    searchsploit -u
    ```
2. **Add a Custom Exploit:** Manually adds a custom exploit to the local database.
    ```bash
    searchsploit --add <path_to_exploit>
    ```
3. **Backup Local Database:** Creates a backup of your local database to prevent data loss.
    ```bash
    searchsploit --backup
    ```
4. **Restoring the Database:** Restores a previously backed-up copy of the database.
    ```bash
    tar -xvzf searchsploit_backup.tar.gz -C /usr/share/exploitdb/
    ```

# Additional Information

#### Using Exploits Manually

1. **Locate Exploit**
2. **Select Exploit and Copy to Root:** Target is running Windows, so we can try  exploit 3996.c. Copy the exploit on over to a working directory as to not write over the original and so it's easier to work with.
	```bash
	cp /usr/share/exploitdb/platform/windows/remote/3996.c /root/3996.c
	```
3. **Review File Using Gedit:** Navigate to the working directory and gedit the exploit. Review the exploit for additional information such as usage and requirements.
	```bash
	gedit 3996.c
	```
4. **Compile the Exploit:** Finally, compile the exploit. In this example, the file is written in C+, as indicated by the `.c`. This command also renames the exploit `apache` by using switch `-o`.
	```bash
	gcc 3996.c -o apache.
	```
5. **To run it, enter:**
	```bash
	./apache
	```
6. **Permissions:** In some instances modifying the permissions may be required to ensure the file is executable. 
	```bash
	chmod +x ./apache
	```

# Resources

|**Website**|**URL**|
|-|-|
|SearchSploit Documentation|https://www.exploit-db.com/searchsploit|
|Exploit Database Homepage|https://www.exploit-db.com/|
|Nmap XML Parsing with SearchSploit|https://www.offensive-security.com/metasploit-unleashed/nmap-and-searchsploit/|
|SearchSploit Usage Examples|https://www.hackingarticles.in/searchsploit-command-line-utility-explained/|
|Nmap and SearchSploit for Recon|https://infosecwriteups.com/nmap-and-searchsploit-the-perfect-couple-for-reconnaissance-a001d88219f4|
|Advanced Exploit Searches|https://github.com/offensive-security/exploitdb|
|Exploiting CVEs with SearchSploit|https://null-byte.wonderhowto.com/how-to/exploit-vulnerabilities-using-exploit-db-0176148/|
|SearchSploit Nmap Integration|https://null-byte.wonderhowto.com/how-to/find-exploits-for-open-ports-with-searchsploit-0227156/|