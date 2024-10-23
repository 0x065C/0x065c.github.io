# Summary 
Dorking, also known as Google Dorking or Google Hacking, is a technique used in penetration testing and ethical hacking to find sensitive information exposed on the internet by using advanced search engine queries. The term "Google Dorking" comes from the fact that it originally involved crafting specific search queries on Google to uncover hidden or unintentionally exposed information. However, the technique can be applied to any search engine.

Dorking leverages advanced search operators to filter search results in a way that reveals information that might not be easily accessible through regular searches. This information can include exposed files, directories, sensitive data, misconfigured servers, login pages, and more.

Dorking is built around the use of advanced search operators that manipulate how search engines filter and display results. Here are some key search operators and how they can be used in dorking:

# Basic Search Operators

#### The `site:` Operator
- **Purpose:** Restricts the search results to a specific website or domain. This is useful for finding all indexed pages of a particular domain.
- **Usage:**
  ```bash
  site:<domain>
  ```
  - **Example:**
    ```bash
    site:example.com
    ```
  - **Application:** This can be used to enumerate subdomains, discover all indexed pages of a target domain, and focus the search within a specific website.

#### The `filetype:` Operator
- **Purpose:** Restricts the search to a specific file type. This is particularly useful for finding exposed documents, configuration files, or backups.
- **Usage:**
  ```bash
  filetype:<extension>
  ```
  - **Example:**
    ```bash
    filetype:pdf
    ```
  - **Application:** Combined with the `site:` operator, you can find all files of a specific type on a particular domain:
    ```bash
    site:example.com filetype:pdf
    ```

#### The `intitle:` Operator
- **Purpose:** Searches for pages that contain specific words in the title. This can be used to identify login pages, admin panels, or specific web applications.
- **Usage:**
  ```bash
  intitle:<keyword>
  ```
  - **Example:**
    ```bash
    intitle:"index of"
    ```
  - **Application:** To find pages that might list directory contents, you can combine this with the `site:` operator:
    ```bash
    intitle:"index of" site:example.com
    ```

#### The `inurl:` Operator
- **Purpose:** Searches for specific words within the URL. This is useful for identifying specific web pages, such as login pages or scripts with specific parameters.
- **Usage:**
  ```bash
  inurl:<keyword>
  ```
  - **Example:**
    ```bash
    inurl:login
    ```
  - **Application:** To find login pages within a domain:
    ```bash
    inurl:login site:example.com
    ```

#### The `allintext:` and `intext:` Operators
- **Purpose:** Searches for specific text within the body of a web page. `allintext:` is used to search for multiple keywords, whereas `intext:` is used for a single keyword.
- **Usage:**
  ```bash
  allintext:<keywords>
  ```
  ```bash
  intext:<keyword>
  ```
  - **Example:**
    ```bash
    intext:"password"
    ```
  - **Application:** To find pages containing certain sensitive keywords like "password" or "username":
    ```bash
    intext:"password" site:example.com
    ```

# Advanced Search Operators

#### The `cache:` Operator
- **Purpose:** Shows the cached version of a web page. This can be useful for viewing a version of a page that has been modified or taken down.
- **Usage:**
  ```bash
  cache:<url>
  ```
  - **Example:**
    ```bash
    cache:example.com
    ```
  - **Application:** Use this to view and analyze older versions of pages that might have contained sensitive information.

#### The `link:` Operator
- **Purpose:** Finds pages that link to a specific URL. This is useful for identifying backlinks or for understanding the web of connections to a specific page.
- **Usage:**
  ```bash
  link:<url>
  ```
  - **Example:**
    ```bash
    link:example.com
    ```
  - **Application:** Useful in reconnaissance to understand the relationships between different sites and the target domain.

#### The `related:` Operator
- **Purpose:** Finds pages that are similar to the specified URL. This can be used to find related websites or mirror sites.
- **Usage:**
  ```bash
  related:<url>
  ```
  - **Example:**
    ```bash
    related:example.com
    ```

#### The `define:` Operator
- **Purpose:** Provides definitions of words or phrases. This operator is more general and less useful in traditional penetration testing but can be useful in understanding jargon or technical terms found during reconnaissance.
- **Usage:**
  ```bash
  define:<keyword>
  ```
  - **Example:**
    ```bash
    define:SQL injection
    ```

#### The `*` (Wildcard) Operator
- **Purpose:** Acts as a placeholder for any word. This can be used to uncover variations of search results.
- **Usage:**
  ```bash
  "admin * login"
  ```
  - **Example:**
    ```bash
    "admin * login"
    ```
  - **Application:** Use this to find variations of phrases or search queries, such as "admin panel login," "admin area login," etc.

# Common Google Dorks for Penetration Testing

#### Finding Login Pages
- **Purpose:** Locate login pages for applications or administrative panels that might be exposed.
- **Dork Example:**
  ```bash
  inurl:login site:<target_domain>
  ```
  - **Example:**
    ```bash
    inurl:login site:example.com
    ```

#### Discovering Sensitive Directories
- **Purpose:** Identify directories that might be exposed and accessible through a browser, often containing backups, logs, or configuration files.
- **Dork Example:**
  ```bash
  intitle:"index of" "parent directory" site:<target_domain>
  ```
  - **Example:**
    ```bash
    intitle:"index of" "parent directory" site:example.com
    ```

#### Locating Exposed Files
- **Purpose:** Find files that might contain sensitive information, such as database dumps, configuration files, or source code.
- **Dork Examples:**
  - **Configuration Files:**
    ```bash
    filetype:cfg site:<target_domain>
    ```
    - **Example:**
      ```bash
      filetype:cfg site:example.com
      ```
  - **SQL Dumps:**
    ```bash
    filetype:sql "password" site:<target_domain>
    ```
    - **Example:**
      ```bash
      filetype:sql "password" site:example.com
      ```
  - **Backup Files:**
    ```bash
    filetype:bak site:<target_domain>
    ```
    - **Example:**
      ```bash
      filetype:bak site:example.com
      ```

#### Finding Vulnerable Web Applications
- **Purpose:** Identify web applications or pages that might be vulnerable to specific types of attacks, such as SQL injection.
- **Dork Example:**
  ```bash
  inurl:"id=" "SELECT * FROM" site:<target_domain>
  ```
  - **Example:**
    ```bash
    inurl:"id=" "SELECT * FROM" site:example.com
    ```

#### Uncovering Exposed Cameras and IoT Devices
- **Purpose:** Locate publicly accessible cameras, routers, or other IoT devices that are improperly secured.
- **Dork Example:**
  ```bash
  inurl:view/view.shtml
  ```
  - **Example:** This dork is used to find accessible IP cameras:
    ```bash
    inurl:view/view.shtml
    ```

#### Identifying Exposed Email Addresses
- **Purpose:** Find email addresses that are publicly exposed on the web, which can be useful for social engineering or phishing campaigns.
- **Dork Example:**
  ```bash
  site:<target_domain> intext:"@<target_domain>"
  ```
  - **Example:**
    ```bash
    site:example.com intext:"@example.com"
    ```

# Automating Dorking with Tools

Dorking can be automated using tools that help streamline the process of crafting and executing dorks. These tools can run multiple queries and gather results efficiently.

#### Google Hacking Database (GHDB)
- **Purpose:** The GHDB is a database of known Google dorks maintained by the offensive security community. It contains pre-built dorks for various purposes, such as finding vulnerable files, directories, and more.
- **Usage:**
  - Access the GHDB at: [Exploit-DB Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
  - Use the database to find relevant

 dorks based on the type of information you want to uncover.

#### `googler`
- **Purpose:** A command-line tool to search Google from the terminal. It can be used to automate dorking queries.
- **Command Example:**
  ```bash
  googler -n 5 "inurl:login site:example.com"
  ```
  - **Example:**
    ```bash
    googler -n 5 "intitle:index.of site:example.com"
    ```

#### `GooFuzz`
- **Purpose:** An automated Google Dorking tool that combines multiple dorks and searches to identify potential vulnerabilities and exposed data.
- **Usage:**
  - Clone and use GooFuzz from its repository:
    ```bash
    git clone https://github.com/johndoe/goofuzz.git
    cd goofuzz
    python3 goofuzz.py -d <target_domain>
    ```
  - **Example:**
    ```bash
    python3 goofuzz.py -d example.com
    ```

#### `dork-cli`
- **Purpose:** A command-line tool designed to run Google Dorking queries from the terminal.
- **Usage:**
  ```bash
  dork-cli -q "<dork_query>"
  ```
  - **Example:**
    ```bash
    dork-cli -q "filetype:pdf site:example.com"
    ```

# Resources

|**Website**|**URL**|
|-|-|
| Google Advanced                  | [https://www.google.com/advanced_search](https://www.google.com/advanced_search)                                                     |
| Google Support Web Search        | [https://support.google.com/websearch/answer/2466433](https://support.google.com/websearch/answer/2466433)                           |
| Bing Advanced                    | [https://help.bing.microsoft.com/apex/index/18/en-US/10002](https://help.bing.microsoft.com/apex/index/18/en-US/10002)               |
| DuckDuckGo Advanced              | [https://help.duckduckgo.com/duckduckgo-help-pages/results/syntax](https://help.duckduckgo.com/duckduckgo-help-pages/results/syntax) |
| Google Advanced Search Operators | [https://ahrefs.com/blog/google-advanced-search-operators/](https://ahrefs.com/blog/google-advanced-search-operators/)               |
| Googel Hacking Database          | [https://www.exploit-db.com/google-hacking-database/](https://www.exploit-db.com/google-hacking-database/)                           |