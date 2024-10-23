# Index
- [[Methodology]]
	- [[Physical Access Methodology]]
	- [[Linux Methodology]]
	- [[Windows Methodology]]
	- [[Web Application Methodology]]
	- [[Cloud Methodology]]

# External Reconnaissance
- [ ] **OSINT:** - Use `theHarvester` to gather domains, subdomains, IPs, emails, and cloud services used by the target (e.g., `cloudfront.net`, `amazonaws.com`).
- [ ] **Nmap:** - `nmap -Pn -sS -A <target_cloud_ip> -p- -o <assessment_number>_<system_name>_<date>` (applicable for public cloud-hosted assets).
- [ ] **Nessus:** - Scan cloud-hosted systems or virtual machines (e.g., AWS EC2, Azure VMs) for vulnerabilities, misconfigurations, and patches.
- [ ] **Shodan:** - Find public information about exposed cloud services, such as S3 buckets, Elasticsearch instances, and more.
- [ ] **Cloud Asset Discovery:** - Use tools like `CloudBrute` to discover exposed cloud assets, including S3 buckets, Azure Blob storage, and GCP buckets.
- [ ] **SecurityTrails:** - Enumerate domains and subdomains to find exposed cloud services.

# Initial Access
- [ ] **Exposed Storage Buckets:** - Identify misconfigured or publicly accessible storage (e.g., AWS S3, Azure Blob Storage) using tools like `s3scanner` or `cloud_enum`.
- [ ] **Credential Leaks:** - Identify leaked cloud credentials on public repositories using tools like `Gitrob` or `TruffleHog` to scan GitHub and other sources for AWS, GCP, and Azure credentials.
- [ ] **Phishing via Cloud Services:** - Use spear-phishing emails with links to cloud-hosted malicious payloads (e.g., Azure blob storage hosting malicious executables).
- [ ] **IAM Misconfigurations:** - Exploit misconfigured IAM roles or overly permissive policies to gain initial access (use tools like `Pacu` for AWS, `ScoutSuite` for Azure/GCP).
- [ ] **Exploiting Public-Facing Cloud Services:** - Exploit misconfigured services like AWS Lambda, Azure Functions, or GCP Cloud Functions that expose sensitive APIs or configurations. Use `Metasploit` or direct API interactions for exploitation.
- [ ] **Password Spraying/Brute Force on Cloud Services:** - Perform brute force or password spraying against cloud services (e.g., AWS IAM, Azure AD) using tools like `awscli`, `Azure AD Toolkit`, or `o365spray`.

# Internal Reconnaissance
- [ ] **Cloud Metadata Service:** - Enumerate the cloud metadata service (e.g., `curl http://169.254.169.254/latest/meta-data/` on AWS) to retrieve sensitive information like IAM role credentials.
- [ ] **IAM Enumeration:** - Use tools like `Pacu` (AWS), `Azucar` (Azure), or `GCPBucketBrute` (GCP) to enumerate IAM permissions, roles, and groups.
- [ ] **Network Discovery in Cloud Environments:** - Use `netstat`, `ss`, and `traceroute` to discover network configurations in cloud VMs.
- [ ] **Storage Service Enumeration:** - Use `s3scanner` or `cloud_enum` to identify accessible cloud storage services such as AWS S3, Azure Blob, or Google Cloud Storage.

# Persistence
- [ ] **Create or Modify IAM Roles:** - Create a new IAM role or modify existing roles with elevated permissions to persist within the environment (e.g., `aws iam create-role`).
- [ ] **Backdoor Lambda/Serverless Functions:** - Modify AWS Lambda, Azure Functions, or GCP Cloud Functions code to create a persistent backdoor.
- [ ] **SSO Manipulation:** - Abuse misconfigured single sign-on (SSO) services like Azure AD or Google OAuth to maintain persistent access across cloud accounts.
- [ ] **Deploy Malicious Containers:** - Deploy malicious Docker containers in ECS, EKS, or AKS for persistence within cloud workloads.
- [ ] **Modify Cloud API Gateways:** - Modify API Gateway configurations to allow continuous command and control access (e.g., malicious payload through an API route).

# Credential Harvesting
- [ ] **Cloud Credential Dumping:** - Extract IAM roles, credentials, and tokens by querying the cloud metadata service (`http://169.254.169.254/` on AWS).
- [ ] **OAuth Tokens:** - Dump OAuth tokens for cloud services like Azure, GCP, or AWS using `MicroBurst`, `Azucar`, or API interactions.
- [ ] **Secrets Manager and Parameter Store:** - Query AWS Secrets Manager or Systems Manager Parameter Store to extract credentials and sensitive data (`aws secretsmanager get-secret-value`).
- [ ] **SSRF for Metadata Access:** - Exploit SSRF vulnerabilities to access cloud metadata endpoints and extract credentials or IAM role tokens (use tools like `SSRFire`).
- [ ] **Service Account Impersonation:** - Impersonate service accounts with high privileges in GCP or Azure to escalate privileges and exfiltrate credentials.

# Privilege Escalation
- [ ] **Over-Privileged IAM Roles:** - Identify and exploit overly permissive IAM roles and policies (use `Pacu` or `ScoutSuite` to enumerate and escalate permissions).
- [ ] **Role Assumption:** - Assume higher-privileged roles in AWS or GCP using `aws sts assume-role` or equivalent commands for other cloud providers.
- [ ] **Weak Identity Federation Configurations:** - Exploit weak identity federation (e.g., SAML misconfigurations) to escalate privileges across cloud services.
- [ ] **Misconfigured Service Accounts:** - Exploit overly permissive service accounts in GCP or Azure to gain elevated privileges (enumerate permissions using `GCPBucketBrute` or `Azucar`).
- [ ] **Container Privilege Escalation:** - Escalate privileges from containers running in ECS, AKS, or GKE by exploiting misconfigured container privileges.

# Lateral Movement/Pivoting/Tunneling
- [ ] **Cross-Account Role Assumption:** - Use `sts assume-role` in AWS or equivalent in other cloud environments to pivot into other accounts with shared trust policies.
- [ ] **API Key Leaks:** - Find and exploit leaked API keys to move laterally across cloud environments (e.g., extract and use GCP, AWS, or Azure API keys).
- [ ] **Cloud Function Exploitation:** - Modify cloud functions (AWS Lambda, GCP Cloud Functions, Azure Functions) to move laterally and execute commands in different environments.
- [ ] **Pivot through IAM Roles:** - Enumerate and assume IAM roles across different cloud environments to gain access to additional resources (`aws sts assume-role`, `gcloud auth`).
- [ ] **Cloud VPN/Networking Exploitation:** - Use misconfigured cloud VPNs or Virtual Private Cloud (VPC) peering to pivot within or across cloud networks.

# Data Exfiltration
- [ ] **Cloud Storage Services:** - Exfiltrate sensitive data from misconfigured cloud storage services (AWS S3, Azure Blob Storage, GCP Buckets) using `aws s3 cp`, `azcopy`, or `gsutil`.
- [ ] **API Gateway/HTTPS Exfiltration:** - Set up API Gateway endpoints or HTTPS POST requests to exfiltrate data via cloud APIs.
- [ ] **Covert Channels in Cloud:** - Use covert channels such as DNS tunneling via cloud DNS or ICMP via cloud VMs for exfiltration.
- [ ] **Cloud Database Dumping:** - Extract data from cloud-hosted databases (e.g., RDS, DynamoDB, Cosmos DB) using SQL queries or cloud-native tools (`aws rds describe-db-instances`).
- [ ] **SaaS Platform Exfiltration:** - Use misconfigured SaaS platforms (e.g., Office365, Google Workspace) for data exfiltration by uploading files or sending large amounts of data to external storage.
