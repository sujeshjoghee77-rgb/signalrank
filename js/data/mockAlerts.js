/**
 * SignalRank - Realistic Security Alert Dataset (105+ incidents)
 * 
 * Mixed security alerts across 12+ alert categories, diverse assets,
 * sources, MITRE ATT&CK techniques, and realistic factor distributions.
 */

import { normalizeAffectedUsers } from '../engine/scoring.js';

const rawAlerts = [
  // P1 - CRITICAL TIER ALERTS
  {
    id: 'INC-2026-0001',
    timestamp: '2026-09-01T09:42:15Z',
    alertType: 'Ransomware / Mass Encryption',
    shortDescription: 'Volume Shadow Copies deleted via vssadmin and rapid .locked extension renaming detected on core Domain Controller.',
    source: 'CrowdStrike Falcon EDR',
    severity: 98,
    asset: 'AD-DC-01.corp.internal',
    assetImportance: 100,
    rawAffectedUsers: 4500,
    dataSensitivity: 95,
    attackConfidence: 96,
    businessImpact: 98,
    status: 'New',
    mitreTechnique: 'T1486 - Data Encrypted for Impact',
    iocs: ['cmd.exe /c vssadmin delete shadows /all /quiet', 'SHA256: 4a2f8e...b109', '192.168.10.5']
  },
  {
    id: 'INC-2026-0002',
    timestamp: '2026-09-01T09:30:00Z',
    alertType: 'Data Exfiltration / Cloud Sync',
    shortDescription: '142 GB anomalous outbound HTTPS data transfer to untrusted Mega.nz endpoint from production customer SQL cluster.',
    source: 'Palo Alto NGFW & Prisma Cloud',
    severity: 94,
    asset: 'DB-PROD-SQL-01.us-east-1',
    assetImportance: 95,
    rawAffectedUsers: 8500,
    dataSensitivity: 98,
    attackConfidence: 92,
    businessImpact: 95,
    status: 'Investigating',
    mitreTechnique: 'T1048.003 - Exfiltration Over Web Service',
    iocs: ['Dest IP: 185.190.140.22', 'Port: 443', 'Payload Size: 142.4 GB', 'Service: MegaSync CLI']
  },
  {
    id: 'INC-2026-0003',
    timestamp: '2026-09-01T08:15:22Z',
    alertType: 'Privilege Escalation / LSASS Dump',
    shortDescription: 'Memory dump of lsass.exe performed using comsvcs.dll mini-dump method on primary Payment Gateway API server.',
    source: 'Microsoft Defender for Endpoint',
    severity: 92,
    asset: 'PAY-PROD-API-01',
    assetImportance: 98,
    rawAffectedUsers: 1200,
    dataSensitivity: 95,
    attackConfidence: 94,
    businessImpact: 92,
    status: 'New',
    mitreTechnique: 'T1003.001 - OS Credential Dumping: LSASS Memory',
    iocs: ['rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump', 'Process: lsass.exe (PID 644)']
  },
  {
    id: 'INC-2026-0004',
    timestamp: '2026-09-01T07:50:11Z',
    alertType: 'SQL Injection / Active Exploitation',
    shortDescription: 'Stacked SQL queries injecting xp_cmdshell payloads into public authentication portal backend database.',
    source: 'Cloudflare WAF & Splunk SIEM',
    severity: 90,
    asset: 'WEB-AUTH-PORTAL-PROD',
    assetImportance: 90,
    rawAffectedUsers: 6200,
    dataSensitivity: 92,
    attackConfidence: 95,
    businessImpact: 88,
    status: 'New',
    mitreTechnique: 'T1190 - Exploit Public-Facing Application',
    iocs: ["Payload: ' UNION SELECT null, xp_cmdshell('whoami')--", 'Source IP: 194.26.29.112']
  },
  {
    id: 'INC-2026-0005',
    timestamp: '2026-09-01T09:12:44Z',
    alertType: 'Cloud IAM / Root Account Compromise',
    shortDescription: 'AWS root account logged in without MFA from anomalous ASN in St. Petersburg and generated long-term admin access keys.',
    source: 'AWS GuardDuty',
    severity: 96,
    asset: 'AWS-ROOT-MGMT-ACCOUNT',
    assetImportance: 100,
    rawAffectedUsers: 10000,
    dataSensitivity: 90,
    attackConfidence: 98,
    businessImpact: 96,
    status: 'Investigating',
    mitreTechnique: 'T1078.004 - Cloud Accounts',
    iocs: ['Action: iam:CreateAccessKey', 'IP: 195.201.225.8', 'UserAgent: aws-cli/2.15.0 Python/3.11']
  },
  {
    id: 'INC-2026-0006',
    timestamp: '2026-09-01T06:30:19Z',
    alertType: 'Lateral Movement / PsExec Execution',
    shortDescription: 'Service installation and interactive PsExec SMB execution across 18 banking transaction cluster nodes in 4 minutes.',
    source: 'SentinelOne Complete',
    severity: 88,
    asset: 'CORE-BANKING-NODE-01..18',
    assetImportance: 96,
    rawAffectedUsers: 3500,
    dataSensitivity: 90,
    attackConfidence: 90,
    businessImpact: 92,
    status: 'New',
    mitreTechnique: 'T1570 - Lateral Tool Transfer',
    iocs: ['Service: PSEXESVC.exe', 'Pipe: \\pipe\\psexec', 'Source: WKSTN-ADMIN-04']
  },
  {
    id: 'INC-2026-0007',
    timestamp: '2026-09-01T08:45:00Z',
    alertType: 'Supply Chain / Malicious Dependency',
    shortDescription: 'CI/CD pipeline executed npm package injecting obfuscated reverse shell into staging customer mobile backend build.',
    source: 'Snyk Container & GitLab Security',
    severity: 89,
    asset: 'GITLAB-RUNNER-PROD-01',
    assetImportance: 85,
    rawAffectedUsers: 5000,
    dataSensitivity: 88,
    attackConfidence: 91,
    businessImpact: 87,
    status: 'Investigating',
    mitreTechnique: 'T1195.002 - Compromise Software Supply Chain',
    iocs: ['Package: event-stream-logger@2.4.1', 'Reverse Shell: 91.240.118.172:4444']
  },
  {
    id: 'INC-2026-0008',
    timestamp: '2026-09-01T09:05:33Z',
    alertType: 'Zero-Day Exploit / Remote Code Execution',
    shortDescription: 'Unauthenticated RCE detected exploiting deserialization flaw on enterprise VPN concentrator gateway.',
    source: 'Suricata NIDS',
    severity: 97,
    asset: 'VPN-GATEWAY-EAST-01',
    assetImportance: 95,
    rawAffectedUsers: 2800,
    dataSensitivity: 80,
    attackConfidence: 94,
    businessImpact: 90,
    status: 'New',
    mitreTechnique: 'T1190 - Exploit Public-Facing Application',
    iocs: ['CVE-2026-21844', 'Exploit Payload: Java Object Deserialization', 'IP: 103.145.13.9']
  },
  {
    id: 'INC-2026-0009',
    timestamp: '2026-09-01T07:18:50Z',
    alertType: 'Living-off-the-Land / C2 Beaconing',
    shortDescription: 'PowerShell executing base64 encoded staging script with recurring beaconing intervals to Cobalt Strike C2 server.',
    source: 'CrowdStrike Falcon EDR',
    severity: 86,
    asset: 'FIN-CONTROLLER-LAPTOP',
    assetImportance: 82,
    rawAffectedUsers: 150,
    dataSensitivity: 94,
    attackConfidence: 93,
    businessImpact: 84,
    status: 'New',
    mitreTechnique: 'T1059.001 - Command and Scripting Interpreter: PowerShell',
    iocs: ['powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAag...', 'C2: cobalt-relay-cdn.xyz:8443']
  },
  {
    id: 'INC-2026-0010',
    timestamp: '2026-09-01T08:02:14Z',
    alertType: 'Mass Phishing / Executive Impersonation',
    shortDescription: 'CFO impersonation email requesting emergency wire transfer with credential harvesting link sent to 1,200 employees.',
    source: 'Proofpoint Email Protection',
    severity: 82,
    asset: 'CORP-EXCHANGE-ONLINE',
    assetImportance: 85,
    rawAffectedUsers: 1200,
    dataSensitivity: 85,
    attackConfidence: 89,
    businessImpact: 86,
    status: 'New',
    mitreTechnique: 'T1566.002 - Spearphishing Link',
    iocs: ['Sender: cfo-office@corp-internal-urgent.com', 'Phish URL: https://login-microsoft-auth365.net']
  },

  // P2 - HIGH TIER ALERTS
  {
    id: 'INC-2026-0011',
    timestamp: '2026-09-01T05:22:10Z',
    alertType: 'Kerberoasting / Service Ticket Extraction',
    shortDescription: 'High volume of RC4 Kerberos TGS requests requesting SPNs associated with Domain Admin accounts.',
    source: 'Microsoft Defender for Identity',
    severity: 78,
    asset: 'AD-DC-02.corp.internal',
    assetImportance: 90,
    rawAffectedUsers: 45,
    dataSensitivity: 80,
    attackConfidence: 86,
    businessImpact: 75,
    status: 'New',
    mitreTechnique: 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting',
    iocs: ['Target SPN: MSSQLSvc/db-prod.corp:1433', 'Encryption: RC4-HMAC']
  },
  {
    id: 'INC-2026-0012',
    timestamp: '2026-09-01T04:45:00Z',
    alertType: 'Impossible Travel / Geolocation Anomaly',
    shortDescription: 'Senior DevOps engineer account authenticated from Frankfurt and Tokyo simultaneously within 12 minutes.',
    source: 'Okta Identity Cloud',
    severity: 75,
    asset: 'OKTA-SSO-DIRECTORY',
    assetImportance: 88,
    rawAffectedUsers: 1,
    dataSensitivity: 82,
    attackConfidence: 88,
    businessImpact: 76,
    status: 'Investigating',
    mitreTechnique: 'T1078.004 - Cloud Accounts',
    iocs: ['IP1: 185.220.101.5 (Frankfurt)', 'IP2: 133.242.18.90 (Tokyo)', 'User: devops.lead@corp.com']
  },
  {
    id: 'INC-2026-0013',
    timestamp: '2026-09-01T06:10:05Z',
    alertType: 'Suspicious API Key Creation / Shadow IT',
    shortDescription: 'Production Stripe secret API key generated with full billing and customer refund permissions outside normal change window.',
    source: 'Datadog Cloud SIEM',
    severity: 80,
    asset: 'STRIPE-PROD-INTEGRATION',
    assetImportance: 85,
    rawAffectedUsers: 300,
    dataSensitivity: 88,
    attackConfidence: 82,
    businessImpact: 80,
    status: 'New',
    mitreTechnique: 'T1098 - Account Manipulation',
    iocs: ['Key: rk_live_99f2...a71', 'Action: apikey.create', 'Origin: Unknown IP 45.154.255.8']
  },
  {
    id: 'INC-2026-0014',
    timestamp: '2026-09-01T07:05:40Z',
    alertType: 'Kubernetes Pod Escape / Privileged Container',
    shortDescription: 'Container in staging namespace mounted host /var/run/docker.sock and spawned root shell on host node.',
    source: 'Sysdig Falco',
    severity: 82,
    asset: 'K8S-WORKER-NODE-07',
    assetImportance: 80,
    rawAffectedUsers: 80,
    dataSensitivity: 75,
    attackConfidence: 87,
    businessImpact: 74,
    status: 'New',
    mitreTechnique: 'T1611 - Escape to Host',
    iocs: ['Container: guestbook-frontend-7f9', 'Namespace: staging', 'Host Socket Mount']
  },
  {
    id: 'INC-2026-0015',
    timestamp: '2026-09-01T03:55:18Z',
    alertType: 'DDoS Attack / SYN Flood',
    shortDescription: '85 Gbps TCP SYN flood targeting external load balancer VIP serving retail checkout application.',
    source: 'Cloudflare Magic Transit & F5 BIG-IP',
    severity: 85,
    asset: 'EDGE-LB-VIP-01',
    assetImportance: 86,
    rawAffectedUsers: 14000,
    dataSensitivity: 30,
    attackConfidence: 95,
    businessImpact: 85,
    status: 'Contained',
    mitreTechnique: 'T1498.001 - Direct Network Flood',
    iocs: ['Attack Vector: TCP SYN on Port 443', 'Peak Rate: 84.8 Gbps', 'Source: 12,000+ Botnet IPs']
  },
  {
    id: 'INC-2026-0016',
    timestamp: '2026-09-01T06:40:12Z',
    alertType: 'Brute-Force / SSH Password Spraying',
    shortDescription: '15,000 failed SSH login attempts from 45 distributed Tor exit nodes against bastion host.',
    source: 'Splunk SIEM & Fail2ban',
    severity: 70,
    asset: 'BASTION-SSH-PUBLIC-01',
    assetImportance: 80,
    rawAffectedUsers: 250,
    dataSensitivity: 60,
    attackConfidence: 92,
    businessImpact: 68,
    status: 'Investigating',
    mitreTechnique: 'T1110.003 - Password Spraying',
    iocs: ['Target: root, admin, ubuntu', 'Failed Count: 15,402', 'IP Subnet: Tor Exits']
  },
  {
    id: 'INC-2026-0017',
    timestamp: '2026-09-01T08:25:30Z',
    alertType: 'Unauthorized DNS Tunneling',
    shortDescription: 'Anomalous high-entropy Base32 encoded TXT record queries resolved against attacker nameserver ns1.darkdns.cc.',
    source: 'Infoblox BloxOne Threat Defense',
    severity: 76,
    asset: 'WKSTN-RND-091',
    assetImportance: 65,
    rawAffectedUsers: 1,
    dataSensitivity: 86,
    attackConfidence: 88,
    businessImpact: 72,
    status: 'New',
    mitreTechnique: 'T1071.004 - Application Layer Protocol: DNS',
    iocs: ['Query: a8f9bc71.ns1.darkdns.cc', 'Volume: 12,400 queries / hour']
  },
  {
    id: 'INC-2026-0018',
    timestamp: '2026-09-01T05:50:00Z',
    alertType: 'Suspicious Scheduled Task / Persistence',
    shortDescription: 'New scheduled task "WindowsUpdateCheck" created to run hidden VBScript from C:\\ProgramData\\Temp every 30 minutes.',
    source: 'SentinelOne Complete',
    severity: 74,
    asset: 'SRV-FILE-SHARE-02',
    assetImportance: 75,
    rawAffectedUsers: 600,
    dataSensitivity: 70,
    attackConfidence: 85,
    businessImpact: 68,
    status: 'New',
    mitreTechnique: 'T1053.005 - Scheduled Task',
    iocs: ['Task: WindowsUpdateCheck', 'Path: C:\\ProgramData\\update.vbs', 'Trigger: Boot & Every 30m']
  },
  {
    id: 'INC-2026-0019',
    timestamp: '2026-09-01T07:11:29Z',
    alertType: 'Cloud Storage Bucket / Public Exposure',
    shortDescription: 'S3 bucket containing customer KYC driver licenses modified to public read via misconfigured bucket ACL policy.',
    source: 'AWS Security Hub',
    severity: 84,
    asset: 'S3-CUSTOMER-KYC-VAULT',
    assetImportance: 80,
    rawAffectedUsers: 4200,
    dataSensitivity: 96,
    attackConfidence: 96,
    businessImpact: 78,
    status: 'Investigating',
    mitreTechnique: 'T1530 - Data from Cloud Storage',
    iocs: ['Bucket: s3://corp-customer-kyc-docs-2026', 'Permission: AllUsers READ']
  },
  {
    id: 'INC-2026-0020',
    timestamp: '2026-09-01T04:12:00Z',
    alertType: 'Suspicious OAuth App Grant / Token Theft',
    shortDescription: 'Third-party OAuth application "PDF Converter Pro" granted offline access with Mail.ReadWrite and Files.ReadWrite.All scopes.',
    source: 'Microsoft Entra ID Protection',
    severity: 72,
    asset: 'M365-TENANT-CORP',
    assetImportance: 80,
    rawAffectedUsers: 14,
    dataSensitivity: 82,
    attackConfidence: 84,
    businessImpact: 70,
    status: 'New',
    mitreTechnique: 'T1528 - Steal Application Access Token',
    iocs: ['AppId: e841b903-8821-4f11-98ab', 'Scopes: Mail.ReadWrite, Files.ReadWrite.All']
  },

  // P3 - MEDIUM TIER ALERTS
  {
    id: 'INC-2026-0021',
    timestamp: '2026-09-01T02:30:15Z',
    alertType: 'Port Scan / Internal Subnet Sweep',
    shortDescription: 'Internal host initiated TCP SYN sweep across 192.168.100.0/24 subnet probing ports 22, 445, 3389.',
    source: 'Suricata NIDS',
    severity: 55,
    asset: 'WKSTN-QA-014',
    assetImportance: 45,
    rawAffectedUsers: 5,
    dataSensitivity: 35,
    attackConfidence: 85,
    businessImpact: 40,
    status: 'New',
    mitreTechnique: 'T1046 - Network Service Discovery',
    iocs: ['Source IP: 192.168.100.44', 'Probed: 254 IPs on 3 ports in 45 seconds']
  },
  {
    id: 'INC-2026-0022',
    timestamp: '2026-09-01T03:15:40Z',
    alertType: 'Failed Logins / Threshold Exceeded',
    shortDescription: '25 consecutive failed domain logins for single contractor account within 5 minutes.',
    source: 'Active Directory Event Logs',
    severity: 45,
    asset: 'CORP-VPN-PORTAL',
    assetImportance: 60,
    rawAffectedUsers: 1,
    dataSensitivity: 40,
    attackConfidence: 75,
    businessImpact: 45,
    status: 'New',
    mitreTechnique: 'T1110.001 - Password Guessing',
    iocs: ['Account: contractor.alex@corp.com', 'Failure Code: 0xC000006A (Bad Password)']
  },
  {
    id: 'INC-2026-0023',
    timestamp: '2026-09-01T01:45:00Z',
    alertType: 'Potentially Unwanted Program / Adware',
    shortDescription: 'Browser extension injecting tracking scripts and adware popups installed on marketing laptop.',
    source: 'CrowdStrike Falcon EDR',
    severity: 38,
    asset: 'WKSTN-MKTG-012',
    assetImportance: 40,
    rawAffectedUsers: 1,
    dataSensitivity: 30,
    attackConfidence: 90,
    businessImpact: 25,
    status: 'Resolved',
    mitreTechnique: 'T1176 - User Execution: Malicious Extension',
    iocs: ['Extension ID: gighmmpiobklfepjocnamgkkbiglidom', 'Hash: e99a...01bf']
  },
  {
    id: 'INC-2026-0024',
    timestamp: '2026-09-01T08:35:10Z',
    alertType: 'Suspicious USB Storage Insertion',
    shortDescription: 'Unregistered SanDisk USB flash drive connected to engineering workstation in restricted development lab.',
    source: 'Microsoft Defender Device Control',
    severity: 50,
    asset: 'WKSTN-ENG-HARDWARE-02',
    assetImportance: 65,
    rawAffectedUsers: 1,
    dataSensitivity: 60,
    attackConfidence: 95,
    businessImpact: 45,
    status: 'New',
    mitreTechnique: 'T1091 - Replication Through Removable Media',
    iocs: ['Device: USB\\VID_0781&PID_5581', 'Serial: 4C530001090317117290']
  },
  {
    id: 'INC-2026-0025',
    timestamp: '2026-09-01T06:00:22Z',
    alertType: 'SSL Certificate Expiration Warning',
    shortDescription: 'Internal telemetry SSL wildcard certificate *.internal.corp.com expires in under 48 hours.',
    source: 'Qualys SSL Labs Monitor',
    severity: 48,
    asset: 'INTERNAL-API-GATEWAY',
    assetImportance: 70,
    rawAffectedUsers: 500,
    dataSensitivity: 30,
    attackConfidence: 100,
    businessImpact: 50,
    status: 'Investigating',
    mitreTechnique: 'T1588 - Obtain Capabilities',
    iocs: ['Cert CN: *.internal.corp.com', 'Expires: 2026-09-03T00:00:00Z']
  },
  {
    id: 'INC-2026-0026',
    timestamp: '2026-09-01T04:10:00Z',
    alertType: 'Anomalous Off-Hours Database Query',
    shortDescription: 'Read-only analytics service queried 50,000 legacy records at 03:00 AM on staging reporting replica.',
    source: 'Imperva SecureSphere DAM',
    severity: 42,
    asset: 'DB-STAGE-ANALYTICS-02',
    assetImportance: 50,
    rawAffectedUsers: 0,
    dataSensitivity: 55,
    attackConfidence: 65,
    businessImpact: 35,
    status: 'New',
    mitreTechnique: 'T1005 - Data from Local System',
    iocs: ['User: svc_tableau_batch', 'Query: SELECT * FROM archive_customers WHERE created_at < 2020']
  },
  {
    id: 'INC-2026-0027',
    timestamp: '2026-09-01T05:15:30Z',
    alertType: 'Suspicious PowerShell Download Cradle',
    shortDescription: 'PowerShell Invoke-WebRequest used to download test automation script from internal GitLab server.',
    source: 'Carbon Black EDR',
    severity: 40,
    asset: 'JENKINS-AGENT-04',
    assetImportance: 55,
    rawAffectedUsers: 0,
    dataSensitivity: 30,
    attackConfidence: 60,
    businessImpact: 30,
    status: 'Resolved',
    mitreTechnique: 'T1059.001 - PowerShell',
    iocs: ['Command: iwr -Uri http://gitlab.internal/scripts/build.ps1 -OutFile C:\\temp\\build.ps1']
  },
  {
    id: 'INC-2026-0028',
    timestamp: '2026-09-01T07:44:00Z',
    alertType: 'Cleartext Password in Configuration File',
    shortDescription: 'Plaintext database password found in unencrypted application.properties file on staging web server.',
    source: 'Tenable Nessus Scanner',
    severity: 58,
    asset: 'WEB-STAGE-PORTAL-03',
    assetImportance: 45,
    rawAffectedUsers: 10,
    dataSensitivity: 65,
    attackConfidence: 90,
    businessImpact: 40,
    status: 'New',
    mitreTechnique: 'T1552.001 - Credentials in Files',
    iocs: ['File: /opt/app/config/application.properties', 'Parameter: db.password=SpringP@ss2026!']
  },
  {
    id: 'INC-2026-0029',
    timestamp: '2026-09-01T03:40:11Z',
    alertType: 'External Vulnerability Scan Detected',
    shortDescription: 'Repeated HTTP vulnerability probing from Shodan scanning engine across external IP block.',
    source: 'Palo Alto NGFW',
    severity: 35,
    asset: 'PUBLIC-IP-POOL-EDGE',
    assetImportance: 50,
    rawAffectedUsers: 0,
    dataSensitivity: 20,
    attackConfidence: 95,
    businessImpact: 20,
    status: 'Suppressed',
    mitreTechnique: 'T1595.002 - Vulnerability Scanning',
    iocs: ['Scanner: Shodan.io', 'Source IP: 198.20.99.130', 'Probed: /actuator/health, /wp-login.php']
  },
  {
    id: 'INC-2026-0030',
    timestamp: '2026-09-01T02:10:55Z',
    alertType: 'Suspicious Outbound NTP Traffic',
    shortDescription: 'Unusual volume of UDP port 123 queries sent to non-standard external timeservers from sandbox VM.',
    source: 'Snort NIDS',
    severity: 36,
    asset: 'SANDBOX-DEV-VM-18',
    assetImportance: 30,
    rawAffectedUsers: 0,
    dataSensitivity: 20,
    attackConfidence: 70,
    businessImpact: 25,
    status: 'Resolved',
    mitreTechnique: 'T1071 - Application Layer Protocol',
    iocs: ['Destination: 162.159.200.123:123', 'Rate: 15 pkts/sec']
  }
];

// Helper to generate the remaining 75 varied alerts programmatically
// with realistic enterprise variation across all categories, assets, and factor distributions.
const alertTypeTemplates = [
  {
    type: 'Ransomware / File Encryption',
    sev: [85, 98],
    ast: [80, 100],
    users: [500, 8000],
    dat: [75, 98],
    cnf: [85, 98],
    imp: [85, 98],
    sources: ['CrowdStrike Falcon EDR', 'SentinelOne Complete', 'Microsoft Defender for Endpoint'],
    desc: 'Rapid file renaming with encrypted header markers and ransomware ransom note dropped in shared folders.',
    mitre: 'T1486 - Data Encrypted for Impact'
  },
  {
    type: 'Data Exfiltration',
    sev: [80, 95],
    ast: [75, 98],
    users: [1000, 10000],
    dat: [85, 99],
    cnf: [75, 92],
    imp: [80, 95],
    sources: ['Palo Alto NGFW', 'Zscaler DLP', 'Cloudflare Gateway', 'Splunk SIEM'],
    desc: 'Unusual outbound data transfer exceeding baseline threshold to external unclassified IP destination.',
    mitre: 'T1048 - Exfiltration Over Alternative Protocol'
  },
  {
    type: 'Phishing Email / Credential Harvest',
    sev: [60, 85],
    ast: [60, 85],
    users: [50, 2500],
    dat: [60, 85],
    cnf: [70, 90],
    imp: [60, 85],
    sources: ['Proofpoint Email Protection', 'Mimecast Email Security', 'Microsoft Defender for Office 365'],
    desc: 'Inbound spearphishing email detected with obfuscated link pointing to fake corporate login portal.',
    mitre: 'T1566.002 - Spearphishing Link'
  },
  {
    type: 'Brute-Force / Password Spraying',
    sev: [50, 75],
    ast: [55, 80],
    users: [100, 1500],
    dat: [40, 70],
    cnf: [80, 95],
    imp: [45, 75],
    sources: ['Okta Identity Cloud', 'Cisco Duo Security', 'Active Directory SIEM', 'Auth0 Security'],
    desc: 'Distributed password spray targeting common passwords across multiple active enterprise accounts.',
    mitre: 'T1110.003 - Password Spraying'
  },
  {
    type: 'Privilege Escalation / Exploitation',
    sev: [75, 95],
    ast: [70, 95],
    users: [1, 200],
    dat: [65, 90],
    cnf: [80, 96],
    imp: [70, 92],
    sources: ['CrowdStrike Falcon EDR', 'Wiz Cloud Security', 'Microsoft Defender for Cloud'],
    desc: 'Local privilege escalation attempt detected attempting to spawn SYSTEM shell via token impersonation.',
    mitre: 'T1134 - Access Token Manipulation'
  },
  {
    type: 'Web Application Attack / SQLi / XSS',
    sev: [65, 90],
    ast: [65, 90],
    users: [50, 3000],
    dat: [70, 95],
    cnf: [75, 92],
    imp: [65, 90],
    sources: ['Cloudflare WAF', 'AWS WAF', 'Akamai App & API Protector', 'F5 BIG-IP ASM'],
    desc: 'WAF blocked automated injection vectors targeting customer-facing web application endpoints.',
    mitre: 'T1190 - Exploit Public-Facing Application'
  },
  {
    type: 'Port Scan / Network Reconnaissance',
    sev: [25, 55],
    ast: [30, 60],
    users: [0, 20],
    dat: [10, 40],
    cnf: [70, 95],
    imp: [20, 50],
    sources: ['Suricata NIDS', 'Snort NIDS', 'Palo Alto NGFW', 'Fortinet FortiGate'],
    desc: 'Sequential TCP port probing detected traversing external perimeter firewall interface.',
    mitre: 'T1046 - Network Service Discovery'
  },
  {
    type: 'Cloud IAM / Identity Drift',
    sev: [60, 90],
    ast: [70, 95],
    users: [10, 500],
    dat: [60, 90],
    cnf: [75, 95],
    imp: [60, 90],
    sources: ['AWS GuardDuty', 'Azure Security Center', 'Google Cloud Security Command Center'],
    desc: 'Anomalous administrative role assumption or permissive security group modification in cloud tenant.',
    mitre: 'T1078.004 - Cloud Accounts'
  },
  {
    type: 'Malware / C2 Beaconing',
    sev: [70, 92],
    ast: [60, 85],
    users: [1, 50],
    dat: [55, 85],
    cnf: [80, 95],
    imp: [65, 88],
    sources: ['SentinelOne Complete', 'CrowdStrike Falcon EDR', 'Trend Micro Apex One'],
    desc: 'Persistent outbound HTTPS beaconing pattern detected communicating with known threat actor infrastructure.',
    mitre: 'T1071.001 - Web Protocols'
  },
  {
    type: 'Living-off-the-Land / Suspicious Scripting',
    sev: [55, 82],
    ast: [50, 80],
    users: [1, 100],
    dat: [45, 75],
    cnf: [70, 88],
    imp: [50, 80],
    sources: ['Microsoft Defender for Endpoint', 'Carbon Black EDR', 'Splunk SIEM'],
    desc: 'Execution of built-in binary (certutil / bitsadmin / wmic) with anomalous command line arguments.',
    mitre: 'T1218 - System Binary Proxy Execution'
  },
  {
    type: 'DDoS / Network Flood',
    sev: [65, 88],
    ast: [70, 92],
    users: [500, 15000],
    dat: [20, 50],
    cnf: [85, 98],
    imp: [70, 95],
    sources: ['Cloudflare Magic Transit', 'Arbor Networks TMS', 'AWS Shield Advanced'],
    desc: 'High packet rate UDP / ICMP amplification flood causing service degradation on public edge endpoint.',
    mitre: 'T1498.002 - Reflection Amplification'
  },
  {
    type: 'Failed Logins / Account Lockouts',
    sev: [20, 50],
    ast: [40, 70],
    users: [1, 30],
    dat: [20, 50],
    cnf: [65, 85],
    imp: [20, 45],
    sources: ['Okta Identity Cloud', 'Active Directory Logs', 'CyberArk PAS'],
    desc: 'Multiple consecutive authentication failures resulting in automated account lockout policy trigger.',
    mitre: 'T1110.001 - Password Guessing'
  }
];

const sampleAssets = [
  { name: 'AD-DC-PRIMARY.corp.internal', importance: 98 },
  { name: 'DB-PROD-SQL-PAYMENTS', importance: 96 },
  { name: 'K8S-PROD-CLUSTER-EAST', importance: 92 },
  { name: 'AWS-ROOT-ORG-ACCOUNT', importance: 100 },
  { name: 'CORE-SWIFT-PAYMENT-SRV', importance: 97 },
  { name: 'SAP-ERP-ENTERPRISE-01', importance: 94 },
  { name: 'HEALTHCARE-EMR-RECORDS-DB', importance: 95 },
  { name: 'EXECUTIVE-LAPTOP-CFO', importance: 88 },
  { name: 'CORP-EXCHANGE-HYBRID-01', importance: 86 },
  { name: 'GITLAB-PRIMARY-ENTERPRISE', importance: 85 },
  { name: 'VPN-CONCENTRATOR-WEST', importance: 84 },
  { name: 'SALESFORCE-DATA-SYNC-SRV', importance: 80 },
  { name: 'SRV-FILE-SHARE-FINANCE', importance: 78 },
  { name: 'JENKINS-BUILD-RUNNER-12', importance: 65 },
  { name: 'WKSTN-ACCOUNTING-044', importance: 60 },
  { name: 'STAGE-WEB-APP-CLUSTER', importance: 52 },
  { name: 'DEV-SANDBOX-NODE-03', importance: 25 },
  { name: 'GUEST-WIFI-GATEWAY-LOBBY', importance: 15 },
  { name: 'PRINT-SERVER-BUILDING-B', importance: 20 },
  { name: 'TEST-AUTOMATION-VM-08', importance: 18 }
];

const statuses = ['New', 'Investigating', 'Contained', 'Resolved', 'Suppressed'];

function getRandomInt(min, max, seed) {
  // Deterministic pseudo-random based on seed to ensure 100% reproducible alerts
  const x = Math.sin(seed) * 10000;
  const rand = x - Math.floor(x);
  return Math.floor(rand * (max - min + 1)) + min;
}

// Generate alerts from index 31 to 108 (total 108 alerts)
const generatedAlerts = [];
for (let i = 31; i <= 108; i++) {
  const seed = i * 42.17;
  const templateIdx = (i - 31) % alertTypeTemplates.length;
  const template = alertTypeTemplates[templateIdx];
  const assetObj = sampleAssets[(i * 3) % sampleAssets.length];

  const id = `INC-2026-${String(i).padStart(4, '0')}`;
  
  // Calculate deterministic timestamps spanning past 48 hours
  const hoursAgo = ((108 - i) * 0.45).toFixed(2);
  const dateObj = new Date(Date.now() - (hoursAgo * 3600 * 1000));
  const timestamp = dateObj.toISOString();

  const sev = getRandomInt(template.sev[0], template.sev[1], seed + 1);
  const ast = getRandomInt(Math.max(10, assetObj.importance - 10), Math.min(100, assetObj.importance + 5), seed + 2);
  const rawUsers = getRandomInt(template.users[0], template.users[1], seed + 3);
  const dat = getRandomInt(template.dat[0], template.dat[1], seed + 4);
  const cnf = getRandomInt(template.cnf[0], template.cnf[1], seed + 5);
  const imp = getRandomInt(template.imp[0], template.imp[1], seed + 6);
  
  const statusIdx = getRandomInt(0, statuses.length - 1, seed + 7);
  const sourceIdx = (i) % template.sources.length;

  generatedAlerts.push({
    id,
    timestamp,
    alertType: template.type,
    shortDescription: `${template.desc} Identified on ${assetObj.name}.`,
    source: template.sources[sourceIdx],
    severity: sev,
    asset: assetObj.name,
    assetImportance: ast,
    rawAffectedUsers: rawUsers,
    dataSensitivity: dat,
    attackConfidence: cnf,
    businessImpact: imp,
    status: statuses[statusIdx],
    mitreTechnique: template.mitre,
    iocs: [
      `Target: ${assetObj.name}`,
      `Detection Vector: ${template.sources[sourceIdx]}`,
      `Raw Users: ${rawUsers.toLocaleString()}`
    ]
  });
}

// Combine handcrafted high-fidelity alerts with generated alerts
export const MOCK_SECURITY_ALERTS = Object.freeze([
  ...rawAlerts,
  ...generatedAlerts
]);

export function getAlertsWithNormalizedScores() {
  return MOCK_SECURITY_ALERTS.map(alert => ({
    ...alert,
    affectedUsers: normalizeAffectedUsers(alert.rawAffectedUsers)
  }));
}
