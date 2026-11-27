// 40 high-yield GCIH flashcards: Windows Event IDs, CLI flags, persistence paths, IR frameworks.
const r = String.raw;

export const flashcards = [
  // ---------- Domain 1: IR frameworks, volatility, packet & memory tooling ----------
  { id: 'fc-01', domain: 1, tag: 'IR Framework', front: 'PICERL — the six incident handling phases', back: 'Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned' },
  { id: 'fc-02', domain: 1, tag: 'IR Framework', front: 'Order of volatility (RFC 3227), most to least volatile', back: r`1. Registers, cache
2. Routing table, ARP cache, process table, kernel stats, memory
3. Temporary file systems
4. Disk
5. Remote logging / monitoring data
6. Physical configuration, network topology
7. Archival media` },
  { id: 'fc-03', domain: 1, tag: 'IR Framework', front: 'NIST SP 800-61 incident response lifecycle (4 phases)', back: '1. Preparation\n2. Detection & Analysis\n3. Containment, Eradication & Recovery\n4. Post-Incident Activity' },
  { id: 'fc-04', domain: 1, tag: 'tcpdump', front: 'tcpdump: read a pcap, no name/port resolution, show only SYN packets (no ACK)', back: r`tcpdump -nn -r cap.pcap 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'` },
  { id: 'fc-05', domain: 1, tag: 'tcpdump', front: 'tcpdump ring buffer: 100 MB files, keep 10, full packets', back: r`tcpdump -i eth0 -s 0 -C 100 -W 10 -w ring.pcap` },
  { id: 'fc-06', domain: 1, tag: 'tshark', front: 'tshark: capture filter vs display filter flags', back: r`-f "<BPF>"     capture filter (libpcap/BPF syntax)
-Y "<filter>"  display filter (Wireshark syntax)
-T fields -e <field>  print chosen fields
-z conv,tcp    conversation statistics` },
  { id: 'fc-07', domain: 1, tag: 'Volatility', front: 'Volatility 3: core Windows process plugins and what they reveal', back: r`windows.pslist   walk active process list
windows.psscan   pool-tag scan (finds hidden/exited)
windows.pstree   parent/child tree
windows.cmdline  process arguments
windows.netscan  network endpoints
windows.malfind  injected RWX private memory` },
  { id: 'fc-08', domain: 1, tag: 'Volatility', front: 'Normal parent of svchost.exe, lsass.exe, and services.exe', back: 'svchost.exe ← services.exe\nlsass.exe ← wininit.exe\nservices.exe ← wininit.exe\n(explorer.exe is usually orphaned because userinit.exe exits)' },
  { id: 'fc-09', domain: 1, tag: 'AI Triage', front: 'Three rules for AI-assisted log/malware triage', back: '1. Treat AI output as advisory; verify against raw evidence\n2. Treat pasted logs as untrusted input (prompt injection risk)\n3. Only use approved tools; redact sensitive data' },

  // ---------- Domain 2: scanning, enumeration, detection, shells ----------
  { id: 'fc-10', domain: 2, tag: 'Nmap', front: 'Nmap scan types: -sS, -sT, -sU, -sA, -sn', back: r`-sS  SYN half-open (default as root)
-sT  full TCP connect (no root needed)
-sU  UDP scan
-sA  ACK scan (maps firewall filtering)
-sn  host discovery only, no port scan` },
  { id: 'fc-11', domain: 2, tag: 'Nmap', front: 'Nmap flags for no DNS, skip discovery, versions, default scripts, all ports', back: '-n  never resolve DNS\n-Pn treat hosts as up\n-sV service/version detection\n-sC default NSE scripts\n-p- all 65,535 TCP ports' },
  { id: 'fc-12', domain: 2, tag: 'Nmap', front: 'Packet signature of an Nmap Xmas scan', back: 'TCP flags FIN + PSH + URG set (Flags [FPU]). Closed port → RST; open|filtered → no reply.' },
  { id: 'fc-13', domain: 2, tag: 'Snort/Suricata', front: 'Anatomy of a Snort/Suricata rule header', back: r`action proto src_ip src_port -> dst_ip dst_port (options;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"..."; flags:S; sid:1000001; rev:1;)` },
  { id: 'fc-14', domain: 2, tag: 'Snort/Suricata', front: 'Content modifiers: depth, offset, distance, within', back: 'offset/depth: absolute, from start of payload (where to start / how far to look)\ndistance/within: relative to the end of the previous content match' },
  { id: 'fc-15', domain: 2, tag: 'Netcat', front: 'Bind shell vs reverse shell (who listens?)', back: 'Bind: victim listens, attacker connects in.\nReverse: attacker listens, victim connects out (evades inbound firewall rules).' },
  { id: 'fc-16', domain: 2, tag: 'Netcat', front: 'Common netcat flags: -l -v -n -p -z -e', back: '-l listen  -v verbose  -n no DNS  -p local port\n-z zero-I/O (port scan)  -e execute program after connect' },
  { id: 'fc-17', domain: 2, tag: 'SMB', front: 'Why "SMB signing not required" matters', back: 'Allows NTLM relay attacks (captured authentication replayed to the host). Fix: require SMB signing; disable LLMNR/NBT-NS.' },
  { id: 'fc-18', domain: 2, tag: 'Covert Channels', front: 'Indicators of DNS tunneling', back: 'Long, high-entropy subdomain labels; many TXT/NULL queries; high query volume to one domain; unusually large DNS packets.' },

  // ---------- Domain 3: credential & cloud IR ----------
  { id: 'fc-19', domain: 3, tag: 'Event ID', front: 'Windows logon events 4624, 4625, 4634, 4648', back: '4624 successful logon\n4625 failed logon\n4634 logoff\n4648 logon with explicit credentials' },
  { id: 'fc-20', domain: 3, tag: 'Event ID', front: 'Logon types 2, 3, 4, 5, 9, 10', back: '2 interactive  3 network  4 batch  5 service\n9 NewCredentials (runas /netonly)  10 RemoteInteractive (RDP)' },
  { id: 'fc-21', domain: 3, tag: 'Event ID', front: 'Kerberos events 4768, 4769, 4771 and NTLM 4776', back: '4768 TGT requested\n4769 service ticket requested (Kerberoasting: RC4 0x17)\n4771 pre-auth failed\n4776 NTLM credential validation' },
  { id: 'fc-22', domain: 3, tag: 'Event ID', front: '4625 SubStatus codes 0xC000006A, 0xC0000064, 0xC0000234', back: '0xC000006A wrong password (valid user)\n0xC0000064 user does not exist\n0xC0000234 account locked out' },
  { id: 'fc-23', domain: 3, tag: 'Kerberos', front: 'Kerberoasting: detection and prevention', back: 'Detect: many 4769 with RC4 (0x17) from one user; honey SPN accounts.\nPrevent: gMSA or 25+ char random passwords, AES-only service accounts.' },
  { id: 'fc-24', domain: 3, tag: 'AWS', front: 'AWS access key prefixes AKIA vs ASIA', back: 'AKIA = long-term IAM user key (deactivate it)\nASIA = temporary STS credential (revoke role sessions via aws:TokenIssueTime deny)' },
  { id: 'fc-25', domain: 3, tag: 'AWS', front: 'High-signal CloudTrail events for key compromise', back: 'GetCallerIdentity, CreateUser, CreateAccessKey, AttachUserPolicy, UpdateAssumeRolePolicy, PutBucketPolicy, StopLogging, DeleteTrail' },
  { id: 'fc-26', domain: 3, tag: 'AWS', front: 'AWS IAM key compromise containment steps', back: r`1. aws iam update-access-key --status Inactive
2. Attach explicit deny-all policy
3. Revoke role sessions (TokenIssueTime deny)
4. Hunt for new users/keys/roles/trust changes
5. Rotate and move to short-lived credentials` },
  { id: 'fc-27', domain: 3, tag: 'Azure/M365', front: 'Entra ID sign-in error codes 50126, 50053, 50074', back: '50126 invalid username or password\n50053 account locked (smart lockout)\n50074 strong authentication (MFA) required' },
  { id: 'fc-28', domain: 3, tag: 'Azure/M365', front: 'BEC mailbox IR checklist', back: 'Remove malicious inbox rules & forwarding, revoke sessions, reset password, review MFA methods, remove illicit OAuth grants, search UAL (MailItemsAccessed), notify finance.' },

  // ---------- Domain 4: web & API ----------
  { id: 'fc-29', domain: 4, tag: 'Web', front: 'Apache/Nginx combined log format field positions (awk)', back: r`$1 client IP   $4 timestamp   $6-$8 request ("METHOD URI PROTO")
$7 URI   $9 status code   $10 response bytes   $11 referer   $12+ user agent` },
  { id: 'fc-30', domain: 4, tag: 'Web', front: 'SQL injection log indicators', back: r`' or %27, -- or #, UNION SELECT, information_schema, SLEEP( / BENCHMARK(, OR 1=1, sqlmap user agent, DB syntax errors in error log` },
  { id: 'fc-31', domain: 4, tag: 'Web', front: 'Primary fixes: SQLi, XSS, command injection, SSRF', back: 'SQLi → parameterized queries\nXSS → context-aware output encoding + CSP\nCommand injection → no shell; argument arrays + allowlists\nSSRF → destination allowlist, block internal ranges, IMDSv2' },
  { id: 'fc-32', domain: 4, tag: 'API', front: 'BOLA/IDOR vs BFLA', back: 'BOLA/IDOR: accessing another user\'s object by changing its ID.\nBFLA: calling a function/endpoint your role should not access (e.g., admin DELETE).' },
  { id: 'fc-33', domain: 4, tag: 'Cloud', front: 'AWS instance metadata endpoint and the control that blunts SSRF theft', back: '169.254.169.254 → /latest/meta-data/iam/security-credentials/<role>\nEnforce IMDSv2 (PUT for session token + header), hop limit 1.' },

  // ---------- Domain 5: persistence, pivoting, evasion, LLM ----------
  { id: 'fc-34', domain: 5, tag: 'Persistence', front: 'Windows Run key persistence paths', back: r`HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
...\RunOnce (runs once then deleted)` },
  { id: 'fc-35', domain: 5, tag: 'Event ID', front: 'Persistence-related Event IDs: 4698, 7045, 4697, 4720, 4732', back: '4698 scheduled task created\n7045 service installed (System log)\n4697 service installed (Security log)\n4720 user created\n4732 member added to local group' },
  { id: 'fc-36', domain: 5, tag: 'Persistence', front: 'WMI event subscription persistence: the three objects', back: r`__EventFilter (trigger)
CommandLineEventConsumer / ActiveScriptEventConsumer (action)
__FilterToConsumerBinding (link)
Namespace: root\subscription — Sysmon 19/20/21` },
  { id: 'fc-37', domain: 5, tag: 'Persistence', front: 'Linux persistence locations to check', back: r`cron: /etc/crontab, /etc/cron.d/, /var/spool/cron/
systemd: /etc/systemd/system/, ~/.config/systemd/user/, timers
~/.ssh/authorized_keys, ~/.bashrc, /etc/profile.d/
/etc/ld.so.preload, UID 0 accounts in /etc/passwd` },
  { id: 'fc-38', domain: 5, tag: 'Pivoting', front: 'SSH tunnel flags -L, -R, -D', back: '-L local forward: local port → remote target via SSH server\n-R remote forward: listener on SSH server → target via client\n-D dynamic SOCKS proxy' },
  { id: 'fc-39', domain: 5, tag: 'Anti-Forensics', front: 'Log-clearing and timestomping indicators', back: '1102 Security log cleared; 104 other log cleared\nwevtutil cl / Clear-EventLog\nTimestomping: $STANDARD_INFORMATION earlier than $FILE_NAME, .0000000 sub-seconds' },
  { id: 'fc-40', domain: 5, tag: 'LLM Security', front: 'Key OWASP LLM risks for incident handlers', back: 'LLM01 Prompt Injection (direct & indirect)\nLLM02 Sensitive Information Disclosure\nLLM06 Excessive Agency\nLLM07 System Prompt Leakage\nMitigate: untrusted-input handling, least-privilege tools, human approval' },
];
