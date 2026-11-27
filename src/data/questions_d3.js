// Domain 3 — Password & Cloud Credential Attacks (defender's perspective)
// Detecting Kerberoasting, NTLM abuse and password spraying; AWS CloudTrail/IAM IR; Azure/Entra ID & M365 IR.
const r = String.raw;

export const questionsD3 = [
  {
    id: 'd3-q01',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`EventID: 4769  A Kerberos service ticket was requested.
Account Name:        jdoe@CORP.LOCAL
Service Name:        svc_sql
Ticket Options:      0x40810000
Ticket Encryption Type: 0x17
Client Address:      ::ffff:10.20.4.22
(same client requested 37 distinct service tickets in 40 seconds)`,
    question: 'What attack does this pattern most strongly indicate?',
    options: [
      'Golden ticket',
      'Pass-the-hash',
      'AS-REP roasting',
      'Kerberoasting: bulk service-ticket requests for SPN accounts using RC4 (0x17)',
    ],
    correctIndex: 3,
    explanation: 'Any domain user can request service tickets for accounts with SPNs, and part of each ticket is protected by the service account\'s key. Attackers request RC4 (0x17) tickets because they are weaker. A burst of 4769 events with RC4 from one user to many services is the classic detection. AS-REP roasting appears as 4768 with pre-authentication type 0, and golden tickets often show service-ticket requests with no preceding 4768.',
  },
  {
    id: 'd3-q02',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: '',
    question: 'Which control MOST reduces the impact of Kerberoasting against service accounts?',
    options: [
      'Enabling SMB signing',
      'Blocking TCP 88 at the perimeter',
      'Disabling LLMNR',
      'Using group Managed Service Accounts (gMSA) or long (25+ character) random passwords, and enforcing AES-only Kerberos encryption for service accounts',
    ],
    correctIndex: 3,
    explanation: 'Kerberoasting succeeds only when the service account password is guessable offline. gMSAs rotate long random passwords automatically, and AES-only settings remove the weaker RC4 option. SMB signing and LLMNR hardening address relay and poisoning, not Kerberoasting. Kerberos traffic is internal, so perimeter blocks do nothing.',
  },
  {
    id: 'd3-q03',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`EventID 4625 (x214 in 10 min)  Logon Type 3
Account Name: a.adams, b.brown, c.chen, d.diaz, ... (214 unique)
Failure Reason: Unknown user name or bad password.  Status: 0xC000006D  SubStatus: 0xC000006A
Source Network Address: 10.20.4.77
EventID 4624  Account Name: m.miller  Source Network Address: 10.20.4.77`,
    question: 'What attack occurred, and what is the immediate concern?',
    options: [
      'Brute force against one account; no concern',
      'Kerberoasting',
      'Password spraying (one or few passwords across many accounts); m.miller successfully authenticated and is likely compromised',
      'Credential stuffing against a web app',
    ],
    correctIndex: 2,
    explanation: 'Many unique accounts with one failure each from a single source is spraying, which stays under per-account lockout thresholds. SubStatus 0xC000006A means wrong password for a valid user (0xC0000064 would mean the user does not exist). The subsequent 4624 shows a hit: reset m.miller, review its activity, and contain 10.20.4.77.',
  },
  {
    id: 'd3-q04',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`{
  "eventName": "GetCallerIdentity",
  "eventSource": "sts.amazonaws.com",
  "sourceIPAddress": "45.155.205.11",
  "userAgent": "aws-cli/2.15.0 Python/3.11 Linux/6.1 exe/x86_64.kali.2024",
  "userIdentity": { "type": "IAMUser", "userName": "ci-deploy", "accessKeyId": "AKIA4XVQEXAMPLE7M2Q" }
}`,
    question: 'Why is this single CloudTrail event a strong early indicator of key compromise?',
    options: [
      'It is a typical first "whoami" call after obtaining a key; the unfamiliar IP and a Kali user agent on a CI service account are anomalous',
      'GetCallerIdentity modifies IAM permissions',
      'GetCallerIdentity is only available to root',
      'STS events are never logged',
    ],
    correctIndex: 0,
    explanation: 'sts:GetCallerIdentity cannot be denied by IAM and reveals the account ID and principal behind a key, so it is usually an intruder\'s first step. A long-term key (AKIA prefix) for a CI user suddenly used from a new IP with a Kali user-agent string is high fidelity. GuardDuty has a PenTest:IAMUser/KaliLinux finding for exactly this.',
  },
  {
    id: 'd3-q05',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`$ aws iam update-access-key --user-name ci-deploy --access-key-id AKIA4XVQEXAMPLE7M2Q --status Inactive
$ aws iam put-user-policy --user-name ci-deploy --policy-name IR-DenyAll --policy-document file://deny-all.json`,
    question: 'Why does the responder deactivate the key rather than delete it immediately?',
    options: [
      'Deleting keys is impossible',
      'Inactive keys alert the attacker',
      'Deactivation also rotates the secret',
      'Deactivation stops use immediately while preserving the key ID for investigation and allowing reactivation if a business process breaks; deletion can follow scoping',
    ],
    correctIndex: 3,
    explanation: 'Setting the key Inactive is instant, reversible containment. Keeping the key ID lets you correlate CloudTrail activity and confirm no further use. An explicit deny-all inline policy also stops any other credentials the user may hold. Deactivation does not rotate the secret; you issue a new key for legitimate use after eradication.',
  },
  {
    id: 'd3-q06',
    domain: 3,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'Which Windows Event ID records Kerberos pre-authentication failures on a domain controller, useful for spotting password spraying over Kerberos?',
    options: [
      '4624',
      '7045',
      '4688',
      '4771',
    ],
    correctIndex: 3,
    explanation: '4771 (Kerberos pre-authentication failed, failure code 0x18 for a bad password) is logged on DCs when Kerberos is used, and spraying tools that use Kerberos generate these instead of 4625. 4624 is a successful logon, 4688 is process creation, and 7045 is service installation.',
  },
  {
    id: 'd3-q07',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`EventID 4776  The computer attempted to validate the credentials for an account.
Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account: svc_backup
Source Workstation: KALI
Error Code: 0x0`,
    question: 'What is notable about this event?',
    options: [
      'It is a Kerberos ticket request',
      'It shows a failed logon',
      'NTLM credential validation succeeded for a privileged service account from a workstation named KALI, which is not an asset name in the environment',
      'It indicates the account was disabled',
    ],
    correctIndex: 2,
    explanation: '4776 records NTLM credential validation on the DC; Error Code 0x0 means success. The source workstation name is supplied by the client, and a non-standard name like KALI authenticating as a backup service account is a strong lead for investigation of NTLM abuse such as pass-the-hash or relay. Kerberos requests are 4768/4769.',
  },
  {
    id: 'd3-q08',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`EventID 4624  An account was successfully logged on.
Logon Type:         9
Logon Process:      seclogo
Authentication Package: Negotiate
Account Name:       jdoe
Network Account Name: Administrator
Network Account Domain: CORP`,
    question: 'Logon Type 9 with logon process "seclogo" is a known detection for what activity?',
    options: [
      'A normal interactive logon at the console',
      'A scheduled task logon',
      'Use of alternate credentials for network access (runas /netonly), a pattern also produced by pass-the-hash tooling',
      'A service account starting a service',
    ],
    correctIndex: 2,
    explanation: 'Logon Type 9 (NewCredentials) keeps the local identity but uses different credentials for network resources. It is legitimate for runas /netonly, but credential-injection tools produce the same signature, so a type 9 seclogo logon presenting Administrator network credentials from a standard workstation deserves investigation. Interactive is type 2, batch is 4, and service is 5.',
  },
  {
    id: 'd3-q09',
    domain: 3,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'What is the key difference between password spraying and credential stuffing?',
    options: [
      'They are the same thing',
      'Stuffing only targets Kerberos',
      'Spraying tries a few common passwords across many accounts; stuffing replays username/password pairs leaked from other breaches',
      'Spraying requires admin rights',
    ],
    correctIndex: 2,
    explanation: 'Spraying exploits weak, common passwords while avoiding lockouts. Stuffing exploits password reuse by replaying known pairs, usually against internet-facing logins. Both are countered by MFA, banned-password lists, and monitoring for many-account failure patterns. Neither needs admin rights.',
  },
  {
    id: 'd3-q10',
    domain: 3,
    difficulty: 'Hard',
    scenarioLog: r`{"eventTime":"2026-03-14T07:02:11Z","eventName":"CreateUser","requestParameters":{"userName":"aws-health-monitor"},"userIdentity":{"userName":"ci-deploy"},"sourceIPAddress":"45.155.205.11"}
{"eventTime":"2026-03-14T07:02:15Z","eventName":"AttachUserPolicy","requestParameters":{"userName":"aws-health-monitor","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}
{"eventTime":"2026-03-14T07:02:19Z","eventName":"CreateAccessKey","requestParameters":{"userName":"aws-health-monitor"}}`,
    question: 'What has the intruder done, and what must the containment plan include?',
    options: [
      'Established persistence via a new admin IAM user with its own access key; containment must disable that user and key, not only the original ci-deploy key',
      'Read an S3 bucket; rotate the bucket key',
      'Launched EC2 instances; terminate them',
      'Nothing harmful; IAM users are inert until used',
    ],
    correctIndex: 0,
    explanation: 'CreateUser, then AttachUserPolicy with AdministratorAccess, then CreateAccessKey is a classic persistence chain with a benign-sounding name. Revoking only the initial key leaves the backdoor working. Enumerate every principal, key, role trust policy, and login profile created or modified by the compromised identity.',
  },
  {
    id: 'd3-q11',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: '{"eventName":"StopLogging","eventSource":"cloudtrail.amazonaws.com","requestParameters":{"name":"org-trail"},"userIdentity":{"userName":"aws-health-monitor"}}',
    question: 'What does this event represent, and how should defenders prepare for it?',
    options: [
      'Defense evasion: disabling the audit trail. Use an organization trail managed from a separate account, SCPs that deny StopLogging/DeleteTrail, and alert on these events',
      'Routine maintenance',
      'A billing optimization',
      'An S3 data event',
    ],
    correctIndex: 0,
    explanation: 'StopLogging, DeleteTrail, UpdateTrail, and PutEventSelectors changes are high-severity because they blind defenders. Organization trails, SCP guardrails, log delivery to a locked-down logging account with Object Lock, and EventBridge alerts on these API calls make tampering hard and visible.',
  },
  {
    id: 'd3-q12',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`Entra ID Sign-in logs (filtered: Status = Failure)
User                 App               ErrorCode  ClientApp       IP
a.adams@corp.com     Exchange Online   50126      IMAP4           185.100.87.1
b.brown@corp.com     Exchange Online   50126      IMAP4           185.100.87.1
c.chen@corp.com      Exchange Online   50126      IMAP4           185.100.87.1
...  (1,904 rows, 1 per user)`,
    question: 'What does this pattern indicate and what is the best preventive control?',
    options: [
      'MFA fatigue; train users',
      'Consent phishing; disable app registration',
      'Token replay; rotate certificates',
      'Password spraying through legacy authentication (IMAP4), which cannot do MFA; block legacy authentication via Conditional Access',
    ],
    correctIndex: 3,
    explanation: 'Error 50126 is invalid username or password. One attempt per user from one IP across the tenant is spraying, and legacy protocols like IMAP/POP/SMTP AUTH are favored because basic auth bypasses MFA prompts. Blocking legacy authentication with Conditional Access closes that path. Smart lockout (error 50053) also helps.',
  },
  {
    id: 'd3-q13',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`M365 Unified Audit Log
Operation: New-InboxRule
UserId: cfo@corp.com
Parameters: Name=".", From="invoices@", MoveToFolder="RSS Subscriptions", MarkAsRead=True, ForwardTo="acct-team@prot0nmail.com"
ClientIP: 102.89.33.14`,
    question: 'What does this inbox rule suggest?',
    options: [
      'A normal user organizing email',
      'A DLP policy',
      'Business email compromise: hiding invoice-related mail and forwarding it externally to stay unnoticed while manipulating payments',
      'A mailbox migration',
    ],
    correctIndex: 2,
    explanation: 'Rules with cryptic names (".") that move mail to obscure folders, mark it read, and forward externally are hallmarks of BEC. Responders should remove the rule, revoke sessions, reset credentials, review MFA methods and OAuth grants, check mailbox forwarding settings, and alert finance to verify recent payment changes.',
  },
  {
    id: 'd3-q14',
    domain: 3,
    difficulty: 'Hard',
    scenarioLog: r`Sign-in: cfo@corp.com  Result: Success  MFA: satisfied (claim in token)
  IP 102.89.33.14  Device: unregistered  Browser: Chrome 120 / Linux
Earlier the same hour: cfo@corp.com clicked hxxps://login.micr0soft-sso[.]com/... (proxy page)
User reports: "I signed in and approved MFA normally."`,
    question: 'Which attack best explains a successful sign-in from an attacker IP even though MFA was completed?',
    options: [
      'Adversary-in-the-middle (AiTM) phishing: a reverse proxy relayed the real login and stole the resulting session cookie',
      'Password spraying',
      'Kerberoasting',
      'SIM swapping',
    ],
    correctIndex: 0,
    explanation: 'AiTM phishing kits sit between the user and the real login page, so the user completes genuine MFA and the proxy captures the post-authentication session token. Replaying it from another IP bypasses MFA. Phishing-resistant MFA (FIDO2/passkeys, certificate-based auth), token protection, and compliant-device Conditional Access mitigate it. Respond by revoking sessions and resetting credentials.',
  },
  {
    id: 'd3-q15',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`PS> Revoke-MgUserSignInSession -UserId cfo@corp.com
PS> Update-MgUser -UserId cfo@corp.com -PasswordProfile @{ForceChangePasswordNextSignIn=$true; Password="<new-random>"}`,
    question: 'Why is revoking sign-in sessions necessary in addition to resetting the password?',
    options: [
      'It is not necessary; a password reset kills all sessions instantly',
      'Existing refresh tokens and session cookies can stay valid after a password change; revocation invalidates them so a stolen token cannot keep working',
      'It deletes the mailbox',
      'It disables MFA',
    ],
    correctIndex: 1,
    explanation: 'Tokens already issued are not necessarily tied to the password, especially when an attacker holds a stolen refresh token or session cookie. Revoke-MgUserSignInSession invalidates refresh tokens (with Continuous Access Evaluation speeding enforcement). Also review newly registered MFA methods, which attackers add for persistence.',
  },
  {
    id: 'd3-q16',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`Entra ID Audit Log
Activity: Consent to application
Target: "Mail Backup Pro" (AppId 3f2a...)
Permissions: Mail.ReadWrite, Files.ReadWrite.All, offline_access
InitiatedBy: j.lee@corp.com`,
    question: 'What attack is this, and why does a password reset alone not fix it?',
    options: [
      'Spraying; reset fixes it',
      'Illicit consent grant: the malicious OAuth app holds delegated tokens (offline_access) that keep working regardless of the user password; revoke the grant and remove the service principal',
      'Kerberoasting; rotate krbtgt',
      'A benign backup integration',
    ],
    correctIndex: 1,
    explanation: 'In consent phishing, the user authorizes an attacker-controlled app. With offline_access it gets refresh tokens and reads mail/files via Graph without the password. Remediation: revoke the OAuth2PermissionGrant, delete the enterprise app, review audit logs for its Graph activity, and restrict user consent to verified publishers or admin approval.',
  },
  {
    id: 'd3-q17',
    domain: 3,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'An AWS access key ID begins with "ASIA" instead of "AKIA". What does that tell the responder?',
    options: [
      'It is a root account key',
      'It is a temporary STS credential (from an assumed role or session), so the investigation must find which role and session issued it',
      'It is for Asia regions only',
      'It is a deactivated key',
    ],
    correctIndex: 1,
    explanation: 'AKIA prefixes long-term IAM user keys; ASIA prefixes temporary credentials from STS (AssumeRole, GetSessionToken, instance profiles). Temporary credentials cannot be deactivated directly, so you trace the AssumeRole event and revoke the role\'s active sessions. Prefixes are not region-specific.',
  },
  {
    id: 'd3-q18',
    domain: 3,
    difficulty: 'Hard',
    scenarioLog: r`{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny", "Action": "*", "Resource": "*",
    "Condition": { "DateLessThan": { "aws:TokenIssueTime": "2026-03-14T08:00:00Z" } }
  }]
}`,
    question: 'A responder attaches this policy to a compromised IAM role. What does it accomplish?',
    options: [
      'Denies the role permanently',
      'Only affects IAM users, not roles',
      'Rotates the role\'s trust policy',
      'Revokes all sessions issued before the given time (the same as the console "Revoke active sessions" action) while allowing new, legitimate sessions afterwards',
    ],
    correctIndex: 3,
    explanation: 'Temporary credentials stay valid until they expire. Denying everything for tokens issued before a cutoff (aws:TokenIssueTime) invalidates stolen sessions immediately. Pair it with fixing the root cause, for example enforcing IMDSv2 if credentials were stolen from instance metadata, or tightening the role trust policy.',
  },
  {
    id: 'd3-q19',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`GuardDuty Finding
Type: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
Resource: Role web-ec2-role (i-0a12b34c56d78e90f)
Remote IP: 203.0.113.77 (not an AWS IP)`,
    question: 'What does this GuardDuty finding mean?',
    options: [
      'Temporary credentials issued to an EC2 instance role are being used from outside AWS, meaning they were stolen (often via SSRF to the metadata service)',
      'An EC2 instance was terminated',
      'A user failed MFA',
      'An S3 bucket became public',
    ],
    correctIndex: 0,
    explanation: 'Instance role credentials should only be used by that instance. Use from an external IP signals theft, commonly through SSRF against 169.254.169.254 or host compromise. Respond by revoking the role\'s older sessions, investigating the instance, and enforcing IMDSv2 (session-token required) to blunt SSRF.',
  },
  {
    id: 'd3-q20',
    domain: 3,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'Which control most effectively defeats password spraying against internet-facing logins?',
    options: [
      'Longer account lockout durations only',
      'Multi-factor authentication combined with banned/common password lists',
      'Changing the login page URL',
      'Disabling password complexity',
    ],
    correctIndex: 1,
    explanation: 'Spraying relies on a few common passwords succeeding somewhere. MFA prevents a correct password alone from granting access, and banned-password lists (e.g., Entra ID Password Protection) stop the guessable passwords sprayers try. Lockouts are often avoided by spraying slowly, and obscurity does not help.',
  },
  {
    id: 'd3-q21',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`EventID 4768  A Kerberos authentication ticket (TGT) was requested.
Account Name: legacy_app
Pre-Authentication Type: 0
Ticket Encryption Type: 0x17
Client Address: 10.20.4.22`,
    question: 'What does Pre-Authentication Type 0 indicate, and what is the risk?',
    options: [
      'Smart card logon; no risk',
      'The TGT was forged',
      'The account is disabled',
      'The account has "Do not require Kerberos preauthentication" set, making it vulnerable to AS-REP roasting, where anyone can request material for offline guessing',
    ],
    correctIndex: 3,
    explanation: 'Normally a client proves knowledge of its key before the DC returns a TGT. Accounts with DONT_REQ_PREAUTH skip that, so anyone can request an AS-REP containing data protected by the user\'s key. Audit for accounts with that flag (userAccountControl 0x400000), remove it, and enforce strong passwords.',
  },
  {
    id: 'd3-q22',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: '{"eventName":"PutBucketPolicy","requestParameters":{"bucketName":"corp-finance-exports","bucketPolicy":{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::corp-finance-exports/*"}]}},"userIdentity":{"userName":"aws-health-monitor"}}',
    question: 'What is the impact of this API call?',
    options: [
      'It encrypts the bucket',
      'It makes every object in the finance bucket publicly readable by anyone on the internet, a likely exfiltration route',
      'It enables versioning',
      'It deletes the bucket',
    ],
    correctIndex: 1,
    explanation: 'Principal "*" with s3:GetObject grants anonymous read. Intruders use this to exfiltrate without generating authenticated download traffic tied to their identity. S3 Block Public Access at the account level prevents it, and it should be alerted on via Config/EventBridge. Check S3 server access logs or data events for downloads.',
  },
  {
    id: 'd3-q23',
    domain: 3,
    difficulty: 'Hard',
    scenarioLog: r`Event 4662 on DC01
Subject: svc_backup
Object Type: domainDNS
Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
Client: 10.20.4.22 (workstation, not a domain controller)`,
    question: 'The GUIDs are the DS-Replication-Get-Changes rights. What activity does this detect?',
    options: [
      'A normal Group Policy update',
      'An LDAP bind failure',
      'Kerberoasting',
      'DCSync: a non-DC host using directory replication rights to pull password hashes (including krbtgt) from the DC',
    ],
    correctIndex: 3,
    explanation: 'Replication requests from a workstation rather than a DC are the key DCSync detection. It yields every account\'s secrets, including krbtgt, enabling golden tickets. Response includes resetting krbtgt twice (with a pause for replication), resetting privileged accounts, and removing replication rights from non-DC principals.',
  },
  {
    id: 'd3-q24',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: '',
    question: 'After a confirmed domain compromise involving golden tickets, why must the krbtgt password be reset TWICE?',
    options: [
      'Active Directory requires two resets for any account',
      'The DC keeps the current and previous krbtgt keys; resetting twice (allowing replication between resets) ensures forged tickets made with the stolen key no longer validate',
      'The first reset is only a test',
      'It increments the domain functional level',
    ],
    correctIndex: 1,
    explanation: 'Kerberos accepts tickets encrypted with either the current or the previous krbtgt key so that tickets survive a single rotation. One reset still leaves the stolen key valid as "previous." Reset, wait for replication and ticket lifetimes, then reset again. Microsoft provides a script for safe rotation.',
  },
  {
    id: 'd3-q25',
    domain: 3,
    difficulty: 'Easy',
    scenarioLog: '{"eventName":"ConsoleLogin","userIdentity":{"type":"Root"},"responseElements":{"ConsoleLogin":"Success"},"additionalEventData":{"MFAUsed":"No"},"sourceIPAddress":"45.155.205.11"}',
    question: 'Why is this event critical?',
    options: [
      'Root logins are routine',
      'A successful root console login without MFA from an unknown IP means full account control by a likely intruder; root should be rarely used and always MFA-protected',
      'It indicates a failed login',
      'It only affects billing',
    ],
    correctIndex: 1,
    explanation: 'Root has unrestricted access that SCPs do not limit in the management account. Best practice: hardware MFA on root, no root access keys, alerts on any root usage, and break-glass procedures. MFAUsed=No plus an unfamiliar IP warrants immediate escalation.',
  },
  {
    id: 'd3-q26',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`Entra ID Sign-ins (user: j.lee@corp.com)
08:01:03 MFA denied by user
08:01:41 MFA denied by user
08:02:15 MFA denied by user
08:03:02 MFA approved (push)   IP 91.214.124.9 (new country)`,
    question: 'What attack is this, and which mitigation helps most?',
    options: [
      'Session hijacking; rotate cookies',
      'Spraying; extend lockout',
      'MFA fatigue (push bombing) after the password was obtained; enable number matching and additional context in Authenticator and alert on repeated denials',
      'Consent grant; block apps',
    ],
    correctIndex: 2,
    explanation: 'Repeated push prompts until the user approves out of annoyance is MFA fatigue. The password is already compromised, so reset it, revoke sessions, and review registered methods. Number matching forces the user to type a code shown on the sign-in screen, which defeats blind approval.',
  },
  {
    id: 'd3-q27',
    domain: 3,
    difficulty: 'Hard',
    scenarioLog: r`$ aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA4XVQEXAMPLE7M2Q \
    --start-time 2026-03-10 --query 'Events[].[EventTime,EventName,EventSource]' --output text | sort | uniq -c | sort -rn | head
  412 ... ListObjects  s3.amazonaws.com
   88 ... GetObject    s3.amazonaws.com
    9 ... DescribeInstances ec2.amazonaws.com
    1 ... GetCallerIdentity sts.amazonaws.com`,
    question: 'What limitation should the responder keep in mind when relying on lookup-events?',
    options: [
      'lookup-events covers all regions and all data events forever',
      'Event history covers only management events for 90 days in the queried region; S3 object-level data events appear only if a trail or lake was configured to record them',
      'lookup-events shows only failed calls',
      'It requires root credentials',
    ],
    correctIndex: 1,
    explanation: 'CloudTrail Event History is regional, management-events-only, and limited to 90 days. GetObject/ListObjects are data events and appear only if a trail (or CloudTrail Lake) records S3 data events; otherwise you may need S3 server access logs. Query each region the attacker may have used, or the org trail in Athena.',
  },
  {
    id: 'd3-q28',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`EventID 4624  Logon Type 3  Authentication Package: NTLM
Account: Administrator (local, RID 500)
Source: 10.20.4.22 -> targets FIN-WS10, FIN-WS11, FIN-WS12, FIN-WS13 within 2 minutes`,
    question: 'What does this suggest and which control limits it?',
    options: [
      'Normal IT administration',
      'Lateral movement reusing the same local Administrator credential across workstations; Windows LAPS gives each host a unique, rotated local admin password',
      'Kerberos delegation abuse',
      'Print spooler activity',
    ],
    correctIndex: 1,
    explanation: 'A shared local admin password (or its hash) lets an intruder hop between hosts. Rapid NTLM network logons with the built-in RID 500 account to many hosts is the signature. LAPS randomizes local admin passwords per machine, and the "Deny access to this computer from the network" right for local accounts further reduces risk.',
  },
  {
    id: 'd3-q29',
    domain: 3,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'Which Windows feature helps protect cached domain credentials in LSASS memory from being dumped on modern systems?',
    options: [
      'Credential Guard (virtualization-based security)',
      'BitLocker',
      'Windows Defender Firewall',
      'AppLocker',
    ],
    correctIndex: 0,
    explanation: 'Credential Guard isolates NTLM hashes and Kerberos secrets in a VBS-protected process (LSAIso), so tools reading LSASS cannot retrieve them. LSA Protection (RunAsPPL) is another layer. BitLocker protects data at rest, the firewall filters traffic, and AppLocker controls which applications run.',
  },
  {
    id: 'd3-q30',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`Get-MgUserAuthenticationMethod -UserId j.lee@corp.com
Type                                 Created
microsoftAuthenticatorAuthenticationMethod   2024-02-11
phoneAuthenticationMethod (+44 7xxx...)      2026-03-14 08:05   <-- 2 minutes after suspicious sign-in`,
    question: 'Why is the newly registered phone method important during IR?',
    options: [
      'Intruders register their own MFA method for persistence; it must be removed or the attacker can re-authenticate after a password reset',
      'It is a harmless user update',
      'Phones cannot be used for MFA',
      'It proves the user is innocent',
    ],
    correctIndex: 0,
    explanation: 'Registering a new authentication method right after a suspicious sign-in is a common persistence technique. Remove unknown methods, require re-registration under controlled conditions (Temporary Access Pass), and restrict security info registration with Conditional Access (e.g., only from trusted locations or compliant devices).',
  },
  {
    id: 'd3-q31',
    domain: 3,
    difficulty: 'Hard',
    scenarioLog: r`index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| stats dc(Service_Name) AS services count BY Account_Name, Client_Address
| where services > 10`,
    question: 'What is this SIEM query designed to detect, and what tuning is often needed?',
    options: [
      'Golden tickets; no tuning',
      'Password spraying via NTLM',
      'Kerberoasting (one user requesting RC4 tickets for many services); tuning to exclude legacy systems that legitimately require RC4 and known scanners',
      'DCSync',
    ],
    correctIndex: 2,
    explanation: 'Counting distinct services per requester with RC4 surfaces Kerberoasting. Some legacy apps still negotiate RC4, so baseline and allowlist them. Honey SPN accounts (decoy service accounts never used legitimately) give near-zero false-positive alerts: any 4769 for them is suspicious.',
  },
  {
    id: 'd3-q32',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`$ aws iam list-access-keys --user-name ci-deploy
AccessKeyMetadata:
- AccessKeyId: AKIA4XVQEXAMPLE7M2Q  Status: Active  CreateDate: 2021-06-01
$ git log -p --all -S 'AKIA4XVQ' -- .
commit 7d1e...  Author: dev2  Date: 2023-11-02  "add deploy script"
+ export AWS_ACCESS_KEY_ID=AKIA4XVQEXAMPLE7M2Q`,
    question: 'What root cause does this evidence point to, and what is the eradication step?',
    options: [
      'A long-lived key committed to source control; rotate it, purge it from history, move to short-lived role credentials (e.g., OIDC federation for CI), and enable secret scanning',
      'Phishing; train users',
      'An EC2 metadata SSRF',
      'A compromised root account',
    ],
    correctIndex: 0,
    explanation: 'A 2021 key hardcoded in a 2023 commit is a classic exposure path, because bots scan public repos for AKIA strings within minutes. Eradication: rotate the key, rewrite history or treat the secret as permanently exposed, replace static keys with role-based or OIDC credentials, and add push protection/secret scanning.',
  },
  {
    id: 'd3-q33',
    domain: 3,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'Why do security teams discourage storing LM hashes and NTLMv1 authentication on Windows networks?',
    options: [
      'They are cryptographically weak: LM is case-insensitive and split into 7-character halves, and NTLMv1 responses can be converted to NT hashes, so they should be disabled via Group Policy',
      'They are slower to compute',
      'They are required by Kerberos',
      'They only work on Linux',
    ],
    correctIndex: 0,
    explanation: 'LM uppercases the password and processes it in two 7-character chunks, and NTLMv1 challenge-responses are weak enough to be reversed. Set "Do not store LAN Manager hash" and "Network security: LAN Manager authentication level" to send NTLMv2 only (refuse LM and NTLM), and audit NTLM usage toward eventual restriction.',
  },
  {
    id: 'd3-q34',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`Defender for Identity alert:
"Suspected Brute Force attack (LDAP)"  Source: 10.20.4.77
Accounts attempted: 640  Passwords attempted: 2  Successful: 1 (svc_print)`,
    question: 'What is the correct IR priority?',
    options: [
      'Tune the alert; LDAP binds are noisy',
      'Disable all 640 accounts',
      'Block LDAP across the domain',
      'Treat svc_print as compromised: reset its password, review where it is used and what it accessed, and investigate and contain the 10.20.4.77 source host',
    ],
    correctIndex: 3,
    explanation: 'Two passwords across 640 accounts is spraying, and one success means a credential is in attacker hands. Focus on the confirmed compromised account and the source host. Mass-disabling accounts or blocking LDAP would cause an outage without addressing the actual risk.',
  },
  {
    id: 'd3-q35',
    domain: 3,
    difficulty: 'Hard',
    scenarioLog: r`Entra ID Sign-in (non-interactive)
User: j.lee@corp.com  App: Microsoft Graph  Token: refresh token
IP: 91.214.124.9   Device ID: (none)   Session ID: 7ab1...
Same Session ID observed earlier from IP 10.20.4.31 (corp NAT)`,
    question: 'What does a single session ID appearing from two unrelated IPs indicate?',
    options: [
      'Load balancing by Microsoft',
      'A failed sign-in',
      'A VPN reconnect is always the cause',
      'Token theft and replay: the session or refresh token issued to the legitimate device is being used by an attacker elsewhere',
    ],
    correctIndex: 3,
    explanation: 'Session IDs tie tokens to an authentication session. The same session suddenly used from a foreign IP without device information suggests a stolen token (from AiTM or infostealer malware). Revoke sessions, investigate the endpoint for infostealers, and consider token protection and compliant-device Conditional Access.',
  },
  {
    id: 'd3-q36',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: '',
    question: 'Which AWS service gives you a quick graph of a compromised principal\'s API activity, related resources, and IPs across CloudTrail, VPC Flow Logs, and GuardDuty?',
    options: [
      'AWS Shield',
      'Amazon Detective',
      'AWS Artifact',
      'AWS Trusted Advisor',
    ],
    correctIndex: 1,
    explanation: 'Amazon Detective builds behavior graphs from CloudTrail, VPC Flow Logs, GuardDuty findings and EKS audit logs to speed scoping of a compromised role or user. Shield handles DDoS, Artifact provides compliance reports, and Trusted Advisor gives best-practice checks.',
  },
  {
    id: 'd3-q37',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`EventID 4738  A user account was changed.
Target Account: svc_web
Changed Attributes: Service Principal Names: HTTP/fake.corp.local
Subject: jdoe`,
    question: 'Why would an attacker add an SPN to an account they can modify?',
    options: [
      'To enable web hosting',
      'To reset its password',
      'Targeted Kerberoasting: adding an SPN makes the account eligible for service tickets an attacker can request and attack offline',
      'To disable Kerberos',
    ],
    correctIndex: 2,
    explanation: 'With write access over an account (GenericWrite/GenericAll), adding an SPN turns any user into a Kerberoastable target. Monitor SPN changes (4738/5136) on user accounts, audit dangerous ACLs with tools like BloodHound, and ensure strong passwords for all accounts.',
  },
  {
    id: 'd3-q38',
    domain: 3,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'In M365 IR, which log source is the primary place to search for mailbox actions such as rule creation, MailItemsAccessed, and Send?',
    options: [
      'Windows Security event log',
      'AWS CloudTrail',
      'The Microsoft Purview Unified Audit Log (UAL)',
      'Sysmon',
    ],
    correctIndex: 2,
    explanation: 'The Unified Audit Log aggregates Exchange, SharePoint, OneDrive, Teams and Entra activity. MailItemsAccessed (available with appropriate licensing/audit tiers) helps determine which emails an attacker read. Retention depends on licensing, so export early during an incident.',
  },
  {
    id: 'd3-q39',
    domain: 3,
    difficulty: 'Hard',
    scenarioLog: r`{"eventName":"UpdateAssumeRolePolicy","requestParameters":{"roleName":"OrgAuditRole","policyDocument":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::999988887777:root\"},\"Action\":\"sts:AssumeRole\"}]}"},"userIdentity":{"userName":"aws-health-monitor"}}`,
    question: 'What persistence has been created?',
    options: [
      'A new S3 bucket',
      'A Lambda function',
      'A cross-account backdoor: an external AWS account (999988887777) can now assume OrgAuditRole at will',
      'A billing alarm',
    ],
    correctIndex: 2,
    explanation: 'Modifying a role trust policy to trust an attacker-owned account allows re-entry even after all users and keys are cleaned up. Eradication must review trust policies of all roles, and IAM Access Analyzer flags roles that external principals can assume.',
  },
  {
    id: 'd3-q40',
    domain: 3,
    difficulty: 'Medium',
    scenarioLog: r`Sign-in log for svc-sync@corp.com
Result: Success   ClientApp: Browser   Location: unfamiliar
Conditional Access: Not Applied (account excluded from "Require MFA" policy)`,
    question: 'What weakness does this reveal?',
    options: [
      'Exclusions from MFA policies create gaps; a service or break-glass account excluded from CA was used interactively from an unfamiliar location and should be investigated and restricted (e.g., by location or workload identity)',
      'Conditional Access is malfunctioning',
      'Browser sign-ins are always safe',
      'The account is disabled',
    ],
    correctIndex: 0,
    explanation: 'Attackers target excluded accounts because they skip MFA. Service accounts should not sign in interactively; convert them to workload identities or restrict them by named location. Break-glass accounts should be monitored with alerts on every use.',
  },
];
