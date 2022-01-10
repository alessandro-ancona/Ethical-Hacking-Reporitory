EHR - Ethical Hacking Repository


# Information Gathering

## Passive Information Gathering

1. **whois**: $ whois targetdomain.com
2. **nslookup**: $ nslookup -type=[T] targetdomain.com [optional-resolver]
      
      | [T]   | Result             |
      |-------|--------------------|
      | A     | IPv4 Addresses     |
      | AAAA  | IPv6 Addresses     |
      | CNAME | Canonical Name     |
      | MX    | Mail Servers       |
      | SOA   | Start of Authority |
      | TXT   | TXT Records        |
      
3. **dig**: $ dig [@optional-resolver] targetdomain.com [T]
4. **DNSDumpster**
5. **nmap**: $ nmap -sC -sV -A -O [target_ip] 

## Active Information Gathering

1. **ping**: $ ping -n 10 [target_ip]
2. **traceroute**: $ traceroute [target_ip or domain name]
3. **telnet**: $ telnet [target_ip] [port] 

# Enumeration/Scanning

## Pre-Access

### Web Content Discovery

1. Check http:/targetsite.com/robots.txt for hidden folders or files;
2. Check http:/targetsite.com/sitemap.xml for website architecture and hidden areas;
3. Check HTTP Response Header fields such as: "Server" (OS and version) and "X-Powered-By" (web langauge version);
4. Check Framework Stack version and vulnerabilities;
5. Google Dorking:
      
      | Filter   | Example             | Description                                      |
      |----------|---------------------|--------------------------------------------------|
      | site     | site:targetsite.com | results only from specified URL                  |
      | inurl    | inurl:admin         | results that have specified word in URL          |
      | filetype | filetype:pdf        | results which are a particular type of file ext. |
      | intitle  | intitle:admin       | results that contain the specified word in title |

6. Automated Content Discovery:
     - $ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -u http:/target.com/

### Subdomain Enumeration

1. Check TLS Certificate;
2. Serach Engines, to reveal subdomains:
      - GOOGLE: -site:www.targetsite.com site:* .targetsite.com

3. DNS Bruteforce:
      - $ dnsrecon -d targetsite.com -D /usr/share/wordlists/dnsmap.txt -t std

### Username Enumeration

For Login forms, if the HTTP response returns a different answer for existing usernames rather than non existent:

    $ ffuf -w /usr/share/wordlists/[usernames.txt] -u http:/targetsite.com -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "name_parameter=FUZZ&password_parameter=randompass" -[mx] [number or "string for mr"]

Where the match criteria is used in order to print only some matching Responses:

| [mx] | Result                                              |
|------|-----------------------------------------------------|
| mc   | Match code (200, 204, 301, 302, 307, 401, 403, 405) |
| mw   | Match amount of words in response                   |
| mr   | Match defined "string" in response                  |
| ml   | Match amount of lines in response                   |
| ms   | Match HTTP response size                            |

But you can also exploit the registration form where the "Username already exist" response will be provided.

## Post-Access

### Device enumeration

#### Manual Enumeration

1. Hostname: $ hostname
2. System information: $ uname -a
3. Processes information: $ cat /proc/version
4. OS version: $ cat /etc/os-release
5. Processes List: $ ps aux
6. Check root privileges on current user: $ sudo -l
7. User privilege and membership: $ id
8. Users on the system: $ cat /etc/passwd (Check also if it is writable)
9. Existing communications: $ netstat -a; $ netstat -ano
10. Find interesting files:
      - $ find / -name flag1.txt 2>/dev/null
11. Find writable or executable folders:
      - $ find / -perm -o w -type d 2>/dev/null
      - $ find / -perm -o x -type d 2>/dev/nul
12. Find SUID bit files (Executables with higher privileges):
      . $ find / -perm -u=s -type f 2>/dev/null

#### Automated Tools

1. LinPeas
2. LES
3. LinEnum
 
# Exploitation

## Kernel Exploitation

Once identified Kernel version, search for exploits for the kernel version of the target system and then run the snippet.


# Privilege Escalation

# Post-Exploitation
[GTFO bins](https://gtfobins.github.io/)

## Vulnerabilities

### Brute Force

#### Website Authentication bypass

    $ ffuf -w usernames.txt:W1,passwords.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -fx [number or "string for fr"]
    
Where -fx could be {fc | fw | fr | fl | fs} which are dual with respect to the matching criteria. For example -fc 200 will return only answers with response codes different from 200 (e.g. 301 permanent redirects for correct login)

### IDOR

### LFI & RFI

### XSS

### SQL Injection
