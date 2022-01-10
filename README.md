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

## Web Content Discovery

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

## Subdomain Enumeration

1. Check TLS Certificate;
2. Serach Engines, to reveal subdomains:
      - GOOGLE: -site:www.targetsite.com site:* .targetsite.com

3. DNS Bruteforce:
      - $ dnsrecon -d targetsite.com -D /usr/share/wordlists/dnsmap.txt -t std

## User Enumeration

If the POST form returns a different answer for existing usernames rather than non existent:

    $ ffuf -w /usr/share/wordlists/[usernames.txt] -u http:/targetsite.com -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "name_parameter=FUZZ&password_parameter=randompass" -[mx] [number or "string for mr"]

Where the match criteria is used in order to print only some matching Responses:

| [mx] | Result                                              |
|------|-----------------------------------------------------|
| mc   | Match code (200, 204, 301, 302, 307, 401, 403, 405) |
| mw   | Match amount of words in response                   |
| mr   | Match defined "string" in response                  |
| ml   | Match amount of lines in response                   |
| ms   | Match HTTP response size                            |

# Exploitation

# Privilege Escalation

# Post-Exploitation
[GTFO bins](https://gtfobins.github.io/)

## Vulnerabilities

### Brute Force

### Subdomain Enumeration

### IDOR

### LFI & RFI

### XSS

### SQL Injection
