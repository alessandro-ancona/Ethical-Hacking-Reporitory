EHR - Ethical Hacking Repository


# Information Gathering

## Active Information Gathering

## Passive Information Gathering

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
8.

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
