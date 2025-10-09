### dnsrecon Cheat Sheet (Raw Memo Style)

Install (Kali Linux)  
Check: dnsrecon --version  
If missing:  
sudo apt update  
sudo apt install dnsrecon -y  
Verify: dnsrecon -h  
Deps: python3, python3-dnspython (auto)  
Time: ~30s

Usage: dnsrecon [options] -d <domain>

Options:

- -d <domain>: Target (e.g., example.com)
- -t <type>: Test type (std, axfr, brt, srv, tld, ptr, cache, rpz)
- -D <dict>: Brute force wordlist (e.g., /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt)
- -n <nameserver>: NS server (e.g., 8.8.8.8)
- -r <from-to>: IP range (e.g., 192.168.1.1-192.168.1.100)
- -x <file.xml>: XML output
- -j <file.json>: JSON output
- -v: Verbose
- -f: Ignore failed queries (NXDOMAIN)
- --threads <N>: Multi-thread (max 50)

Common Commands:

1. Basic DNS: dnsrecon -d example.com -t std
   - Gets A, MX, NS, SOA records
2. Subdomain Brute: dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt --threads 10
   - Finds hidden subs (admin.example.com)
3. Zone Transfer: dnsrecon -d example.com -t axfr
   - Checks vulnerable DNS servers
4. SRV Records: dnsrecon -d example.com -t srv
   - Gets service records (\_ldap.\_tcp.example.com)
5. Reverse DNS: dnsrecon -d example.com -t ptr -r 192.168.1.1-192.168.1.100
   - Maps IPs to hostnames
6. TLD Scan: dnsrecon -d example -t tld
   - Finds variants (example.co.uk)
7. Full Scan + Save: dnsrecon -d example.com -t std,axfr,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -x output.xml -v
   - Saves XML for reports

Tips:

- Speed: --threads 20, -f
- Wordlist: /usr/share/seclists/Discovery/DNS/
- OSCP: axfr may get flags
- Alt tools: dig, host, nmap --script dns-brute

---
