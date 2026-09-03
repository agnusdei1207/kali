### dnsrecon Cheat Sheet

Install (Kali Linux)

```bash
sudo apt update
sudo apt install dnsrecon -y
```

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

```bash
dnsrecon -t brt -d acmeitsupport.thm
dnsrecon -t brt -d acmeitsupport.thm -D /path/to/wordlist.txt
dnsrecon -t brt -d acmeitsupport.thm -o results.json
```
