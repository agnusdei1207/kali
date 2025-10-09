#### Installation (Kali Linux)

Check if installed: `dnsrecon --version`  
If not, install:

```bash
sudo apt update
sudo apt install dnsrecon -y
```

- Verify: `dnsrecon -h`
- Dependencies: `python3`, `python3-dnspython` (auto-installed)
- Time: ~30s

#### Usage

Basic format: `dnsrecon [options] -d <domain>`

#### Options

| Option            | Description                                                                                    | Type                     |
| ----------------- | ---------------------------------------------------------------------------------------------- | ------------------------ |
| `-d <domain>`     | Target domain (e.g., example.com)                                                              | String                   |
| `-t <type>`       | Test type: std, axfr, brt, srv, tld, ptr, cache, rpz                                           | String (comma-separated) |
| `-D <dict>`       | Wordlist for brute force (e.g., /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt) | File path                |
| `-n <nameserver>` | Specify NS server (e.g., 8.8.8.8)                                                              | IP/Host                  |
| `-r <from-to>`    | IP range (e.g., 192.168.1.1-192.168.1.100)                                                     | IP range                 |
| `-x <file.xml>`   | Save output as XML                                                                             | File path                |
| `-j <file.json>`  | Save output as JSON                                                                            | File path                |
| `-v`              | Verbose mode                                                                                   | Flag                     |
| `-f`              | Ignore failed queries (e.g., NXDOMAIN)                                                         | Flag                     |
| `--threads <N>`   | Multi-threading (max 50)                                                                       | Integer                  |

#### Common Commands

1. **Basic DNS Enumeration**:

   ```bash:disable-run
   dnsrecon -d example.com -t std
   ```

   - Finds: A, MX, NS, SOA records

2. **Subdomain Brute Force**:

   ```bash
   dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt --threads 10
   ```

   - Finds: Hidden subdomains (e.g., admin.example.com)

3. **Zone Transfer Test**:

   ```bash
   dnsrecon -d example.com -t axfr
   ```

   - Tests: Vulnerable DNS servers

4. **SRV Record Enumeration**:

   ```bash
   dnsrecon -d example.com -t srv
   ```

   - Finds: Service records (e.g., \_ldap.\_tcp.example.com)

5. **Reverse DNS Lookup**:

   ```bash
   dnsrecon -d example.com -t ptr -r 192.168.1.1-192.168.1.100
   ```

   - Maps: IPs to hostnames

6. **TLD Expansion**:

   ```bash
   dnsrecon -d example -t tld
   ```

   - Finds: Domain variants (e.g., example.co.uk)

7. **Full Scan + Save Output**:
   ```bash
   dnsrecon -d example.com -t std,axfr,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -x output.xml -v
   ```
   - Saves: Results in XML for reporting

#### Tips

- Speed: Use `--threads 20`, `-f`
- Wordlist: `/usr/share/seclists/Discovery/DNS/`
- OSCP: Zone transfer (`axfr`) may yield flags
- Alternatives: `dig`, `host`, `nmap --script dns-brute`

```

```
