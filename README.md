<div align="center">
    <img src="https://www.kali.org/images/kali-dragon-icon.svg" alt="Kali Linux Logo" width="150" />
</div>

<div align="center">
    <h1>Penetration Test</h1>
</div>

### Focused on manual penetration techniques in the Kali Linux environment.

---

# Penetration Methodology

1. **Information Gathering**

   - Investigate all areas thoroughly, including network, services, and web (including snooping/sniffing).
   - Obtain key information such as service versions, directory structures, and user details.
   - **Tip**: Organize results in tables, detect changes through repeated scans. Actively use tools like wireshark and tcpdump for network traffic monitoring and packet analysis.

2. **Vulnerability Analysis**

   - Directly verify vulnerabilities based on collected information.
   - Minimize automated tools, focus on manual analysis.
   - Carefully check service configurations, file permissions, authentication, container images, etc.

3. **Privilege Escalation**

   - Explore all GTFO privilege escalation routes.
   - **Tip**: Also check environment variables, PATH, scheduled jobs, backup files, etc.

4. **Lateral Movement**

   - Use obtained credentials/keys to further penetrate the internal network.
   - Use only allowed protocols such as SMB, WinRM, SSH.
   - Reinvestigate internal assets, users, and services, and repeat penetration.
   - **Tip**: Utilize shared folders, network maps, ARP cache, etc.

5. **Evidence Collection**

   - Secure flag files, system information, and screenshots proving vulnerabilities.
   - Organize all evidence by system and document in real time.
   - **Tip**: Record flag location, permissions, and access paths.
