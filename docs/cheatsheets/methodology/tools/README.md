# 도구 모음

패키지에 들어가는 도구의 전체 목록은 최종 ZIP의 TOOL_LIST.md에 있다.
여기서는 침투 테스트 단계별로 어떤 도구를 쓰는지만 정리한다. 각 도구의 사용법은 치트시트 폴더에서 찾는다.

## 열거 (Enumeration)

- 네트워크 발견: nmap, masscan, rustscan, arp-scan, netdiscover (recon\network)
- 서브도메인/DNS: amass, subfinder, dnsrecon, dnsx (recon\dns)
- 포트 스캔: naabu, nmap (recon\network)
- 웹 표면: ffuf, gobuster, feroxbuster, dirsearch, katana, httpx (recon\web-surface)
- 웹 취약점 스캔: nuclei, nikto, whatweb, wafw00f, arjun (recon)
- 시크릿 스캔: gitleaks, trufflehog (recon\secrets)
- 스니핑: tcpdump, wireshark, tshark (recon\network, recon\wireshark)

## 웹 공격 (Web Attacks)

- 수동 테스트: Burp Suite (web\burp), curl, httpie (recon\curl, recon\web-surface)
- SQLi: sqlmap (web\sqli)
- XSS: dalfox (web\xss)
- 명령 삽입: commix (web)
- 인증 우회: jwt_tool (web)
- 웹셸: weevely, php_filter_chain_generator (shells\web-shell, web\file-inclusion)

## Active Directory / Windows

- 열거: netexec(nxc), enum4linux-ng, smbmap, smbclient, rpcclient, ldapsearch, kerbrute (active-directory)
- 그래프 수집: BloodHound, SharpHound, bloodhound.py, azurehound (active-directory)
- 인증 강제: PetitPotam, Coercer, responder, mitm6 (active-directory)
- 인증서: Certipy (active-directory)
- 셸 접근: evil-winrm, impacket 스크립트(smbclient.py, wmiexec.py) (windows, active-directory)
- 자격증명: mimikatz, pypykatz, impacket secretsdump (active-directory, python)
- 권한 상승: winPEAS, GodPotato, PrintSpoofer, 포테이토 시리즈 (windows\privileges, active-directory\potatoes)
- 권한 활용: PowerSploit, nishang, Snaffler, ysoserial (active-directory)

## 리눅스

- 권한 상승 점검: linpeas, GTFOBins, sudo/SUID 확인 (linux\privesc)
- 자격증명: hashcat, john (cracking)

## 크래킹

- 해시 식별: hashid (common\crypto)
- 해시 크래킹: hashcat, john, hydra, crunch, cewl (cracking, bruteforce)
- 단어사전: seclists, rockyou, wordlists (cracking\wordlists)

## 피벗 (Pivoting)

- 터널/프록시: chisel, ligolo-ng, sshuttle, socat, plink (pivoting)
- 프록시 체인: proxychains4, mitmproxy (pivoting\proxy)
- VPN: openvpn (common\lab-setup)

## 모바일 / 포렌식

- 모바일: jadx, apktool, MobSF, adb (mobile)
- 메모리 분석: volatility3 (forensics)
- 역분석: ghidra, rizin, dnSpy(.NET) (forensics, windows\tools)
- 디스크/파일: sleuthkit, binwalk, foremost (forensics)
- 컨테이너/아티팩트: trivy (windows\tools)

## 지원 도구

- 데이터/인코딩: CyberChef, jq, exiftool (util)
- Python 도구 환경: venv + wheel 오프라인 설치 (common\lab-setup\python_venv)
- 셸: reverse shell 모음, 셸 업그레이드 (shells)
- 스크립트: nishang, PowerSploit, 커스텀 스크립트 (active-directory, scripts)
