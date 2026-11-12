# Active Directory

AD 열거·공격 문서 폴더. 진단 순서는 methodology/enumeration, 도구 배치는 methodology/tools를 함께 본다.

## 열거

- `enum4linux.md` NetBIOS·SMB·LDAP 일괄 열거 (enum4linux-ng)
- `rpcclient.md` RPC를 통한 사용자·그룹·도메인 정보 질의
- `ldapsearch.md` LDAP 질의로 사용자·그룹·ACL 확인
- `kerbrute.md` 사용자명·패스워드 스프레이 (4768/4771 이벤트 주의)
- `nxc.md` netexec — SMB·WinRM·MSSQL·LDAP 일괄 실행, SAM·LSA·NTDS 덤프
- `crackmapexec.md` netexec의 구형 명칭 문서
- `smb/` SMB 상세 — smbclient, smbmap, rpcdump
- `smb/theory/` SMB 포트·협상 이론, NTLM 릴레이 이론

## 그래프 수집

- `bloodhound.md` BloodHound 데이터 수집·활용
- `azurehound.md` Azure·온프레임 통합 그래프 수집

## 인증 공격

- `responder.md` LLMNR·NBT-NS 포이즈닝, 해시 수집(hashcat 5600 연계)
- `mitm6.md` DHCPv6·DNS 스푸핑, IPv6 릴레이
- `coercer.md` 인증 강제 프레임워크 (scan·coerce·fuzz 모드)
- `petitpotam.md` PetitPotam 인증 강제
- `potatoes.md` 포테이토 시리즈 개요 — GodPotato·JuicyPotato·RoguePotato 등
- `windows/privileges/PrintSpoofer.md` PrintSpoofer 권한 상승 (windows 쪽 문서)

## 인증서·자격증명

- `certipy.md` AD CS 열거·공격 (Esc1~Esc8)
- `impacket.md` impacket 스크립트 세트 — smbexec·psexec·secretsdump 등
- `mimikatz.md` LSASS 덤프·자격증명 추출

## 공유·시크릿 수집

- `snaffler.md` SMB 공유 시크릿 수집

## 스크립트 프레임워크

- `nishang.md` PowerShell 공격·지원 스크립트 모음
- `powersploit.md` PowerSploit — 권한 상승·정보수집 모듈
- `ysoserial.md` .NET 역직렬화 페이로드 생성 (ViewState 포함)
