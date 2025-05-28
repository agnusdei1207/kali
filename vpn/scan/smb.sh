# 1. SMB 포트 열려있는지 확인 (139, 445)
nmap -Pn -p 139,445 <TARGET_IP>                   # SMB 포트 오픈 여부

# 2. SMB 서비스 상세 정보 및 취약점 스캔
nmap -Pn -p 445 --script smb-os-discovery <TARGET_IP>         # OS, 도메인, NetBIOS 등
nmap -Pn -p 445 --script smb-enum-shares <TARGET_IP>          # 공유 목록
nmap -Pn -p 445 --script smb-enum-users <TARGET_IP>           # 사용자 목록
nmap -Pn -p 445 --script smb-vuln-ms17-010 <TARGET_IP>        # 취약점(MS17-010 등)

# 3. NetBIOS 이름, 워크그룹 등 확인
nbtscan <TARGET_IP>                              # NetBIOS 이름, 워크그룹, MAC 등
nmblookup -A <TARGET_IP>                         # NetBIOS 이름 확인

# 4. 공유 목록 확인 (익명/Null 세션)
smbclient -L //<TARGET_IP> -N                    # 공유 목록, Null 세션

# 5. 공유 자원 접근 시도 (익명)
smbclient //<TARGET_IP>/<SHARE> -N               # 공유 폴더 내부 탐색
# 예시: 파일 목록 보기
smbclient //<TARGET_IP>/<SHARE> -N -c "ls"
# 예시: 파일 다운로드
smbclient //<TARGET_IP>/<SHARE> -N -c "get <파일명>"

# 6. 자동화 열거 (enum4linux)
enum4linux -a <TARGET_IP>                        # 사용자, 그룹, 공유, 정책 등 종합 정보

# 7. RPC 기반 정보 수집 (Null 세션)
rpcclient -U "" -N <TARGET_IP> -c "srvinfo"      # 서버 정보
rpcclient -U "" -N <TARGET_IP> -c "enumdomusers" # 도메인 사용자 목록
rpcclient -U "" -N <TARGET_IP> -c "enumdomgroups"# 도메인 그룹 목록
rpcclient -U "" -N <TARGET_IP> -c "querydispinfo"# SID→사용자 매핑
rpcclient -U "" -N <TARGET_IP> -c "getdompwinfo" # 패스워드 정책

# 8. SMBMap/CrackMapExec 등으로 권한/공유/취약점 확인
smbmap -H <TARGET_IP>                            # 공유, 권한, 읽기/쓰기 여부
crackmapexec smb <TARGET_IP> --shares            # 공유 목록
crackmapexec smb <TARGET_IP> --users             # 사용자 목록
crackmapexec smb <TARGET_IP> --pass-pol          # 패스워드 정책
crackmapexec smb <TARGET_IP> --check-vulns       # 취약점 진단

# 9. 계정이 있을 경우 인증 시도
smbclient //<TARGET_IP>/<SHARE> -U <USER>        # 계정으로 접근
crackmapexec smb <TARGET_IP> -u <USER> -p <PASS> # 인증 및 권한 확인

# 10. 결과 분석 후, 파일 다운로드/업로드, 추가 정보 수집 등
# 예시: smbclient로 파일 다운로드
smbclient //<TARGET_IP>/<SHARE> -N -c "get <파일명>"

# <TARGET_IP>, <SHARE>, <USER>, <PASS> 등은 실제 환경에 맞게 변경