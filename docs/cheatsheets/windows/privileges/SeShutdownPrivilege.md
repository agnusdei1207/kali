# SeShutdownPrivilege

- SeShutdownPrivilege — 시스템 종료·재부팅을 수행할 수 있는 특권. whoami /priv 목록에서 종종 보이지만 단독으로 권한 상승으로 이어지지 않는다.
- 특권 목록 점검 시 "상승 경로가 아니다"라고 판정해 넘어가고, 재부팅이 필요한 공격의 마무리 단계(shutdown /r 트리거)로만 활용한다.
- 종료·재부팅을 실제로 하려면 State가 Enabled여야 한다. Disabled면 그마저도 불가능하다.

## 확인

```powershell
whoami /priv
# SeShutdownPrivilege   Shut down the system   Disabled
whoami /priv | findstr /i "Shutdown"
```

## 판정

```text
역할        시스템 종료·재부팅 수행
공격 가치   단독 권한 상승 없음
활용        재부팅이 트리거인 공격의 마무리 단계
Enabled     shutdown /r /t 0 실행 가능
Disabled    종료·재부팅 불가 (DoS도 불가)
```

- Enabled여도 시스템을 내려버리는 것은 상승이 아니라 가용성 공격(DoS)에 가깝다. 점검·실습 목적에서는 상승 경로에서 제외한다.

## 재부팅이 트리거인 공격에서의 활용

```text
utilman(접근성) 교체 공격의 흐름
1. 시스템 파티션 마운트 (SeBackup 등으로 파일 접근 확보)
2. C:\Windows\System32\utilman.exe 교체
3. 재부팅 -> 로그인 화면에서 접근성 버튼 -> 교체된 프로그램 실행
4. 마무리: shutdown /r /t 0 로 시스템 재시작

shutdown /r /t 0      즉시 재부팅
shutdown /s /t 0      즉시 종료
shutdown /a           예약된 종료 취소
shutdown /r /t 60 /c "msg"  60초 후 재부팅 + 메시지
```

- 이 특권이 Enabled인 세션에서만 shutdown 명령이 권한 오류 없이 동작한다. Disabled면 Administrators로 다시 셸을 열거나 다른 특권 경로로 전환한다.

## 관련 특권과 구분

```text
SeShutdownPrivilege   종료·재부팅만 가능 (상승 아님)
SeRemoteShutdownPrivilege  원격(네트워크 경유) 종료 권한 — 도메인 정책 쪽 설정
```

## 트러블슈팅

- `shutdown /r`이 "Access denied"로 실패하면 현재 토큰에 이 특권이 없거나 Disabled다. 다른 세션·특권 상승 후 재시도한다.
- 특권 목록 점검 시 SeShutdown이 보인다고 포테이토·덤프 계열 도구를 시험하는 실수를 하지 않는다. 상승 특권은 SeImpersonate·SeDebug·SeBackup 등으로 한정된다.
- 공유 폴더·설정 변경이 재부팅을 필요로 하는 경우(레지스트리·서비스 설정 등)만 이 특권이 의미 있다. 그때 shutdown /r /t 0을 쓴다.
