# enum4linux-ng로 AD/RPC 열거

- enum4linux — rpcclient·smbclient·nmblookup을 묶어 사용자·그룹·공유·패스워드 정책·OS 정보를 한 번에 열거하는 도구. 구버전 enum4linux는 유지보수가 끊겼고 Python으로 재작성된 enum4linux-ng를 쓴다.
- 도메인 컨트롤러·Windows 호스트 열거 초기 단계에서 사용자 목록(RID)·공유·패스워드 정책을 한 번에 수집할 때, 자격증명 유무에 따라 무엇이 열리는지 비교할 때.
- Kali면 apt install enum4linux-ng. 내부적으로 samba 도구(rpcclient, smbclient, nmblookup)와 impacket, ldap3, PyYaml에 의존한다.

## 설치와 기본 구조

```bash
sudo apt install enum4linux-ng
enum4linux-ng -A 10.10.10.10 -oY out
enum4linux-ng 10.10.10.10 -u user -p 'Passw0rd' -oY out
```

- `-A`: -U -G -S -P -O -N -I -L을 묶어 실행한다(사용자·그룹·공유·패스워드 정책·OS·NetBIOS·프린터·LDAP 도메인 정보).
- `-As`: NetBIOS 이름 조회(-N)를 뺀 축약판. 도메인 컨트롤러가 아닌 멤버 서버에 쓴다.
- 옵션을 아무것도 주지 않으면 -A가 기본 동작이다.

## 개별 열거 옵션

```bash
enum4linux-ng -U 10.10.10.10       # 사용자 목록(RID 포함)
enum4linux-ng -S 10.10.10.10       # 공유 목록
enum4linux-ng -G 10.10.10.10       # 그룹 목록(-Gm은 그룹 멤버까지)
enum4linux-ng -P 10.10.10.10       # 패스워드 정책(최소 길이·잠금 임계값)
enum4linux-ng -L 10.10.10.10       # LDAP로 추가 도메인 정보(DC 한정)
enum4linux-ng -C 10.10.10.10       # 서비스 정보
```

- `-d`: -U/-G/-R에 상세 정보(설명 필드, 마지막 로그온 등)를 붙인다.
- `-R -r 500-1100`: RID cycling으로 계정을 추측한다. 열거가 막혔을 때 쓰는 보조 수단이다.
- `-H <nthash>`, `-K <ticket>`: NT 해시, Kerberos 티켓(ccache/kirbi) 인증도 지원한다. `--local-auth`는 로컬 계정으로 인증한다.

## 실전 예시

```bash
# 자격증명 있을 때 상세 사용자 정보까지
enum4linux-ng 10.10.10.10 -u Tester -p 'Start123!' -U -d -oY out

# RID cycling으로 숨은 계정 찾기
enum4linux-ng 10.10.10.10 -u Tester -p 'Start123!' -R -r 500-1100

# 서비스·프린터 정보 추가 조회
enum4linux-ng 10.10.10.10 -A -C -I
```

- 결과 YAML은 users/groups/shares/password_policy 섹션으로 정리되며, kerbrute 워드리스트와 smbmap 대상 목록의 입력이 된다.

## 팁·트러블슈팅

1. 결과가 거의 비면(NT_STATUS_ACCESS_DENIED) 익명 열거가 막힌 것이고, 유효 계정으로 재시도하거나 kerbrute userenum으로 전환한다.
2. LDAP 관련 항목은 대상이 DC일 때만 채워지고 그 외에는 스킵되므로, 결과가 비어 있다고 오답 처리하지 않는다.
3. 구버전 enum4linux와 출력 형식·-A 포함 범위가 다르므로, 온라인 참고 자료를 쓸 때 도구 버전을 먼저 확인한다.
