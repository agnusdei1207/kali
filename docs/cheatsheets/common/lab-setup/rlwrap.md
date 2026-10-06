apt install rlwrap

rlwrap nc -lvnp 443
sudo rlwrap nc -lnvp 135

`rlwrap`은 **Readline Wrapper**의 약자로, 터미널 명령어 실행 시 **방향키(↑, ↓, ←, →) 이동, 명령어 기록(History), 자동 완성** 같은 편리한 기능을 제공해 주는 유틸리티 프로그램입니다.

보안 점검이나 모의 해킹(OSCP 등) 시 사용하는 `nc`(Netcat)는 리버스 셸을 받을 때 기본적으로 방향키나 백스페이스가 깨지거나 입력 수정이 매우 불편합니다. 이때 앞에 `rlwrap`을 붙여 실행하면 리눅스 일반 터미널처럼 자유롭게 방향키로 지난 명령어를 꺼내 쓰거나 오타를 수정할 수 있게 됩니다.
