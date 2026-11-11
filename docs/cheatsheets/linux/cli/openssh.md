> 무엇: SSH 클라이언트(openssh-client)와 SSH 서버(openssh-server)를 apt로 설치하는 명령만 모아 둔 최소 메모
> 언제: 공격자 머신에서 ssh·scp로 타깃에 접속할 준비를 하거나, 타깃에 SSH 서비스를 띄워 새 접근로를 만들 때 패키지가 없으면 설치한다
> 조건: Debian/Ubuntu 계열에서 apt를 쓸 수 있어야 하고, 서버 설치 시에는 sshd가 실제로 떠 있는지와 포트 개방 상태를 확인해야 접속된다

sudo apt install openssh-client
sudo apt install openssh-server
