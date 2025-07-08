# 1. 필요한 패키지 설치

apt update
apt install -y python3 python3-pip python3-venv build-essential git

# 2. impacket GitHub에서 다운로드

git clone https://github.com/fortra/impacket.git
cd impacket

# 1. 가상환경 생성

python3 -m venv impenv

# impenv 가상화 활성화

source impenv/bin/activate

# 2. pip 업그레이드

pip install --upgrade pip

# 3. impacket 설치

pip install .

# 4. secretsdump.py -> Windows 시스템 또는 Domain Controller에서 암호 해시 추출

python examples/secretsdump.py -h
