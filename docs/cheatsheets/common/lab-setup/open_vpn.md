# connect

openvpn --config /vpn/test.ovpn --daemon

# terminate

sudo killall openvpn
sudo killall -9 openvpn
sudo kill -9 processID
sudo pkill -9 openvpn

apt update
apt install -y procps

ps aux | grep openvpn

pkill -f openvpn
