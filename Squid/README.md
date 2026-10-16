docker cp universal.ovpn kali:/

apt install openvpn
openvpn --config /universal.ovpn --daemon

apt install procps
ps aux | grep openvpn

apt install iproute2
ip a | grep tun

#
