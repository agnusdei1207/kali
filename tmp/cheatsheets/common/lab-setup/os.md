# 호스트 정보 수집

- 리눅스 호스트에서 호스트명·사용자(id, sudo -l)·계정 파일(/etc/passwd, /etc/shadow)·네트워크(netstat, route)·서비스·설치 패키지(dpkg)·SUID 파일·환경 변수까지 수집하는 정찰 명령 모음이다.
- 셸을 하나 얻은 초기 침투·권한 상승 단계에서 시스템 정보를 빠짐없이 모을 때 위에서 아래로 순서대로 돌린다.
- 대상 셸 접근이 필요하고 /etc/shadow 읽기, sudo -l·sudo env 확인은 그에 맞는 권한이 있어야 한다. hostname·find·netstat·ss·dpkg 등 기본 유틸만 쓰므로 별도 설치가 없다.

#!/bin/bash

## host

hostname
cat /etc/os-release

## user

id
uname -a
whoami
sudo -l

## other users

cat /etc/passwd
cat /etc/shadow
cat /etc/group

ls -alh
find / -type f -perm -4000 2>/dev/null

## network

arp -a

## arp

ifconfig

## routing table

route -n

## host interative other device

netstat -tulpna

## DNS

cat /etc/resolv.conf

## DNS cache

cat /etc/hosts

## service

systemctl --type=service --state=running

## open ports

ss -ltnp
netstat -tulpna

## package with apt

dpkg --list

## package omit apt

ls -hal /opt

## find config file

find / -type f \( -name "_.conf" -o -name "_.cfg" \) 2>/dev/null

## find log file

find / -type f \( -name "_.log" -o -name "_.log.\*" \) 2>/dev/null

## find SUID

find / -type f -perm -4000 2>/dev/null

## env

env

## env with sudo

sudo env

## export

export

## kubernetes

ls -alh dockerenv
