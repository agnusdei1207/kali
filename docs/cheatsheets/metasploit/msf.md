# msfconsole -> msf start

> 무엇: msfconsole 기본 조작 — 모듈 검색(search), 대상 지정(set rhosts, setg), datastore 초기화(unset all), 백그라운드 실행(exploit -z, background), 세션 관리(sessions), auxiliary 스캐너(portscan·smb_version·http_version) 구동.
> 언제: msfconsole을 열고 스캐너와 익스플로잇을 연달아 돌릴 때, 특히 rhosts를 setg로 전역 고정해 모듈을 갈아끼울 때.
> 조건: msfconsole이 설치되어 있어야 하고, rhosts에는 단일 IP·범위(10.10.15.10-255)·CIDR(/24) 모두 지정 가능하다.

msfconsole

## options

show options

## set target

set rhosts 10.10.15.10
set rhosts 10.10.15.10 - 10.10.15.255
set rhosts 10.10.15.10/24

## check

show options

## flushing datastore

unset all
unset payload

## set global env across modules

setg

## exploit

## background mode: -z

exploit -z

## background mode -> go to msfconsole as soon as || ctrl+z

background

## session list

sessions

## interacte session

sessions -i 2

## search

search portscan tcp
search portscan

## use

setg rhosts 10.10.148.128
use auxiliary/scanner/portscan/tcp
run

search smb_version
use auxiliary/scanner/smb/smb_version
run

search netbios
use auxiliary/scanner/netbios/nbname
run

search http_version
show options
setg rport 8000
use auxiliary/scanner/http/http_version
run

## back

back
