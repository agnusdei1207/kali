# Hashcat 네트워크 프로토콜 해시

Kerberos, WPA, SIP, IPMI, TACACS+ 등.

## Kerberos

```bash
# Kerberos 5 AS-REQ Pre-Auth etype 23 -m 7500
hashcat -m 7500 -a 0 kerberos_asreq.txt wordlist.txt

# Kerberos 5 TGS-REP etype 23 -m 13100
hashcat -m 13100 -a 0 tgs_rep.txt wordlist.txt

# Kerberos 5 AS-REP etype 23 -m 18200
hashcat -m 18200 -a 0 asrep.txt wordlist.txt
```

## WPA/WPA2

```bash
# WPA2 핸드셰이크 (hc22000) -m 22000
hashcat -m 22000 -a 0 capture.hc22000 wordlist.txt

# PMKID -m 16800
hashcat -m 16800 -a 0 pmkid.txt wordlist.txt

# 구버전 WPA -m 2500 (deprecated)
hashcat -m 2500 -a 0 wpa.hccapx wordlist.txt
```

## WPA 캡처 변환

```bash
# cap -> hc22000
hcxpcapngtool -o capture.hc22000 capture.cap

# hccapx -> hc22000
# (구버전) hccap2john, hashcat-utils
```

## SIP digest authentication (-m 11400)

```bash
hashcat -m 11400 -a 0 sip.txt wordlist.txt
```

## IPMI2 RAKP HMAC-SHA1 (-m 7300)

```bash
hashcat -m 7300 -a 0 ipmi.txt wordlist.txt
```

## TACACS+ (-m 16100)

```bash
hashcat -m 16100 -a 0 tacacs.txt wordlist.txt
```

## Juniper/NetBSD sha1crypt (-m 15100)

```bash
hashcat -m 15100 -a 0 juniper.txt wordlist.txt
```

## 팁

- Kerberos TGS-REP (Kerberoasting)은 salt = SPN. 사전 공격 효과적
- AS-REP Roasting은 사전 인증 비활성 계정 대상
- WPA는 PMKID 방식이 핸드셰이크 캡처보다 쉬움 (클라이언트 불필요)