# Hashcat 암호화폐 지갑 해시

- 암호화폐 지갑 파일 크래킹 모음 — Bitcoin wallet.dat(-m 11300), Ethereum PBKDF2(-m 15600)/SCRYPT(-m 15700)/Pre-Sale(-m 16300), Electrum(-m 16600), Blockchain My Wallet(-m 12700)
- 확보한 지갑 파일(wallet.dat·wallet.json)의 마스터 패스워드가 필요할 때. bitcoin2john·ethereum2john으로 먼저 해시 추출
- 지갑 파일 접근 권한과 2john 계열 추출 도구(Python) — scrypt 기반은 GPU 가속이 어렵고 마스터 패스워드는 보통 길어 시간 제한 필수, wallet.dat는 Berkeley DB

## Bitcoin/Litecoin wallet.dat (-m 11300)

```bash
hashcat -m 11300 -a 0 bitcoin.txt wordlist.txt
```

## Ethereum Wallet (PBKDF2-HMAC-SHA256) (-m 15600)

```bash
hashcat -m 15600 -a 0 eth_pbkdf2.txt wordlist.txt
```

## Ethereum Wallet (SCRYPT) (-m 15700)

```bash
hashcat -m 15700 -a 0 eth_scrypt.txt wordlist.txt
```

## Ethereum Pre-Sale Wallet (-m 16300)

```bash
hashcat -m 16300 -a 0 eth_presale.txt wordlist.txt
```

## Electrum Wallet (Salt-Type 1-3) (-m 16600)

```bash
hashcat -m 16600 -a 0 electrum.txt wordlist.txt
```

## Blockchain (My Wallet) (-m 12700)

```bash
hashcat -m 12700 -a 0 blockchain.txt wordlist.txt
```

## 해시 추출

```bash
# Bitcoin
python3 bitcoin2john.py wallet.dat > bitcoin.hash

# Ethereum
python3 ethereum2john.py wallet.json > eth.hash
```

## 팁

- scrypt 기반 지갑은 GPU 가속 어려움
- wallet.dat는 Berkeley DB. 추출 도구 필요
- 시간 제한 두고 시도. 마스터 패스워드는 보통 길고 복잡