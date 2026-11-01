# Hashcat 인덱스: 시나리오별

## CTF / 랩

- 압축 파일 → hashes/archive? `archive_cracking.md` (루트), `hashes/hash_documents.md`
- 웹앱 DB 해시 → `hashes/hash_web_applications.md`, `hashes/hash_databases.md`
- Linux shadow → `hashes/hash_linux_crypt.md`, `hashes/hash_classic_unix.md`
- Windows 해시 → `hashes/hash_ntlm.md`, `hashes/hash_netntlm.md`

## Active Directory / 내부망

- NTLM → `hashes/hash_ntlm.md`
- NetNTLMv2 (Responder) → `hashes/hash_netntlm.md`
- Kerberoasting (TGS-REP) → `hashes/hash_network_protocols.md` (-m 13100)
- AS-REP Roasting → `hashes/hash_network_protocols.md` (-m 18200)
- DCC/DCC2 → `hashes/hash_ntlm.md`

## WiFi

- WPA2 핸드셰이크/PMKID → `hashes/hash_network_protocols.md` (-m 22000, 16800)

## 디스크 / 파일

- LUKS/VeraCrypt/BitLocker/FileVault → `hashes/hash_disk_encryption.md`
- SSH 키 → `hashes/hash_ssh_keys.md`
- GPG → `hashes/hash_gpg.md`
- PDF/Office → `hashes/hash_documents.md`

## 패스워드 매니저

- KeePass/1Password/LastPass → `hashes/hash_password_managers.md`

## 암호화폐

- Bitcoin/Ethereum/Electrum → `hashes/hash_cryptocurrency.md`

## 네트워크 장비

- Cisco/Fortigate → `hashes/hash_cisco.md`