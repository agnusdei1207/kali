# Hashcat 모드 번호 인덱스 (-m)

검색용. 모드 번호로 해당 파일을 찾는다. `hashcat --example-hashes`로 형식 확인.

## MD5 계열

- 0 MD5 → hash_md5_variants.md
- 10 MD5($pass.$salt) → hash_md5_variants.md
- 20 MD5($salt.$pass) → hash_md5_variants.md
- 30 MD5(unicode($pass).$salt) → hash_md5_variants.md
- 40 MD5($salt.unicode($pass)) → hash_md5_variants.md
- 50 HMAC-MD5 (key=$pass) → hash_hmac.md
- 60 HMAC-MD5 (key=$salt) → hash_hmac.md
- 2600 md5(md5($pass).$salt) → hash_2600_md5_double_salt.md
- 1600 Apache $apr1$ MD5 → hash_md5_variants.md

## SHA1 계열

- 100 SHA1 → hash_sha1_variants.md
- 110 SHA1($pass.$salt) → hash_sha1_variants.md
- 120 SHA1($salt.$pass) → hash_sha1_variants.md
- 130 SHA1(unicode($pass).$salt) → hash_sha1_variants.md
- 140 SHA1($salt.unicode($pass)) → hash_sha1_variants.md
- 150 HMAC-SHA1 (key=$pass) → hash_hmac.md
- 160 HMAC-SHA1 (key=$salt) → hash_hmac.md

## SHA256 계열

- 1400 SHA256 → hash_sha256_variants.md
- 1410 SHA256($pass.$salt) → hash_sha256_variants.md
- 1420 SHA256($salt.$pass) → hash_sha256_variants.md
- 1430 SHA256(unicode($pass).$salt) → hash_sha256_variants.md
- 1440 SHA256($salt.unicode($pass)) → hash_sha256_variants.md
- 1450 HMAC-SHA256 (key=$pass) → hash_hmac.md
- 1460 HMAC-SHA256 (key=$salt) → hash_hmac.md
- 7400 sha256crypt $5$ → hash_sha256_variants.md
- 10000 Django (PBKDF2-SHA256) → hash_web_applications.md
- 10900 PBKDF2-HMAC-SHA256 → hash_sha256_variants.md

## SHA512 계열

- 1700 SHA512 → hash_sha512_variants.md
- 1710 SHA512($pass.$salt) → hash_sha512_variants.md
- 1720 SHA512($salt.$pass) → hash_sha512_variants.md
- 1730 SHA512(unicode($pass).$salt) → hash_sha512_variants.md
- 1740 SHA512($salt.unicode($pass)) → hash_sha512_variants.md
- 1750 HMAC-SHA512 (key=$pass) → hash_hmac.md
- 1760 HMAC-SHA512 (key=$salt) → hash_hmac.md
- 1800 sha512crypt $6$ → hash_linux_crypt.md

## Windows / AD

- 1000 NTLM → hash_ntlm.md
- 1100 Domain Cached Credentials (DCC) → hash_ntlm.md
- 2100 Domain Cached Credentials 2 (DCC2) → hash_ntlm.md
- 5500 NetNTLMv1 → hash_netntlm.md
- 5600 NetNTLMv2 → hash_netntlm.md
- 3000 LM → hash_classic_unix.md
- 900 MD4 → hash_classic_unix.md
- 700? no

## Linux crypt

- 500 md5crypt $1$ → hash_linux_crypt.md
- 7400 sha256crypt $5$ → hash_linux_crypt.md
- 1800 sha512crypt $6$ → hash_linux_crypt.md
- 3200 bcrypt $2*$ → hash_linux_crypt.md
- 1500 descrypt → hash_classic_unix.md
- 12400 BSDi Crypt → hash_classic_unix.md
- 6300 AIX {smd5} → hash_classic_unix.md
- 6400 AIX {ssha256} → hash_classic_unix.md
- 6500 AIX {ssha512} → hash_classic_unix.md

## 웹 애플리케이션

- 400 phpass (WordPress/Drupal/Joomla/phpBB) → hash_web_applications.md
- 11 Joomla → hash_web_applications.md
- 7900 Drupal 7 → hash_web_applications.md
- 10000 Django (PBKDF2-SHA256) → hash_web_applications.md
- 11000 PrestaShop → hash_web_applications.md
- 13900 OpenCart → hash_web_applications.md

## 데이터베이스

- 200 MySQL323 → hash_databases.md
- 300 MySQL4.1/5 → hash_databases.md
- 12 PostgreSQL MD5 → hash_databases.md
- 11100 PostgreSQL Challenge-Response → hash_databases.md
- 131 MSSQL 2005 → hash_databases.md
- 1731 MSSQL 2012+ → hash_databases.md
- 12800 MSSQL 2012, 2014 → hash_databases.md
- 3100 Oracle H: Type → hash_databases.md
- 12300 Oracle T: Type → hash_databases.md
- 8000 Sybase ASE → hash_databases.md

## 네트워크 / 프로토콜

- 7500 Kerberos 5 AS-REQ Pre-Auth etype 23 → hash_network_protocols.md
- 13100 Kerberos 5 TGS-REP etype 23 → hash_network_protocols.md
- 18200 Kerberos 5 AS-REP etype 23 → hash_network_protocols.md
- 22000 WPA-PBKDF2-PMKID+EAPOL → hash_network_protocols.md
- 16800 WPA-PMKID-PBKDF2 → hash_network_protocols.md
- 2500 WPA/WPA2 (legacy) → hash_network_protocols.md
- 11400 SIP digest authentication → hash_network_protocols.md
- 7300 IPMI2 RAKP HMAC-SHA1 → hash_network_protocols.md
- 16100 TACACS+ → hash_network_protocols.md
- 15100 Juniper/NetBSD sha1crypt → hash_network_protocols.md

## 패스워드 매니저

- 13400 KeePass 1/2 → hash_password_managers.md
- 6600 1Password agilekeychain → hash_password_managers.md
- 6700 1Password cloudkeychain → hash_password_managers.md
- 6800 LastPass → hash_password_managers.md
- 16200 Apple Secure Notes → hash_password_managers.md

## 디스크 암호화

- 14600 LUKS → hash_disk_encryption.md
- 13700 VeraCrypt (PBKDF2-HMAC-RIPEMD160 + XTS 512) → hash_disk_encryption.md
- 13711 VeraCrypt boot mode → hash_disk_encryption.md
- 6211 TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 → hash_disk_encryption.md
- 22100 BitLocker → hash_disk_encryption.md
- 18300 Apple FileVault 2 → hash_disk_encryption.md
- 16700 FileVault 2 (PBKDF2) → hash_disk_encryption.md

## 모바일

- 8800 Android FDE <= 4.3 → hash_mobile.md
- 14700 iTunes backup < 10.0 → hash_mobile.md
- 14800 iTunes backup >= 10.0 → hash_mobile.md

## SSH / GPG

- 22911 SSH RSA (old format) → hash_ssh_keys.md
- 22921 SSH DSA → hash_ssh_keys.md
- 22931 SSH ECDSA → hash_ssh_keys.md
- 22941 SSH Ed25519 → hash_ssh_keys.md
- 22951 Putty → hash_ssh_keys.md
- 11700 GPG (OpenPGP) → hash_gpg.md
- 17010 GPG (SHA-256) → hash_gpg.md
- 17020 GPG (SHA-384) → hash_gpg.md
- 17030 GPG (SHA-512) → hash_gpg.md

## 문서 파일

- 10400 PDF 1.1-1.3 → hash_documents.md
- 10500 PDF 1.4-1.6 → hash_documents.md
- 10600 PDF 1.7 Level 3 → hash_documents.md
- 10700 PDF 1.7 Level 8 → hash_documents.md
- 9400 MS Office 2007 → hash_documents.md
- 9500 MS Office 2010 → hash_documents.md
- 9600 MS Office 2013 → hash_documents.md
- 9700 MS Office <= 2003 → hash_documents.md

## Cisco / 네트워크 장비

- 2400 Cisco PIX MD5 → hash_cisco.md
- 2410 Cisco ASA MD5 → hash_cisco.md
- 500 Cisco IOS type 5 (MD5 crypt) → hash_cisco.md
- 9200 Cisco IOS $8$ (PBKDF2-SHA256) → hash_cisco.md
- 9300 Cisco IOS $9$ (scrypt) → hash_cisco.md
- 7000 Fortigate → hash_cisco.md

## HMAC

- 50 HMAC-MD5 (key=$pass) → hash_hmac.md
- 60 HMAC-MD5 (key=$salt) → hash_hmac.md
- 150 HMAC-SHA1 (key=$pass) → hash_hmac.md
- 160 HMAC-SHA1 (key=$salt) → hash_hmac.md
- 1450 HMAC-SHA256 (key=$pass) → hash_hmac.md
- 1460 HMAC-SHA256 (key=$salt) → hash_hmac.md
- 1750 HMAC-SHA512 (key=$pass) → hash_hmac.md
- 1760 HMAC-SHA512 (key=$salt) → hash_hmac.md
- 18100 TOTP (HMAC-SHA1) → hash_hmac.md

## 압축 파일

- 17200 PKZIP (Uncompressed) → archive_cracking.md
- 13600 WinZip (AES) → archive_cracking.md
- 12500 RAR3-hp → archive_cracking.md
- 13000 RAR5 → archive_cracking.md
- 11600 7-Zip → archive_cracking.md
- 15500 PKZIP (Compressed) → archive_cracking.md

## 암호화폐 지갑

- 11300 Bitcoin/Litecoin wallet.dat → hash_cryptocurrency.md
- 15600 Ethereum Wallet (PBKDF2-HMAC-SHA256) → hash_cryptocurrency.md
- 15700 Ethereum Wallet (SCRYPT) → hash_cryptocurrency.md
- 16300 Ethereum Pre-Sale Wallet → hash_cryptocurrency.md
- 16600 Electrum Wallet → hash_cryptocurrency.md
- 12700 Blockchain (My Wallet) → hash_cryptocurrency.md

## 기타

- 16900 Ansible Vault → hash_miscellaneous.md
- 11900 PBKDF2-HMAC-MD5 → hash_miscellaneous.md
- 12000 PBKDF2-HMAC-SHA1 → hash_miscellaneous.md
- 12100 PBKDF2-HMAC-SHA512 → hash_miscellaneous.md
- 10800 SHA384 → hash_miscellaneous.md
- 8900 scrypt → hash_miscellaneous.md
- 14000 DES (PT DES) → hash_miscellaneous.md
- 14100 3DES (PT 3DES) → hash_miscellaneous.md
- 9800 Radmin2 → hash_miscellaneous.md
- 9900 Radmin2 (lowercase) → hash_miscellaneous.md
- 16400 CRAM-MD5 Dovecot → hash_miscellaneous.md
- 15300 DPAPI masterkey v1 → hash_miscellaneous.md
- 15900 DPAPI masterkey v2 → hash_miscellaneous.md
- 14900 Skip32 → hash_miscellaneous.md
- 9000 Password Safe v2 → hash_miscellaneous.md
- 9100 Password Safe v3 → hash_miscellaneous.md
- 12200 eCryptfs → hash_miscellaneous.md
- 15000 FileZilla Server → hash_miscellaneous.md
- 16000 Tripcode → hash_miscellaneous.md
- 11500 CRC32 → hash_miscellaneous.md
- 10100 SipHash → hash_miscellaneous.md
- 8500 RACF → hash_miscellaneous.md
- 13500 PeopleSoft PS_TOKEN → hash_miscellaneous.md

## 팁

- 모드 번호가 정확하지 않으면 `hashcat --example-hashes | grep`으로 확인
- hashid로 1차 식별 후 시험 크래킹으로 확정
- crypt 계열($1$/$5$/$6$)은 salt 반복으로 매우 느림. 시간 제한 두고 시도