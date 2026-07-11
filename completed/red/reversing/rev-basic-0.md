
agnus@pf MINGW64 /c/workspace/study (main)
$ winpty docker run -it --name dreamhack_env ubuntu:26.04 //bin/bash
root@c627f2c198f6:/# ls
bin   dev  home  lib64  mnt  proc  run   srv  tmp  var
boot  etc  lib   media  opt  root  sbin  sys  usr
root@c627f2c198f6:/# cd tmp
root@c627f2c198f6:/tmp# ls
rev-basic-0
root@c627f2c198f6:/tmp# apt update
Get:1 http://security.ubuntu.com/ubuntu resolute-security InRelease [137 k
B]
Get:2 http://archive.ubuntu.com/ubuntu resolute InRelease [136 kB]
Get:3 http://security.ubuntu.com/ubuntu resolute-security/restricted amd64
 Packages [297 kB]
Get:4 http://archive.ubuntu.com/ubuntu resolute-updates InRelease [137 kB]
Get:5 http://security.ubuntu.com/ubuntu resolute-security/main amd64 Packa
ges [335 kB]
Get:6 http://security.ubuntu.com/ubuntu resolute-security/universe amd64 P
ackages [160 kB]
Get:7 http://archive.ubuntu.com/ubuntu resolute-backports InRelease [136 k
B]
Get:8 http://archive.ubuntu.com/ubuntu resolute/multiverse amd64 Packages
[352 kB]
Get:9 http://archive.ubuntu.com/ubuntu resolute/restricted amd64 Packages
[189 kB]
Get:10 http://archive.ubuntu.com/ubuntu resolute/universe amd64 Packages [
20.1 MB]
Get:11 http://archive.ubuntu.com/ubuntu resolute/main amd64 Packages [1874
 kB]
Get:12 http://archive.ubuntu.com/ubuntu resolute-updates/universe amd64 Pa
ckages [251 kB]
Get:13 http://archive.ubuntu.com/ubuntu resolute-updates/restricted amd64
Packages [306 kB]
Get:14 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 Packag
es [407 kB]
Get:15 http://archive.ubuntu.com/ubuntu resolute-updates/multiverse amd64
Packages [3584 B]
Fetched 24.8 MB in 7s (3556 kB/s)
3 packages can be upgraded. Run 'apt list --upgradable' to see them.
root@c627f2c198f6:/tmp# apt upgrade -y
Upgrading:
  gzip  libgcrypt20  tar

Summary:
  Upgrading: 3, Installing: 0, Removing: 0, Not Upgrading: 0
  Download size: 1034 kB
  Space needed: 3072 B / 994 GB available

Get:1 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 gzip am
d64 1.14-1~exp2ubuntu1.1 [106 kB]
Get:2 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 tar amd
64 1.35+dfsg-4ubuntu0.2 [258 kB]
Get:3 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libgcry
pt20 amd64 1.12.0-2ubuntu1 [671 kB]
Fetched 1034 kB in 2s (522 kB/s)    
debconf: unable to initialize frontend: Dialog
debconf: (No usable dialog-like program is installed, so the dialog based
frontend cannot be used. at /usr/share/perl5/Debconf/FrontEnd/Dialog.pm li
ne 79, <STDIN> line 3.)
debconf: falling back to frontend: Readline
debconf: unable to initialize frontend: Readline
debconf: (Can't locate Term/ReadLine.pm in @INC (you may need to install t
he Term::ReadLine module) (@INC entries checked: /etc/perl /usr/local/lib/
x86_64-linux-gnu/perl/5.40.1 /usr/local/share/perl/5.40.1 /usr/lib/x86_64-
linux-gnu/perl5/5.40 /usr/share/perl5 /usr/lib/x86_64-linux-gnu/perl-base
/usr/lib/x86_64-linux-gnu/perl/5.40 /usr/share/perl/5.40 /usr/local/lib/si
te_perl) at /usr/share/perl5/Debconf/FrontEnd/Readline.pm line 8, <STDIN>
line 3.)
debconf: falling back to frontend: Teletype
(Reading database ... 7724 files and directories currently installed.)
Preparing to unpack .../gzip_1.14-1~exp2ubuntu1.1_amd64.deb ...
Unpacking gzip (1.14-1~exp2ubuntu1.1) over (1.14-1~exp2ubuntu1) ...
Setting up gzip (1.14-1~exp2ubuntu1.1) ...
(Reading database ... 7724 files and directories currently installed.)
Preparing to unpack .../tar_1.35+dfsg-4ubuntu0.2_amd64.deb ...
Unpacking tar (1.35+dfsg-4ubuntu0.2) over (1.35+dfsg-4ubuntu0.1) ...
Setting up tar (1.35+dfsg-4ubuntu0.2) ...
(Reading database ... 7724 files and directories currently installed.)
Preparing to unpack .../libgcrypt20_1.12.0-2ubuntu1_amd64.deb ...
Unpacking libgcrypt20:amd64 (1.12.0-2ubuntu1) over (1.12.0-2ubuntu0.1) ...
Setting up libgcrypt20:amd64 (1.12.0-2ubuntu1) ...
Processing triggers for libc-bin (2.43-2ubuntu2) ...
root@c627f2c198f6:/tmp# sudo apt install binutils gdb
bash: sudo: command not found
root@c627f2c198f6:/tmp# apt install binutils gdb
Installing:
  binutils  gdb

Installing dependencies:
  binutils-common            libldap2
  binutils-x86-64-linux-gnu  libmpfr6
  ca-certificates            libnettle8t64
  krb5-locales               libnghttp2-14
  libatomic1                 libp11-kit0
  libbabeltrace1             libpsl5t64
  libbinutils                libpython3.14
  libbrotli1                 libpython3.14-minimal
  libc6-dbg                  libpython3.14-stdlib
  libctf-nobfd0              libreadline8t64
  libctf0                    librtmp1
  libcurl3t64-gnutls         libsasl2-2
  libdebuginfod-common       libsasl2-modules
  libdebuginfod1t64          libsasl2-modules-db
  libdw1t64                  libsframe3
  libelf1t64                 libsource-highlight-common
  libexpat1                  libsource-highlight4t64
  libffi8                    libsqlite3-0
  libglib2.0-0t64            libssh2-1t64
  libglib2.0-data            libtasn1-6
  libgnutls30t64             libtext-charwidth-perl
  libgprofng0                libtext-wrapi18n-perl
  libgssapi-krb5-2           libunistring5
  libhogweed6t64             libxml2-16
  libidn2-0                  media-types
  libipt2                    netbase
  libjansson4                openssl
  libjson-c5                 publicsuffix
  libk5crypto3               readline-common
  libkeyutils1               shared-mime-info
  libkrb5-3                  tzdata
  libkrb5support0            ucf
  libldap-common             xdg-user-dirs

Suggested packages:
  binutils-doc        krb5-user
  gprofng-gui         libsasl2-modules-gssapi-mit
  binutils-gold       | libsasl2-modules-gssapi-heimdal
  gdb-doc             libsasl2-modules-ldap
  gdbserver           libsasl2-modules-otp
  low-memory-monitor  libsasl2-modules-sql
  gnutls-bin          readline-doc
  krb5-doc

Summary:
  Upgrading: 0, Installing: 68, Removing: 0, Not Upgrading: 0
  Download size: 31.4 MB
  Space needed: 96.8 MB / 994 GB available

Continue? [Y/n]
Get:1 http://archive.ubuntu.com/ubuntu resolute/main amd64 libexpat1 amd64
 2.7.4-1 [94.0 kB]
Get:2 http://archive.ubuntu.com/ubuntu resolute/main amd64 libtext-charwid
th-perl amd64 0.04-11build4 [9530 B]
Get:3 http://archive.ubuntu.com/ubuntu resolute/main amd64 libtext-wrapi18
n-perl all 0.06-10 [7694 B]
Get:4 http://archive.ubuntu.com/ubuntu resolute/main amd64 ucf all 3.0052u
buntu1 [44.3 kB]
Get:5 http://archive.ubuntu.com/ubuntu resolute/main amd64 libdebuginfod-c
ommon all 0.194-4 [12.3 kB]
Get:6 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 openssl
 amd64 3.5.5-1ubuntu3.2 [1243 kB]
Get:7 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 ca-cert
ificates all 20260601~26.04.1 [139 kB]
Get:8 http://archive.ubuntu.com/ubuntu resolute/main amd64 krb5-locales al
l 1.22.1-2ubuntu4 [13.4 kB]
Get:9 http://archive.ubuntu.com/ubuntu resolute/main amd64 libatomic1 amd6
4 16-20260322-1ubuntu1 [11.4 kB]
Get:10 http://archive.ubuntu.com/ubuntu resolute/main amd64 libelf1t64 amd
64 0.194-4 [57.1 kB]
Get:11 http://archive.ubuntu.com/ubuntu resolute/main amd64 libffi8 amd64
3.5.2-4 [26.3 kB]
Get:12 http://archive.ubuntu.com/ubuntu resolute/main amd64 libglib2.0-0t6
4 amd64 2.88.0-1 [1597 kB]
Get:13 http://archive.ubuntu.com/ubuntu resolute/main amd64 libglib2.0-dat
a all 2.88.0-1 [37.8 kB]
Get:14 http://archive.ubuntu.com/ubuntu resolute/main amd64 libnettle8t64
amd64 3.10.2-1 [185 kB]
Get:15 http://archive.ubuntu.com/ubuntu resolute/main amd64 libhogweed6t64
 amd64 3.10.2-1 [201 kB]
Get:16 http://archive.ubuntu.com/ubuntu resolute/main amd64 libunistring5
amd64 1.3-2build1 [610 kB]
Get:17 http://archive.ubuntu.com/ubuntu resolute/main amd64 libidn2-0 amd6
4 2.3.8-4build1 [67.6 kB]
Get:18 http://archive.ubuntu.com/ubuntu resolute/main amd64 libp11-kit0 am
d64 0.26.2-2 [313 kB]
Get:19 http://archive.ubuntu.com/ubuntu resolute/main amd64 libtasn1-6 amd
64 4.21.0-2 [45.3 kB]
Get:20 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libgnu
tls30t64 amd64 3.8.12-2ubuntu1.1 [1029 kB]
Get:21 http://archive.ubuntu.com/ubuntu resolute/main amd64 libkrb5support
0 amd64 1.22.1-2ubuntu4 [33.3 kB]
Get:22 http://archive.ubuntu.com/ubuntu resolute/main amd64 libk5crypto3 a
md64 1.22.1-2ubuntu4 [82.0 kB]
Get:23 http://archive.ubuntu.com/ubuntu resolute/main amd64 libkeyutils1 a
md64 1.6.3-6ubuntu3 [10.6 kB]
Get:24 http://archive.ubuntu.com/ubuntu resolute/main amd64 libkrb5-3 amd6
4 1.22.1-2ubuntu4 [361 kB]
Get:25 http://archive.ubuntu.com/ubuntu resolute/main amd64 libgssapi-krb5
-2 amd64 1.22.1-2ubuntu4 [147 kB]
Get:26 http://archive.ubuntu.com/ubuntu resolute/main amd64 libjson-c5 amd
64 0.18+ds-3 [35.9 kB]
Get:27 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libpyt
hon3.14-minimal amd64 3.14.4-1ubuntu0.1 [916 kB]
Get:28 http://archive.ubuntu.com/ubuntu resolute/main amd64 media-types al
l 14.0.0build1 [31.4 kB]
Get:29 http://archive.ubuntu.com/ubuntu resolute/main amd64 netbase all 6.
5build1 [13.0 kB]
Get:30 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 tzdata
 all 2026b-0ubuntu0.26.04.1 [194 kB]
Get:31 http://archive.ubuntu.com/ubuntu resolute/main amd64 readline-commo
n all 8.3-4 [61.5 kB]
Get:32 http://archive.ubuntu.com/ubuntu resolute/main amd64 libreadline8t6
4 amd64 8.3-4 [164 kB]
Get:33 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libsql
ite3-0 amd64 3.46.1-9ubuntu0.1 [719 kB]
Get:34 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libpyt
hon3.14-stdlib amd64 3.14.4-1ubuntu0.1 [2414 kB]
Get:35 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libxml
2-16 amd64 2.15.2+dfsg-0.1ubuntu0.1 [606 kB]
Get:36 http://archive.ubuntu.com/ubuntu resolute/main amd64 shared-mime-in
fo amd64 2.4-5build3 [476 kB]
Get:37 http://archive.ubuntu.com/ubuntu resolute/main amd64 xdg-user-dirs
amd64 0.19-1 [19.3 kB]
Get:38 http://archive.ubuntu.com/ubuntu resolute/main amd64 libjansson4 am
d64 2.14-2build4 [33.2 kB]
Get:39 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libngh
ttp2-14 amd64 1.68.0-2ubuntu0.2 [71.0 kB]
Get:40 http://archive.ubuntu.com/ubuntu resolute/main amd64 libpsl5t64 amd
64 0.21.2-1.1build2 [59.5 kB]
Get:41 http://archive.ubuntu.com/ubuntu resolute/main amd64 publicsuffix a
ll 20260129.1928-1 [139 kB]
Get:42 http://archive.ubuntu.com/ubuntu resolute/main amd64 libsframe3 amd
64 2.46-3ubuntu2 [20.6 kB]
Get:43 http://archive.ubuntu.com/ubuntu resolute/main amd64 binutils-commo
n amd64 2.46-3ubuntu2 [222 kB]
Get:44 http://archive.ubuntu.com/ubuntu resolute/main amd64 libbinutils am
d64 2.46-3ubuntu2 [602 kB]
Get:45 http://archive.ubuntu.com/ubuntu resolute/main amd64 libgprofng0 am
d64 2.46-3ubuntu2 [898 kB]
Get:46 http://archive.ubuntu.com/ubuntu resolute/main amd64 libctf-nobfd0
amd64 2.46-3ubuntu2 [102 kB]
Get:47 http://archive.ubuntu.com/ubuntu resolute/main amd64 libctf0 amd64
2.46-3ubuntu2 [100 kB]
Get:48 http://archive.ubuntu.com/ubuntu resolute/main amd64 binutils-x86-6
4-linux-gnu amd64 2.46-3ubuntu2 [1150 kB]
Get:49 http://archive.ubuntu.com/ubuntu resolute/main amd64 binutils amd64
 2.46-3ubuntu2 [225 kB]
Get:50 http://archive.ubuntu.com/ubuntu resolute/main amd64 libdw1t64 amd6
4 0.194-4 [285 kB]
Get:51 http://archive.ubuntu.com/ubuntu resolute/main amd64 libbabeltrace1
 amd64 1.5.11-5build1 [165 kB]
Get:52 http://archive.ubuntu.com/ubuntu resolute/main amd64 libbrotli1 amd
64 1.2.0-3build1 [343 kB]
Get:53 http://archive.ubuntu.com/ubuntu resolute/main amd64 libsasl2-modul
es-db amd64 2.1.28+dfsg1-9ubuntu3 [21.1 kB]
Get:54 http://archive.ubuntu.com/ubuntu resolute/main amd64 libsasl2-2 amd
64 2.1.28+dfsg1-9ubuntu3 [54.0 kB]
Get:55 http://archive.ubuntu.com/ubuntu resolute/main amd64 libldap-common
 all 2.6.10+dfsg-1ubuntu5 [36.0 kB]
Get:56 http://archive.ubuntu.com/ubuntu resolute/main amd64 libldap2 amd64
 2.6.10+dfsg-1ubuntu5 [204 kB]
Get:57 http://archive.ubuntu.com/ubuntu resolute/main amd64 librtmp1 amd64
 2.4+20151223.gitfa8646d.1-3 [59.0 kB]
Get:58 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libssh
2-1t64 amd64 1.11.1-1ubuntu0.26.04.2 [137 kB]
Get:59 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libcur
l3t64-gnutls amd64 8.18.0-1ubuntu2.3 [417 kB]
Get:60 http://archive.ubuntu.com/ubuntu resolute/main amd64 libdebuginfod1
t64 amd64 0.194-4 [20.7 kB]
Get:61 http://archive.ubuntu.com/ubuntu resolute/main amd64 libipt2 amd64
2.1.2-3 [49.2 kB]
Get:62 http://archive.ubuntu.com/ubuntu resolute/main amd64 libmpfr6 amd64
 4.2.2-3 [361 kB]
Get:63 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 libpyt
hon3.14 amd64 3.14.4-1ubuntu0.1 [2579 kB]
Get:64 http://archive.ubuntu.com/ubuntu resolute/main amd64 libsource-high
light-common all 3.1.9-4.3build2 [64.2 kB]
Get:65 http://archive.ubuntu.com/ubuntu resolute/main amd64 libsource-high
light4t64 amd64 3.1.9-4.3build2 [273 kB]
Get:66 http://archive.ubuntu.com/ubuntu resolute/main amd64 gdb amd64 17.1
-2ubuntu1 [4173 kB]
Get:67 http://archive.ubuntu.com/ubuntu resolute/main amd64 libsasl2-modul
es amd64 2.1.28+dfsg1-9ubuntu3 [71.3 kB]
Get:68 http://archive.ubuntu.com/ubuntu resolute/main amd64 libc6-dbg amd6
4 2.43-2ubuntu2 [6411 kB]
Fetched 31.4 MB in 9s (3516 kB/s)
debconf: unable to initialize frontend: Dialog
debconf: (No usable dialog-like program is installed, so the dialog based
frontend cannot be used. at /usr/share/perl5/Debconf/FrontEnd/Dialog.pm li
ne 79, <STDIN> line 68.)
debconf: falling back to frontend: Readline
debconf: unable to initialize frontend: Readline
debconf: (Can't locate Term/ReadLine.pm in @INC (you may need to install t
he Term::ReadLine module) (@INC entries checked: /etc/perl /usr/local/lib/
x86_64-linux-gnu/perl/5.40.1 /usr/local/share/perl/5.40.1 /usr/lib/x86_64-
linux-gnu/perl5/5.40 /usr/share/perl5 /usr/lib/x86_64-linux-gnu/perl-base
/usr/lib/x86_64-linux-gnu/perl/5.40 /usr/share/perl/5.40 /usr/local/lib/si
te_perl) at /usr/share/perl5/Debconf/FrontEnd/Readline.pm line 8, <STDIN>
line 68.)
debconf: falling back to frontend: Teletype
Extracting templates from packages: 100%t
Preconfiguring packages ...
Configuring tzdata
------------------

Please select the geographic area in which you live. Subsequent
configuration questions will narrow this down by presenting a list of
cities, representing the time zones in which they are located.

  1. Africa      4. Arctic    7. Australia  10. Pacific
  2. America     5. Asia      8. Europe     11. Etc
  3. Antarctica  6. Atlantic  9. Indian
Geographic area

Geographic area: 1

Please select the city or region corresponding to your time zone.

  1. Abidjan       15. Ceuta          29. Kigali      43. Nairobi
  2. Accra         16. Conakry        30. Kinshasa    44. Ndjamena
  3. Addis_Ababa   17. Dakar          31. Lagos       45. Niamey
  4. Algiers       18. Dar_es_Salaam  32. Libreville  46. Nouakchott
  5. Asmara        19. Djibouti       33. Lome        47. Ouagadougou
  6. Bamako        20. Douala         34. Luanda      48. Porto-Novo
  7. Bangui        21. El_Aaiun       35. Lubumbashi  49. Sao_Tome
  8. Banjul        22. Freetown       36. Lusaka      50. Timbuktu
  9. Bissau        23. Gaborone       37. Malabo      51. Tripoli
  10. Blantyre     24. Harare         38. Maputo      52. Tunis
  11. Brazzaville  25. Johannesburg   39. Maseru      53. Windhoek
  12. Bujumbura    26. Juba           40. Mbabane
  13. Cairo        27. Kampala        41. Mogadishu
  14. Casablanca   28. Khartoum       42. Monrovia
Time zone: 1

Selecting previously unselected package libexpat1:amd64.
(Reading database ... 7724 files and directories currently installed.)
Preparing to unpack .../00-libexpat1_2.7.4-1_amd64.deb ...
Unpacking libexpat1:amd64 (2.7.4-1) ...
Selecting previously unselected package libtext-charwidth-perl:amd64.
Preparing to unpack .../01-libtext-charwidth-perl_0.04-11build4_amd64.deb
...
Unpacking libtext-charwidth-perl:amd64 (0.04-11build4) ...
Selecting previously unselected package libtext-wrapi18n-perl.
Preparing to unpack .../02-libtext-wrapi18n-perl_0.06-10_all.deb ...
Unpacking libtext-wrapi18n-perl (0.06-10) ...
Selecting previously unselected package ucf.
Preparing to unpack .../03-ucf_3.0052ubuntu1_all.deb ...
Moving old data out of the way
Unpacking ucf (3.0052ubuntu1) ...
Selecting previously unselected package libdebuginfod-common.
Preparing to unpack .../04-libdebuginfod-common_0.194-4_all.deb ...
Unpacking libdebuginfod-common (0.194-4) ...
Selecting previously unselected package openssl.
Preparing to unpack .../05-openssl_3.5.5-1ubuntu3.2_amd64.deb ...
Unpacking openssl (3.5.5-1ubuntu3.2) ...
Selecting previously unselected package ca-certificates.
Preparing to unpack .../06-ca-certificates_20260601~26.04.1_all.deb ...
Unpacking ca-certificates (20260601~26.04.1) ...
Selecting previously unselected package krb5-locales.
Preparing to unpack .../07-krb5-locales_1.22.1-2ubuntu4_all.deb ...
Unpacking krb5-locales (1.22.1-2ubuntu4) ...
Selecting previously unselected package libatomic1:amd64.
Preparing to unpack .../08-libatomic1_16-20260322-1ubuntu1_amd64.deb ...
Unpacking libatomic1:amd64 (16-20260322-1ubuntu1) ...
Selecting previously unselected package libelf1t64:amd64.
Preparing to unpack .../09-libelf1t64_0.194-4_amd64.deb ...
Unpacking libelf1t64:amd64 (0.194-4) ...
Selecting previously unselected package libffi8:amd64.
Preparing to unpack .../10-libffi8_3.5.2-4_amd64.deb ...
Unpacking libffi8:amd64 (3.5.2-4) ...
Selecting previously unselected package libglib2.0-0t64:amd64.
Preparing to unpack .../11-libglib2.0-0t64_2.88.0-1_amd64.deb ...
Unpacking libglib2.0-0t64:amd64 (2.88.0-1) ...
Selecting previously unselected package libglib2.0-data.
Preparing to unpack .../12-libglib2.0-data_2.88.0-1_all.deb ...
Unpacking libglib2.0-data (2.88.0-1) ...
Selecting previously unselected package libnettle8t64:amd64.
Preparing to unpack .../13-libnettle8t64_3.10.2-1_amd64.deb ...
Unpacking libnettle8t64:amd64 (3.10.2-1) ...
Selecting previously unselected package libhogweed6t64:amd64.
Preparing to unpack .../14-libhogweed6t64_3.10.2-1_amd64.deb ...
Unpacking libhogweed6t64:amd64 (3.10.2-1) ...
Selecting previously unselected package libunistring5:amd64.
Preparing to unpack .../15-libunistring5_1.3-2build1_amd64.deb ...
Unpacking libunistring5:amd64 (1.3-2build1) ...
Selecting previously unselected package libidn2-0:amd64.
Preparing to unpack .../16-libidn2-0_2.3.8-4build1_amd64.deb ...
Unpacking libidn2-0:amd64 (2.3.8-4build1) ...
Selecting previously unselected package libp11-kit0:amd64.
Preparing to unpack .../17-libp11-kit0_0.26.2-2_amd64.deb ...
Unpacking libp11-kit0:amd64 (0.26.2-2) ...
Selecting previously unselected package libtasn1-6:amd64.
Preparing to unpack .../18-libtasn1-6_4.21.0-2_amd64.deb ...
Unpacking libtasn1-6:amd64 (4.21.0-2) ...
Selecting previously unselected package libgnutls30t64:amd64.
Preparing to unpack .../19-libgnutls30t64_3.8.12-2ubuntu1.1_amd64.deb ...
Unpacking libgnutls30t64:amd64 (3.8.12-2ubuntu1.1) ...
Selecting previously unselected package libkrb5support0:amd64.
Preparing to unpack .../20-libkrb5support0_1.22.1-2ubuntu4_amd64.deb ...
Unpacking libkrb5support0:amd64 (1.22.1-2ubuntu4) ...
Selecting previously unselected package libk5crypto3:amd64.
Preparing to unpack .../21-libk5crypto3_1.22.1-2ubuntu4_amd64.deb ...
Unpacking libk5crypto3:amd64 (1.22.1-2ubuntu4) ...
Selecting previously unselected package libkeyutils1:amd64.
Preparing to unpack .../22-libkeyutils1_1.6.3-6ubuntu3_amd64.deb ...
Unpacking libkeyutils1:amd64 (1.6.3-6ubuntu3) ...
Selecting previously unselected package libkrb5-3:amd64.
Preparing to unpack .../23-libkrb5-3_1.22.1-2ubuntu4_amd64.deb ...
Unpacking libkrb5-3:amd64 (1.22.1-2ubuntu4) ...
Selecting previously unselected package libgssapi-krb5-2:amd64.
Preparing to unpack .../24-libgssapi-krb5-2_1.22.1-2ubuntu4_amd64.deb ...
Unpacking libgssapi-krb5-2:amd64 (1.22.1-2ubuntu4) ...
Selecting previously unselected package libjson-c5:amd64.
Preparing to unpack .../25-libjson-c5_0.18+ds-3_amd64.deb ...
Unpacking libjson-c5:amd64 (0.18+ds-3) ...
Selecting previously unselected package libpython3.14-minimal:amd64.
Preparing to unpack .../26-libpython3.14-minimal_3.14.4-1ubuntu0.1_amd64.d
eb ...
Unpacking libpython3.14-minimal:amd64 (3.14.4-1ubuntu0.1) ...
Selecting previously unselected package media-types.
Preparing to unpack .../27-media-types_14.0.0build1_all.deb ...
Unpacking media-types (14.0.0build1) ...
Selecting previously unselected package netbase.
Preparing to unpack .../28-netbase_6.5build1_all.deb ...
Unpacking netbase (6.5build1) ...
Selecting previously unselected package tzdata.
Preparing to unpack .../29-tzdata_2026b-0ubuntu0.26.04.1_all.deb ...
Unpacking tzdata (2026b-0ubuntu0.26.04.1) ...
Selecting previously unselected package readline-common.
Preparing to unpack .../30-readline-common_8.3-4_all.deb ...
Unpacking readline-common (8.3-4) ...
Selecting previously unselected package libreadline8t64:amd64.
Preparing to unpack .../31-libreadline8t64_8.3-4_amd64.deb ...
Adding 'diversion of /lib/x86_64-linux-gnu/libhistory.so.8 to /lib/x86_64-
linux-gnu/libhistory.so.8.usr-is-merged by libreadline8t64'
Adding 'diversion of /lib/x86_64-linux-gnu/libhistory.so.8.2 to /lib/x86_6
4-linux-gnu/libhistory.so.8.2.usr-is-merged by libreadline8t64'
Adding 'diversion of /lib/x86_64-linux-gnu/libreadline.so.8 to /lib/x86_64
-linux-gnu/libreadline.so.8.usr-is-merged by libreadline8t64'
Adding 'diversion of /lib/x86_64-linux-gnu/libreadline.so.8.2 to /lib/x86_
64-linux-gnu/libreadline.so.8.2.usr-is-merged by libreadline8t64'
Unpacking libreadline8t64:amd64 (8.3-4) ...
Selecting previously unselected package libsqlite3-0:amd64.
Preparing to unpack .../32-libsqlite3-0_3.46.1-9ubuntu0.1_amd64.deb ...
Unpacking libsqlite3-0:amd64 (3.46.1-9ubuntu0.1) ...
Selecting previously unselected package libpython3.14-stdlib:amd64.
Preparing to unpack .../33-libpython3.14-stdlib_3.14.4-1ubuntu0.1_amd64.de
b ...
Unpacking libpython3.14-stdlib:amd64 (3.14.4-1ubuntu0.1) ...
Selecting previously unselected package libxml2-16:amd64.
Preparing to unpack .../34-libxml2-16_2.15.2+dfsg-0.1ubuntu0.1_amd64.deb .
..
Unpacking libxml2-16:amd64 (2.15.2+dfsg-0.1ubuntu0.1) ...
Selecting previously unselected package shared-mime-info.
Preparing to unpack .../35-shared-mime-info_2.4-5build3_amd64.deb ...
Unpacking shared-mime-info (2.4-5build3) ...
Selecting previously unselected package xdg-user-dirs.
Preparing to unpack .../36-xdg-user-dirs_0.19-1_amd64.deb ...
Unpacking xdg-user-dirs (0.19-1) ...
Selecting previously unselected package libjansson4:amd64.
Preparing to unpack .../37-libjansson4_2.14-2build4_amd64.deb ...
Unpacking libjansson4:amd64 (2.14-2build4) ...
Selecting previously unselected package libnghttp2-14:amd64.
Preparing to unpack .../38-libnghttp2-14_1.68.0-2ubuntu0.2_amd64.deb ...
Unpacking libnghttp2-14:amd64 (1.68.0-2ubuntu0.2) ...
Selecting previously unselected package libpsl5t64:amd64.
Preparing to unpack .../39-libpsl5t64_0.21.2-1.1build2_amd64.deb ...
Unpacking libpsl5t64:amd64 (0.21.2-1.1build2) ...
Selecting previously unselected package publicsuffix.
Preparing to unpack .../40-publicsuffix_20260129.1928-1_all.deb ...
Unpacking publicsuffix (20260129.1928-1) ...
Selecting previously unselected package libsframe3:amd64.
Preparing to unpack .../41-libsframe3_2.46-3ubuntu2_amd64.deb ...
Unpacking libsframe3:amd64 (2.46-3ubuntu2) ...
Selecting previously unselected package binutils-common:amd64.
Preparing to unpack .../42-binutils-common_2.46-3ubuntu2_amd64.deb ...
Unpacking binutils-common:amd64 (2.46-3ubuntu2) ...
Selecting previously unselected package libbinutils:amd64.
Preparing to unpack .../43-libbinutils_2.46-3ubuntu2_amd64.deb ...
Unpacking libbinutils:amd64 (2.46-3ubuntu2) ...
Selecting previously unselected package libgprofng0:amd64.
Preparing to unpack .../44-libgprofng0_2.46-3ubuntu2_amd64.deb ...
Unpacking libgprofng0:amd64 (2.46-3ubuntu2) ...
Selecting previously unselected package libctf-nobfd0:amd64.
Preparing to unpack .../45-libctf-nobfd0_2.46-3ubuntu2_amd64.deb ...
Unpacking libctf-nobfd0:amd64 (2.46-3ubuntu2) ...
Selecting previously unselected package libctf0:amd64.
Preparing to unpack .../46-libctf0_2.46-3ubuntu2_amd64.deb ...
Unpacking libctf0:amd64 (2.46-3ubuntu2) ...
Selecting previously unselected package binutils-x86-64-linux-gnu.
Preparing to unpack .../47-binutils-x86-64-linux-gnu_2.46-3ubuntu2_amd64.d
eb ...
Unpacking binutils-x86-64-linux-gnu (2.46-3ubuntu2) ...
Selecting previously unselected package binutils.
Preparing to unpack .../48-binutils_2.46-3ubuntu2_amd64.deb ...
Unpacking binutils (2.46-3ubuntu2) ...
Selecting previously unselected package libdw1t64:amd64.
Preparing to unpack .../49-libdw1t64_0.194-4_amd64.deb ...
Unpacking libdw1t64:amd64 (0.194-4) ...
Selecting previously unselected package libbabeltrace1:amd64.
Preparing to unpack .../50-libbabeltrace1_1.5.11-5build1_amd64.deb ...
Unpacking libbabeltrace1:amd64 (1.5.11-5build1) ...
Selecting previously unselected package libbrotli1:amd64.
Preparing to unpack .../51-libbrotli1_1.2.0-3build1_amd64.deb ...
Unpacking libbrotli1:amd64 (1.2.0-3build1) ...
Selecting previously unselected package libsasl2-modules-db:amd64.
Preparing to unpack .../52-libsasl2-modules-db_2.1.28+dfsg1-9ubuntu3_amd64
.deb ...
Unpacking libsasl2-modules-db:amd64 (2.1.28+dfsg1-9ubuntu3) ...
Selecting previously unselected package libsasl2-2:amd64.
Preparing to unpack .../53-libsasl2-2_2.1.28+dfsg1-9ubuntu3_amd64.deb ...
Unpacking libsasl2-2:amd64 (2.1.28+dfsg1-9ubuntu3) ...
Selecting previously unselected package libldap-common.
Preparing to unpack .../54-libldap-common_2.6.10+dfsg-1ubuntu5_all.deb ...
Unpacking libldap-common (2.6.10+dfsg-1ubuntu5) ...
Selecting previously unselected package libldap2:amd64.
Preparing to unpack .../55-libldap2_2.6.10+dfsg-1ubuntu5_amd64.deb ...
Unpacking libldap2:amd64 (2.6.10+dfsg-1ubuntu5) ...
Selecting previously unselected package librtmp1:amd64.
Preparing to unpack .../56-librtmp1_2.4+20151223.gitfa8646d.1-3_amd64.deb
...
Unpacking librtmp1:amd64 (2.4+20151223.gitfa8646d.1-3) ...
Selecting previously unselected package libssh2-1t64:amd64.
Preparing to unpack .../57-libssh2-1t64_1.11.1-1ubuntu0.26.04.2_amd64.deb
...
Unpacking libssh2-1t64:amd64 (1.11.1-1ubuntu0.26.04.2) ...
Selecting previously unselected package libcurl3t64-gnutls:amd64.
Preparing to unpack .../58-libcurl3t64-gnutls_8.18.0-1ubuntu2.3_amd64.deb
...
Unpacking libcurl3t64-gnutls:amd64 (8.18.0-1ubuntu2.3) ...
Selecting previously unselected package libdebuginfod1t64:amd64.
Preparing to unpack .../59-libdebuginfod1t64_0.194-4_amd64.deb ...
Unpacking libdebuginfod1t64:amd64 (0.194-4) ...
Selecting previously unselected package libipt2.
Preparing to unpack .../60-libipt2_2.1.2-3_amd64.deb ...
Unpacking libipt2 (2.1.2-3) ...
Selecting previously unselected package libmpfr6:amd64.
Preparing to unpack .../61-libmpfr6_4.2.2-3_amd64.deb ...
Unpacking libmpfr6:amd64 (4.2.2-3) ...
Selecting previously unselected package libpython3.14:amd64.
Preparing to unpack .../62-libpython3.14_3.14.4-1ubuntu0.1_amd64.deb ...
Unpacking libpython3.14:amd64 (3.14.4-1ubuntu0.1) ...
Selecting previously unselected package libsource-highlight-common.
Preparing to unpack .../63-libsource-highlight-common_3.1.9-4.3build2_all.
deb ...
Unpacking libsource-highlight-common (3.1.9-4.3build2) ...
Selecting previously unselected package libsource-highlight4t64:amd64.
Preparing to unpack .../64-libsource-highlight4t64_3.1.9-4.3build2_amd64.d
eb ...
Unpacking libsource-highlight4t64:amd64 (3.1.9-4.3build2) ...
Selecting previously unselected package gdb.
Preparing to unpack .../65-gdb_17.1-2ubuntu1_amd64.deb ...
Unpacking gdb (17.1-2ubuntu1) ...
Selecting previously unselected package libsasl2-modules:amd64.
Preparing to unpack .../66-libsasl2-modules_2.1.28+dfsg1-9ubuntu3_amd64.de
b ...
Unpacking libsasl2-modules:amd64 (2.1.28+dfsg1-9ubuntu3) ...
Selecting previously unselected package libc6-dbg:amd64.
Preparing to unpack .../67-libc6-dbg_2.43-2ubuntu2_amd64.deb ...
Unpacking libc6-dbg:amd64 (2.43-2ubuntu2) ...
Setting up libexpat1:amd64 (2.7.4-1) ...
Setting up media-types (14.0.0build1) ...
Setting up libtext-charwidth-perl:amd64 (0.04-11build4) ...
Setting up libkeyutils1:amd64 (1.6.3-6ubuntu3) ...
Setting up xdg-user-dirs (0.19-1) ...
Setting up libxml2-16:amd64 (2.15.2+dfsg-0.1ubuntu0.1) ...
Setting up libbrotli1:amd64 (1.2.0-3build1) ...
Setting up libpython3.14-minimal:amd64 (3.14.4-1ubuntu0.1) ...
Setting up libsqlite3-0:amd64 (3.46.1-9ubuntu0.1) ...
Setting up libsasl2-modules:amd64 (2.1.28+dfsg1-9ubuntu3) ...
Setting up binutils-common:amd64 (2.46-3ubuntu2) ...
Setting up libnghttp2-14:amd64 (1.68.0-2ubuntu0.2) ...
Setting up libsframe3:amd64 (2.46-3ubuntu2) ...
Setting up libctf-nobfd0:amd64 (2.46-3ubuntu2) ...
Setting up krb5-locales (1.22.1-2ubuntu4) ...
Setting up libldap-common (2.6.10+dfsg-1ubuntu5) ...
Setting up libtext-wrapi18n-perl (0.06-10) ...
Setting up libsource-highlight-common (3.1.9-4.3build2) ...
Setting up libelf1t64:amd64 (0.194-4) ...
Setting up libjansson4:amd64 (2.14-2build4) ...
Setting up libc6-dbg:amd64 (2.43-2ubuntu2) ...
Setting up libkrb5support0:amd64 (1.22.1-2ubuntu4) ...
Setting up libdw1t64:amd64 (0.194-4) ...
Setting up libsasl2-modules-db:amd64 (2.1.28+dfsg1-9ubuntu3) ...
Setting up tzdata (2026b-0ubuntu0.26.04.1) ...
debconf: unable to initialize frontend: Dialog
debconf: (No usable dialog-like program is installed, so the dialog based
frontend cannot be used. at /usr/share/perl5/Debconf/FrontEnd/Dialog.pm li
ne 79.)
debconf: falling back to frontend: Readline
debconf: unable to initialize frontend: Readline
debconf: (Can't locate Term/ReadLine.pm in @INC (you may need to install t
he Term::ReadLine module) (@INC entries checked: /etc/perl /usr/local/lib/
x86_64-linux-gnu/perl/5.40.1 /usr/local/share/perl/5.40.1 /usr/lib/x86_64-
linux-gnu/perl5/5.40 /usr/share/perl5 /usr/lib/x86_64-linux-gnu/perl-base
/usr/lib/x86_64-linux-gnu/perl/5.40 /usr/share/perl/5.40 /usr/local/lib/si
te_perl) at /usr/share/perl5/Debconf/FrontEnd/Readline.pm line 8.)
debconf: falling back to frontend: Teletype

Current default time zone: 'Africa/Abidjan'
Local time is now:      Sat Jul 11 14:02:39 GMT 2026.
Universal Time is now:  Sat Jul 11 14:02:39 UTC 2026.
Run 'dpkg-reconfigure tzdata' if you wish to change it.

Setting up libnettle8t64:amd64 (3.10.2-1) ...
Setting up libglib2.0-data (2.88.0-1) ...
Setting up libmpfr6:amd64 (4.2.2-3) ...
Setting up libunistring5:amd64 (1.3-2build1) ...
Setting up libatomic1:amd64 (16-20260322-1ubuntu1) ...
Setting up libipt2 (2.1.2-3) ...
Setting up ucf (3.0052ubuntu1) ...
Setting up libk5crypto3:amd64 (1.22.1-2ubuntu4) ...
Setting up libsasl2-2:amd64 (2.1.28+dfsg1-9ubuntu3) ...
Setting up libffi8:amd64 (3.5.2-4) ...
Setting up libhogweed6t64:amd64 (3.10.2-1) ...
Setting up libtasn1-6:amd64 (4.21.0-2) ...
Setting up netbase (6.5build1) ...
Setting up libkrb5-3:amd64 (1.22.1-2ubuntu4) ...
Setting up libssh2-1t64:amd64 (1.11.1-1ubuntu0.26.04.2) ...
Setting up libbinutils:amd64 (2.46-3ubuntu2) ...
Setting up openssl (3.5.5-1ubuntu3.2) ...
Setting up libjson-c5:amd64 (0.18+ds-3) ...
Setting up readline-common (8.3-4) ...
Setting up publicsuffix (20260129.1928-1) ...
Setting up libldap2:amd64 (2.6.10+dfsg-1ubuntu5) ...
Setting up libctf0:amd64 (2.46-3ubuntu2) ...
Setting up libdebuginfod-common (0.194-4) ...
debconf: unable to initialize frontend: Dialog
debconf: (No usable dialog-like program is installed, so the dialog based
frontend cannot be used. at /usr/share/perl5/Debconf/FrontEnd/Dialog.pm li
ne 79.)
debconf: falling back to frontend: Readline
debconf: unable to initialize frontend: Readline
debconf: (Can't locate Term/ReadLine.pm in @INC (you may need to install t
he Term::ReadLine module) (@INC entries checked: /etc/perl /usr/local/lib/
x86_64-linux-gnu/perl/5.40.1 /usr/local/share/perl/5.40.1 /usr/lib/x86_64-
linux-gnu/perl5/5.40 /usr/share/perl5 /usr/lib/x86_64-linux-gnu/perl-base
/usr/lib/x86_64-linux-gnu/perl/5.40 /usr/share/perl/5.40 /usr/local/lib/si
te_perl) at /usr/share/perl5/Debconf/FrontEnd/Readline.pm line 8.)
debconf: falling back to frontend: Teletype
Setting up libidn2-0:amd64 (2.3.8-4build1) ...
Setting up libsource-highlight4t64:amd64 (3.1.9-4.3build2) ...
Setting up ca-certificates (20260601~26.04.1) ...
debconf: unable to initialize frontend: Dialog
debconf: (No usable dialog-like program is installed, so the dialog based
frontend cannot be used. at /usr/share/perl5/Debconf/FrontEnd/Dialog.pm li
ne 79.)
debconf: falling back to frontend: Readline
debconf: unable to initialize frontend: Readline
debconf: (Can't locate Term/ReadLine.pm in @INC (you may need to install t
he Term::ReadLine module) (@INC entries checked: /etc/perl /usr/local/lib/
x86_64-linux-gnu/perl/5.40.1 /usr/local/share/perl/5.40.1 /usr/lib/x86_64-
linux-gnu/perl5/5.40 /usr/share/perl5 /usr/lib/x86_64-linux-gnu/perl-base
/usr/lib/x86_64-linux-gnu/perl/5.40 /usr/share/perl/5.40 /usr/local/lib/si
te_perl) at /usr/share/perl5/Debconf/FrontEnd/Readline.pm line 8.)
debconf: falling back to frontend: Teletype
Updating certificates in /etc/ssl/certs...
121 added, 0 removed; done.
Setting up libglib2.0-0t64:amd64 (2.88.0-1) ...
No schema files found: doing nothing.
Setting up libgprofng0:amd64 (2.46-3ubuntu2) ...
Setting up shared-mime-info (2.4-5build3) ...
Setting up libp11-kit0:amd64 (0.26.2-2) ...
Setting up libgssapi-krb5-2:amd64 (1.22.1-2ubuntu4) ...
Setting up libbabeltrace1:amd64 (1.5.11-5build1) ...
Setting up libreadline8t64:amd64 (8.3-4) ...
Setting up binutils-x86-64-linux-gnu (2.46-3ubuntu2) ...
Setting up libgnutls30t64:amd64 (3.8.12-2ubuntu1.1) ...
Setting up libpython3.14-stdlib:amd64 (3.14.4-1ubuntu0.1) ...
Setting up libpsl5t64:amd64 (0.21.2-1.1build2) ...
Setting up binutils (2.46-3ubuntu2) ...
Setting up librtmp1:amd64 (2.4+20151223.gitfa8646d.1-3) ...
Setting up libpython3.14:amd64 (3.14.4-1ubuntu0.1) ...
Setting up libcurl3t64-gnutls:amd64 (8.18.0-1ubuntu2.3) ...
Setting up libdebuginfod1t64:amd64 (0.194-4) ...
Setting up gdb (17.1-2ubuntu1) ...
Processing triggers for libc-bin (2.43-2ubuntu2) ...
Processing triggers for ca-certificates (20260601~26.04.1) ...
Updating certificates in /etc/ssl/certs...
0 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
root@c627f2c198f6:/tmp# ls
rev-basic-0
root@c627f2c198f6:/tmp# strings rev-basic-0
!This program cannot be run in DOS mode.
Richc{
.text
`.rdata
@.data
.pdata
@.rsrc
@.reloc
D$ H
L$ L
L$XH
L$ L
L$PL
D$HH
T$@H
L$ L
L$XH
L$ L
L$PL
D$HH
T$@H
D$ H
T$ H
L$ H
D$HH
L$(E3
T$@H
D$ H
D$ H
L$ H
D$HH
D$(3
L$(E3
T$@H
D$ H
D$ H
\$@H
t$HH
D$8H
D$8H
D$@H
@SVWH
T$`H
L$hH
T$`L
L$0L
L$pH
L$(3
@_^[
t!eH
uxHc
uTL+
\$ UH
M H1E
 H3E H3E
\$HH
L$0L
L$(H
L$ 3
L$PH
D$PH
D$@H
D$H3
u0HcH<H
;csm
\$03
\$0H
\$0H
ntelA
GenuD
ineI
t(=`
t!=p
 w$H
T$ H
D$ "
D$ $
\$(3
t$0H
Compar3_the_str1ng
Input :
%256s
Correct
Wrong
RSDS
C:\Users\user\source\repos\reversing-wargame\x64\Release\chall0.pdb
GCTL
.text$mn
.text$mn$00
.text$x
.idata$5
.00cfg
.CRT$XCA
.CRT$XCAA
.CRT$XCZ
.CRT$XIA
.CRT$XIAA
.CRT$XIAC
.CRT$XIZ
.CRT$XPA
.CRT$XPZ
.CRT$XTA
.CRT$XTZ
.rdata
.rdata$zzzdbg
.rtc$IAA
.rtc$IZZ
.rtc$TAA
.rtc$TZZ
.xdata
.idata$2
.idata$3
.idata$4
.idata$6
.data
.bss
.pdata
.rsrc$01
.rsrc$02
__C_specific_handler
__current_exception
__current_exception_context
memset
VCRUNTIME140.dll
strcmp
__acrt_iob_func
puts
__stdio_common_vfprintf
__stdio_common_vfscanf
_seh_filter_exe
_set_app_type
__setusermatherr
_configure_narrow_argv
_initialize_narrow_environment
_get_initial_narrow_environment
_initterm
_initterm_e
exit
_exit
_set_fmode
__p___argc
__p___argv
_cexit
_c_exit
_register_thread_local_exe_atexit_callback
_configthreadlocale
_set_new_mode
__p__commode
_initialize_onexit_table
_register_onexit_function
_crt_atexit
terminate
api-ms-win-crt-string-l1-1-0.dll
api-ms-win-crt-stdio-l1-1-0.dll
api-ms-win-crt-runtime-l1-1-0.dll
api-ms-win-crt-math-l1-1-0.dll
api-ms-win-crt-locale-l1-1-0.dll
api-ms-win-crt-heap-l1-1-0.dll
RtlCaptureContext
RtlLookupFunctionEntry
RtlVirtualUnwind
UnhandledExceptionFilter
SetUnhandledExceptionFilter
GetCurrentProcess
TerminateProcess
IsProcessorFeaturePresent
QueryPerformanceCounter
GetCurrentProcessId
GetCurrentThreadId
GetSystemTimeAsFileTime
InitializeSListHead
IsDebuggerPresent
GetModuleHandleW
KERNEL32.dll
<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level='asInvoker' uiAccess='false' />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
root@c627f2c198f6:/tmp# strings rev-basic-0  | grep Correct
Correct
root@c627f2c198f6:/tmp# strings rev-basic-0  | grep -C 5 Correct
\$(3
t$0H
Compar3_the_str1ng
Input :
%256s
Correct
Wrong
RSDS
C:\Users\user\source\repos\reversing-wargame\x64\Release\chall0.pdb
GCTL
.text$mn
root@c627f2c198f6:/tmp# ls -a
.  ..  rev-basic-0
root@c627f2c198f6:/tmp# ls -al
total 20
drwxrwxrwt 1 root root  4096 Jul 11 14:02 .
drwxr-xr-x 1 root root  4096 Jul 11 14:00 ..
-rwxr-xr-x 1 root root 11264 Jul 11 13:59 rev-basic-0
root@c627f2c198f6:/tmp# ./rev-basic-0
<3>WSL (3024 - ) ERROR: UtilGetPpid:1290: Failed to parse: /proc/1/stat, c
ontent: 1 (bash) S 0 1 1 34816 3024 4194560 1853 802579 29 624 2 3 643 327
 20 0 1 0 1573155 4882432 960 18446744073709551615 98582213140480 98582214
199713 140732593958240 0 0 0 65536 3686404 1266761467 1 0 0 17 14 0 0 0 0
0 98582214428912 98582214477960 98582436708352 140732593962868 14073259396
2879 140732593962879 140732593962989 0
root@c627f2c198f6:/tmp#