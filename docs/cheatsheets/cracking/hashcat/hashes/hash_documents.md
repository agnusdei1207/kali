# Hashcat 문서 파일 해시 (PDF, MS Office)

## PDF 1.1-1.3 (Acrobat 2-4) (-m 10400)

```bash
hashcat -m 10400 -a 0 pdf_old.txt wordlist.txt
```

## PDF 1.4-1.6 (Acrobat 5-8) (-m 10500)

```bash
hashcat -m 10500 -a 0 pdf.txt wordlist.txt
```

## PDF 1.7 Level 3 (Acrobat 9) (-m 10600)

```bash
hashcat -m 10600 -a 0 pdf9.txt wordlist.txt
```

## PDF 1.7 Level 8 (Acrobat 10-11) (-m 10700)

```bash
hashcat -m 10700 -a 0 pdf10.txt wordlist.txt
```

## MS Office 2007 (-m 9400)

```bash
hashcat -m 9400 -a 0 office2007.txt wordlist.txt
```

## MS Office 2010 (-m 9500)

```bash
hashcat -m 9500 -a 0 office2010.txt wordlist.txt
```

## MS Office 2013 (-m 9600)

```bash
hashcat -m 9600 -a 0 office2013.txt wordlist.txt
```

## MS Office <= 2003 (-m 9700)

```bash
hashcat -m 9700 -a 0 office_old.txt wordlist.txt
```

## 해시 추출

```bash
# PDF
pdf2john document.pdf > pdf.hash

# Office
office2john document.docx > office.hash
```

## 팁

- Office 2013은 PBKDF2로 느림
- PDF는 버전별 모드 다름. pdf2john 출력 확인
- 암호 없는 PDF도 있음: qpdf --decrypt