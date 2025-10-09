# 10.201.118.205

nmap -Pn -sV -sC -oN scan.txt 10.201.119.205
nmap -sC -sV 10.201.119.205

ffuf -u http://10.201.119.205 -H "Host:FUZZ.10.201.119.205" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302
