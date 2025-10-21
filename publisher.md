# 10.201.74.120

nmap -Pn -sV -sC -oN scan.txt --open 10.201.74.120

ffuf -u http://10.201.74.120 -H "Host:FUZZ.10.201.74.120" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 50 -mc 200,302
