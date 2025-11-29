                                                                                                                            
# 10.65.154.119

┌──(kali㉿kali)-[~]
└─$ nc 10.65.154.119 1337                                                           
This XOR encoded text has flag 1: 19317c43207c185d56240801457924394d5253330c17430b3121354850053f0d4808253f017e4a2d
What is the encryption key? ^C
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ chmod 700 ./wise.py 
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ sudo python3 ./wise.py
[sudo] password for kali: 
usage: wise.py [-h] hex_encoded
wise.py: error: the following arguments are required: hex_encoded
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ 19317c43207c185d56240801457924394d5253330c17430b3121354850053f0d4808253f017e4a2d
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ sudo python3 ./wise.py
usage: wise.py [-h] hex_encoded
wise.py: error: the following arguments are required: hex_encoded
                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ sudo python3 ./wise.py 19317c43207c185d56240801457924394d5253330c17430b3121354850053f0d4808253f017e4a2d
Derived start of the key: My18
Derived end of the key: P
Derived key: My18P
Decrypted message: THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}
                                