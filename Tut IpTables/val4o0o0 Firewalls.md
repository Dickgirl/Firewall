### IPTables By Valeri Georgiev a.k.a val4o0o0 12.02.2013 (last update)
### check external ip - in terminal, type: ifconfig
### traffic log: tcpdump -i eth1 -l -nn -s 0 -x port 27015-50
### flush na tablicata
 
GPORTS='27000:27100'
 
### politiki
``` 
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
``` 

### dropvame falshivite connect-cii kum politikite
``` 
iptables -I INPUT -m state --state INVALID -j DROP
iptables -I FORWARD -m state --state INVALID -j DROP
iptables -I OUTPUT -m state --state INVALID -j DROP
``` 

### razreshavame lokalniq interfeis
``` 
iptables -I INPUT -i lo -j ACCEPT
``` 

### REL, ESTB razreshenie
``` 
iptables -I INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
``` 

### END OF ACCEPTED IPS
### accept a2s_queries (https://developer.valvesoftware.com/wiki/Server_queries)
``` 
iptables -I INPUT -p udp -m string --hex-string "|FFFFFFFF|" --algo bm -j ACCEPT 
iptables -I INPUT -p udp -m string --hex-string "|FFFFFFFF00|" --algo bm -j ACCEPT 
iptables -I INPUT -p udp -m string --hex-string "|FFFFFFFF41|" --algo bm -j ACCEPT 
iptables -I INPUT -p udp -m string --hex-string "|FFFFFFFF57|" --algo bm -j ACCEPT 
iptables -I INPUT -p udp -m string --hex-string "|FFFFFFFF6A|" --algo bm -j ACCEPT 
iptables -I INPUT -p udp -m string --hex-string "|FFFFFFFF69|" --algo bm -j ACCEPT
iptables -I INPUT -p udp -m string --hex-string "|FFFFFFFF55|" --algo bm -j ACCEPT
``` 

### accept tcp/udp on hlds connections
``` 
iptables -I INPUT -p udp --dport 27000:27100 -m state --state NEW -j ACCEPT
iptables -I INPUT -p tcp --dport 27000:27100 -m state --state NEW -j ACCEPT
``` 

### limitirane na lenght za udp portove 27000:27100 (secure)
``` 
iptables -I INPUT -p udp --dport 27000:27100 -m length ! --length 32:1250 -j DROP
iptables -I INPUT -p udp --dport 27000:27100 -m length --length 222 -j DROP
``` 

### connlimit (vtori metod za secure ot udp flood)
``` 
iptables -I INPUT -p udp --sport 27000:27100 --dport 27000:27100 -m connlimit --connlimit-above 3 -j DROP
``` 

### VAC port accept (-sport in comamnd line on hlds)
``` 
iptables -I INPUT -p udp --dport 25300 -m state --state NEW -j ACCEPT
``` 

### limitirane na lenght za udp port 25300 (secure)
``` 
iptables -I INPUT -p udp --dport 25300 -m length ! --length 32:1320 -j DROP
``` 

### acceptvame 53 & 123 port
``` 
iptables -I INPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
iptables -I INPUT -p udp --dport 123 -m state --state NEW -j ACCEPT
``` 

### limitirane na lenght za udp port 53 (secure)
``` 
iptables -I INPUT -p udp --dport 53 -m length ! --length 32:1250 -j DROP
``` 

### limitirane na lenght za udp port 123 (secure)
``` 
iptables -I INPUT -p udp --dport 123 -m length ! --length 32:1250 -j DROP
``` 

### broadcast drop
``` 
iptables -I INPUT -m pkttype --pkt-type broadcast -j DROP
 ``` 
 
### allow 3306 (MYSQL SERVER) to only for me
``` 
iptables -I INPUT -p tcp --syn --dport 3306 -j DROP
iptables -I INPUT -p tcp --syn --dport 3306 -s 127.0.0.1 -m state --state NEW -j ACCEPT
 ``` 
 
### secure 80 port (apache)
``` 
iptables -I INPUT -p tcp --syn --dport 80 -m state --state NEW -j ACCEPT
iptables -I INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 6 --connlimit-mask 24 -j DROP
``` 

### prevent bad scanners
``` 
iptables -I INPUT -p tcp --dport 80 -m string --string "GET /w00tw00t.at.ISC.SANS." --algo bm --to 70 -j DROP
``` 

### prevent range request's
``` 
iptables -I INPUT -p tcp --dport 80 -m string --algo bm --from 58 --string "Range:bytes=0-" -j DROP
``` 
 
### steam 4380 port open
``` 
iptables -I INPUT -p udp --dport 4380 -m state --state NEW -j ACCEPT
``` 

### some dangerous strings (prevent some exploits)
``` 
for i in $GPORTS
do
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "19e5f1e722f4ab6d0d41c82f89c65295" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "f0ef8a36258af1bb64ed866538c9db76" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "d506d189cf551620a70277a3d2c55bb2" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "67790c589689e0c8bc9254418f74a7e8" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "2f7aca2b284b6bd8aedd261c6a5a6b49" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "a8da12f3f71d87a40ca6c35ee73ad1a5" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "61b9ce4070c5a3ec287995faa9e6dc49" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "821bd412a43cd778dd3448791a135275" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "520a87d91ba71f8dc9a905424b548a7d" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "861078331b85a424935805ca54f82891" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "fc919407beff66e210d03f3a72d456c0" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "dffa71977e9f0a0e6f0ea6d47e8a17bc" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "dacc732487fb2972a20f49b7070eed64" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "5f6aeb507a7f08f9c9d650236ee3ac9c" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "6785596aad8a0becf54c82615f8705f7" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "701175dd24b8dc4d5b01edc880e4409e" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "d414f6c0b2e8c15157d51a87bf9186af" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "664c43a63d2350d8c9da6a6c242b149a" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "5b5e7138b2d0fbdb7ac799b54c1c94ec" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "c448329a0e0d9b583986e18cfaec3aa3" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "cc9d4028d80b7d9c2242cf5fc8cb25f2" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "8a120ff3e2c86713f4d346d20f763ee7" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "565cbe1cfd0b592bbc68642b2be3b8e6" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "57f64e351b16ccfa1a08ef655b6abdf0" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "353f34d3455732d2c6015bb8b3821253" -j DROP #strings of exploit
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|17c74a30a2fb752396b63532b1bf79b0|" -j DROP #antifake1
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|17951a20e2ab6d63d6ac7d62f1f721e057cd4270e2f1357396f66522f1ed61f0|" -j DROP #antifake2
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|178f5230e2e17d73d6bc6562f1ed29e0|" -j DROP #antifake3
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|d50000806e000000|"  -j DROP #antifake4
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|ffffffff6765746368616c6c656e6765000000000000|" -j DROP #antifake5
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|b96c|" -j DROP #antifake6
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|636f 6e74 6163 7420 2248 4c58 4272 7574|" -j DROP #antifake7
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|ffffffff56|" -j DROP #antifake8
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|4141 4141 4141 4141 4141 4141 4141 4141|" -j DROP #antifake9
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|a090909090909090901809a5000000|" -j DROP #antifake10
iptables -I INPUT -p udp --dport $i -m string --algo bm --hex-string "|d51000806e000000|" -j DROP #antifake11
``` 

### anti fake players by ITNI
``` 
iptables -I INPUT -p udp --dport $i -m length --length 50 -m recent --set --name getchallenge_hlds 
iptables -I INPUT -p udp --dport $i -m string --algo bm --string "getchallenge" -m recent --update --seconds 1 --hitcount 1 --name getchallenge_hlds -j DROP  
done
``` 

### HLBRUTE
``` 
iptables -I INPUT -m string --string "HLBrute" --algo bm -j DROP 
iptables -I INPUT -m string --string "HLXBrute" --algo bm -j DROP  
``` 

### CSDeath
``` 
iptables -I INPUT -m string --algo bm --hex-string "|07 00 00 80 05 00 00 00 3B 74 64 04 3D 65 7C 2E 61 7C 21 6F 70 26 79 2B 23 71 27 69 7B 34 43 07 30 2C 79 61 2B 71 68 27 71 61 7C 61 6C 6F 3E 22 79 1B 40 23 73 21 36 6B 2C 38 20 22 3E 6C 36 2B 70 76 35 61 5E 58 74 66|" -j DROP  
``` 

### izvestni portove za hl proxy-ta
``` 
iptables -I INPUT -p udp --sport 60230:60240 -j DROP  
``` 

# DROP RULES
 
### zashtita ot opiti za otvarqne na vhodqshti TCP vruzki bez SYN
``` 
iptables -I INPUT -m conntrack --ctstate NEW -p tcp ! --syn -j DROP
``` 

### Dropvame falshivite TCP packeti
``` 
iptables -I INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -I INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -I INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -I INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -I INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -I INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -I INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -I INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -I INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -I INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -I INPUT -p tcp --tcp-flags ALL SYN,FIN -j DROP
iptables -I INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j DROP
iptables -I INPUT -p tcp --tcp-flags ALL FIN -j DROP
iptables -I INPUT -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -j DROP
``` 

### prosta zashtita ot tcp ataki s nulevi paketi
``` 
iptables -I INPUT -p tcp --tcp-flags ALL NONE -j DROP
``` 

### dropvame XMAS paketite
``` 
iptables -I INPUT -p tcp --tcp-flags ALL ALL -j DROP
``` 

### zashtita ot spoofing tcp
``` 
iptables -I INPUT -m conntrack --ctstate NEW,INVALID -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP
``` 

### fragment data loss
``` 
iptables -I INPUT -f -j DROP
``` 

# DROP BAD IPS
``` 
iptables -I INPUT -s 78.47.148.0/24 -j DROP #extreeme.info (Germany VPS)
iptables -I INPUT -s 94.236.237.0/24 -j DROP #lan-servers&uctt
iptables -I INPUT -s 94.236.211.0/24 -j DROP #lan-servers&uctt - 2
iptables -I INPUT -s 93.186.192.0/24 -j DROP #Second germany VPS
iptables -I INPUT -s 15.109.5.0/24 -j DROP #USA server - Hewlett-packard
iptables -I INPUT -s 153.38.3.0/24 -j DROP #USA Mci Communications Services
iptables -I INPUT -s 84.170.11.0/24 -j DROP #Germany telecom
iptables -I INPUT -s 193.171.69.0/24 -j DROP #Austria AConet
iptables -I INPUT -s 152.49.176.0/24 -j DROP #USA Education Network
iptables -I INPUT -s 113.140.96.0/24 -j DROP #Shaanxi Province Network
iptables -I INPUT -s 1.177.97.0/24 -j DROP #Korea, Republic Of Seoul Cj Hellovision 
iptables -I INPUT -s 175.68.5.0/24 -j DROP #China Beijing North Star Information Hi.tech Ltd. Co.
iptables -I INPUT -s 142.64.43.0/24 -j DROP #Canada Saint-jean-sur-richelieu Defense Nationale
iptables -I INPUT -s 69.107.149.0/24 -j DROP #United States Pleasanton Pltn13 Internal
iptables -I INPUT -s 74.167.32.0/24 -j DROP #United States Chattanooga Bellsouth.net Inc.
iptables -I INPUT -s 91.140.30.0/24 -j DROP #Greece Athens Tellas Telecommunication Services S.a.
iptables -I INPUT -s 122.136.154.0/24 -j DROP #China Changchun China Unicom Jilin Province Network
iptables -I INPUT -s 88.0.100.0/24 -j DROP #Spain Madrid Telefonica De Espana Sau
iptables -I INPUT -s 92.158.89.0/24 -j DROP #France Marseille Bsmar652 Marseille Bloc 
iptables -I INPUT -s 97.67.80.0/24 -j DROP #United States Oneonta Otelco
iptables -I INPUT -s 134.164.162.0/24 -j DROP #United States Fort Huachuca Headquarters Usaisc 
iptables -I INPUT -s 55.2.185.0/24 -j DROP #United States Fort Huachuca Headquarters Usaisc 
iptables -I INPUT -s 32.43.144.0/24 -j DROP #United States Lake Mary AT&T Global Network Services Llc 
iptables -I INPUT -s 192.93.3.0/24 -j DROP #France Montigny Universite De Paris Sud 
iptables -I INPUT -s 178.1.119.0/24 -j DROP #Germany Sulzbach Arcor Ag 
iptables -I INPUT -s 58.72.78.0/24 -j DROP #Korea, Republic Of Seoul Minchanggi 
iptables -I INPUT -s 12.193.120.0/24 -j DROP #United States Belleville AT&T Services Inc. 
iptables -I INPUT -s 18.154.59.0/24 -j DROP #United States Cambridge Massachusetts Institute Of Technology 
iptables -I INPUT -s 110.29.180.0/24 -j DROP #Taiwan Taipei Far Eastone Telecommunication Co. Ltd. 
iptables -I INPUT -s 87.124.141.0/24 -j DROP #United Kingdom Aldershot Fubra Limited 
iptables -I INPUT -s 128.188.90.0/24 -j DROP #United States Westborough Massachusetts Technology Park Corp. 
iptables -I INPUT -s 153.102.190.0/24 -j DROP #United States Fort Huachuca Headquarters Usaisc 
iptables -I INPUT -s 194.88.163.0/24 -j DROP #Germany Aalen Scholz Edelstahl Gmbh
iptables -I INPUT -s 35.139.125.0/24 -j DROP #United States Ann Arbor Merit Network Inc. 
iptables -I INPUT -s 32.12.173.0/24 -j DROP #United States Lake Mary AT&T Global Network Services Llc 
iptables -I INPUT -s 57.122.182.0/24 -j DROP #France Valbonne Sita-societe Internationale De Telecommunications Aeronautiques 
iptables -I INPUT -s 35.104.23.0/24 -j DROP #United States Ann Arbor Merit Network Inc. 
iptables -I INPUT -s 97.182.183.0/24 -j DROP #United States Walnut Creek Verizon Wireless 
iptables -I INPUT -s 38.149.6.0/24 -j DROP #United States Ridgefield Cogent Communications 
iptables -I INPUT -s 143.117.54.0/24 -j DROP #United Kingdom Belfast Queens University Belfast 
iptables -I INPUT -s 5.3.53.0/24 -j DROP #Russian Federation Saint Petersburg Perspectiva Ltd. 
iptables -I INPUT -s 110.173.168.0/24 -j DROP #New Zealand Taupo Ruralinzone Sat Clients 
iptables -I INPUT -s 50.97.141.0/24 -j DROP #United States Dallas Softlayer Technologies Inc. 
iptables -I INPUT -s 73.80.54.0/24 -j DROP #United States Mount Laurel Comcast Ip Services L.l.c. 
iptables -I INPUT -s 198.88.193.0/24 -j DROP #United States Englewood Ntt America Inc. 
iptables -I INPUT -s 184.51.91.0/24 -j DROP #United States Cambridge Akamai Technologies Inc. 
iptables -I INPUT -s 142.22.198.0/24 -j DROP #Canada Victoria Province Of British Columbia 
iptables -I INPUT -s 139.13.24.0/24 -j DROP #Germany Leer Fh Oow
iptables -I INPUT -s 131.104.138.0/24 -j DROP #Canada Guelph University Of Guelph 
iptables -I INPUT -s 66.8.39.0/24 -j DROP #South Africa Cape Town Mtn Business Solutions (pty) Ltd 
iptables -I INPUT -s 76.186.85.0/24 -j DROP #United States Dallas Road Runner Holdco Llc 
iptables -I INPUT -s 73.90.102.0/24 -j DROP #United States Mount Laurel Comcast Ip Services L.l.c.
iptables -I INPUT -s 35.133.91.0/24 -j DROP #United States Ann Arbor Merit Network Inc. 
iptables -I INPUT -s 67.124.29.0/24 -j DROP #United States Los Angeles AT&T Internet Services
iptables -I INPUT -s 123.110.195.0/24 -j DROP #Taiwan Banqiao Tbc 
iptables -I INPUT -s 132.150.113.0/24 -j DROP #Norway Oslo Norwegian Central Governmental Offices
iptables -I INPUT -s 24.73.164.0/24 -j DROP #United States Orlando Road Runner Holdco Llc 
iptables -I INPUT -s 12.144.41.0/24 -j DROP #United States New Brunswick AT&T Services Inc.
iptables -I INPUT -s 92.26.78.0/24 -j DROP #United Kingdom Swansea Opal Telecom Dsl
iptables -I INPUT -s 121.93.128.0/24 -j DROP #Japan Nara-shi Infoweb 
iptables -I INPUT -s 92.110.194.0/24 -j DROP #Netherlands Amsterdam Upc Broadband Operations B.v. 
iptables -I INPUT -s 68.140.123.0/24 -j DROP #United States Ashburn Uunet Technologies Inc. 
iptables -I INPUT -s 99.49.133.0/24 -j DROP #United States Rockford AT&T Internet Services 
iptables -I INPUT -s 168.15.134.0/24 -j DROP #United States Athens Board Of Regents Of The University System Of Georgia 
iptables -I INPUT -s 174.120.182.0/24 -j DROP #United States Dallas Theplanet.com Internet Services Inc. 
iptables -I INPUT -s 75.137.103.0/24 -j DROP #United States Greenville Charter Communications 
iptables -I INPUT -s 174.109.188.0/24 -j DROP #United States Raleigh Road Runner Holdco Llc 
iptables -I INPUT -s 37.141.52.0/24 -j DROP #Saudi Arabia Riyadh Bayanat Al-oula For Network Services 
iptables -I INPUT -s 168.31.165.0/24 -j DROP #United States Athens Board Of Regents Of The University System Of Georgia 
iptables -I INPUT -s 182.163.127.0/24 -j DROP #Bangladesh Dhaka Bangladesh Online Ltd 
iptables -I INPUT -s 12.63.197.0/24 -j DROP #United States Middletown Deprod_pool Lvp3n13a 
iptables -I INPUT -s 68.110.58.0/24 -j DROP #United States Omaha Cox Communications Inc. 
iptables -I INPUT -s 108.194.174.0/24 -j DROP #United States Houston AT&T Internet Services 
iptables -I INPUT -s 147.143.108.0/24 -j DROP #United Kingdom Bangor University Of Wales Bangor 
iptables -I INPUT -s 140.47.134.0/24 -j DROP #United States Columbus Dod Network Information Center 
iptables -I INPUT -s 183.44.150.0/24 -j DROP #China Guangzhou Chinanet Guangdong Province Network 
iptables -I INPUT -s 182.197.136.0/24 -j DROP #Korea, Republic Of Seoul Samsungsds Inc. 
iptables -I INPUT -s 119.105.121.0/24 -j DROP #Japan Tokyo Dion 
iptables -I INPUT -s 44.100.97.0/24 -j DROP #United States La Jolla Amateur Radio Digital Communications 
iptables -I INPUT -s 44.56.97.0/24 -j DROP #United States La Jolla Amateur Radio Digital Communications 
iptables -I INPUT -s 1.123.11.0/24 -j DROP #Australia Adelaide Telstra 
iptables -I INPUT -s 38.96.51.0/24 -j DROP #United States Washington Cogent Communications 
iptables -I INPUT -s 67.68.151.0/24 -j DROP #Canada Sherbrooke Hse 
iptables -I INPUT -s 14.192.151.0/24 -j DROP #Pakistan Karachi Internet Service Provider 
iptables -I INPUT -s 62.124.83.0/24 -j DROP #Netherlands Amsterdam Verizon Nederland B.v. 
iptables -I INPUT -s 170.145.147.0/24 -j DROP #United States Baton Rouge Louisiana Dept. Of Public Safety 
iptables -I INPUT -s 27.44.45.0/24 -j DROP #China Guangzhou China Unicom Guangdong Province Network 
iptables -I INPUT -s 79.15.138.0/24 -j DROP #Italy Roma Telecom Italia Net 
iptables -I INPUT -s 38.152.112.0/24 -j DROP #United States White Lake Cogent Communications 
iptables -I INPUT -s 122.194.102.0/24 -j DROP #China Nanjing China Unicom Jiangsu Province Network  
iptables -I INPUT -s 3.20.39.0/24 -j DROP #United States Fairfield General Electric Company 
iptables -I INPUT -s 67.132.14.0/24 -j DROP #United States Boston Qwest Communications
iptables -I INPUT -s 172.152.194.0/24 -j DROP #United States Reston America Online 
iptables -I INPUT -s 114.57.81.0/24 -j DROP #Indonesia Jakarta Pt. Indosat Mega Media 
iptables -I INPUT -s 79.149.21.0/24 -j DROP #Spain Madrid Telefonica Moviles Espana 
iptables -I INPUT -s 73.140.155.0/24 -j DROP #United States Mount Laurel Comcast Ip Services L.l.c. 
iptables -I INPUT -s 67.15.147.0/24 -j DROP #United States Dallas Theplanet.com Internet Services Inc. 
iptables -I INPUT -s 62.114.181.0/24 -j DROP #Egypt Cairo Nile Online 
iptables -I INPUT -s 128.120.16.0/24 -j DROP #United States Davis University Of California Davis 
iptables -I INPUT -s 38.139.62.0/24 -j DROP #United States Washington Cogent Communications 
iptables -I INPUT -s 124.103.197.0/24 -j DROP #Japan Osaka-shi Open Computer Network 
iptables -I INPUT -s 62.57.82.0/24 -j DROP #Spain Basauri Cable I Televisio De Catalunya 
iptables -I INPUT -s 37.130.49.0/24 -j DROP #Poland Sochaczew Interkam S.c. Zbigniew Kowalewski Sylwia Szczepanik Dominik Szczepanik 
iptables -I INPUT -s 144.126.132.0/24 -j DROP #United States Baltimore Loyola University Maryland 
iptables -I INPUT -s 33.117.93.0/24 -j DROP #United States Columbus Dod Network Information Center 
iptables -I INPUT -s 134.49.195.0/24 -j DROP #United States Moscow Advanced Hardware Architectures 
iptables -I INPUT -s 70.97.4.0/24 -j DROP #United States Reno Integra Telecom Inc. 
iptables -I INPUT -s 166.69.36.0/24 -j DROP #United States Schaumburg Motorola Mnic 
iptables -I INPUT -s 49.136.5.0/24 -j DROP #India Kolkata Bharti Airtel Ltd.
iptables -I INPUT -s 81.17.20.0/24 -j DROP #Russian Federation Moscow Client
iptables -I INPUT -s 65.111.174.0/24 -j DROP #United States Fort Lauderdale Server Pronto 
iptables -I INPUT -s 202.29.238.0/24 -j DROP #Thailand Kalasin Uninet
iptables -I INPUT -s 198.101.149.0/24 -j DROP #United States San Antonio Rackspace Cloud Servers 
iptables -I INPUT -s 61.183.9.0/24 -j DROP #China Wuhan Chinanet Hubei Province Network 
iptables -I INPUT -s 210.109.0.0/24 -j DROP #Korea, Republic Of Seoul Krnic 
iptables -I INPUT -s 83.222.109.0/24 -j DROP #Russian Federation Moscow Joingame Hosting 
iptables -I INPUT -s 95.31.24.0/24 -j DROP #Russian Federation Moscow Static Ip Poool For Broadband Customers In Moscow 
iptables -I INPUT -s 84.254.41.0/24 -j DROP #Greece Athens Tellas Telecommunication Services S.a. 
iptables -I INPUT -s 89.248.173.0/24 -j DROP #Netherlands
iptables -I INPUT -s 212.113.36.0/24 -j DROP #Ukraine
iptables -I INPUT -s 46.45.177.0/24 -j DROP #Turkey
iptables -I INPUT -s 46.45.174.0/24 -j DROP #Turkey #2
iptables -I INPUT -s 46.45.168.0/24 -j DROP #Turkey #3
iptables -I INPUT -s 46.45.173.0/24 -j DROP #Turkey #4
iptables -I INPUT -s 213.128.84.0/24 -j DROP #Turkey #5
iptables -I INPUT -s 46.45.178.0/24 -j DROP #Turkey #6
iptables -I INPUT -s 46.45.182.0/24 -j DROP #Turkey #7
iptables -I INPUT -s 95.133.0.0/16 -j DROP #Ukraine Kiev Jsc Ukrtelecom 
iptables -I INPUT -s 46.39.24.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 46.61.59.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 31.162.18.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 95.221.71.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 109.95.74.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 188.17.85.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 77.232.10.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 109.187.78.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 128.204.7.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 77.94.111.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 176.96.80.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 80.76.241.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 81.200.24.0/24 -j DROP #Russian Federation (HLBRUTE)
iptables -I INPUT -s 94.179.225.0/24 -j DROP #Ukraine (HLBRUTE)
iptables -I INPUT -s 95.132.223.0/24 -j DROP #Ukraine #2 (HLBRUTE)
iptables -I INPUT -s 178.92.82.0/24 -j DROP #Ukraine #3 (HLBRUTE)
iptables -I INPUT -s 94.179.240.0/24 -j DROP #Ukraine #4 (HLBRUTE)
iptables -I INPUT -s 31.41.95.0/24 -j DROP #Ukraine #5 (HLBRUTE)
iptables -I INPUT -s 83.86.164.0/24 -j DROP #Netherlands (HLBRUTE)
iptables -I INPUT -s 178.123.23.0/24 -j DROP #Belarus (HLBRUTE)
iptables -I INPUT -s 65.55.11.0/24 -j DROP #United States New York City Microsoft Corp 
iptables -I INPUT -s 64.31.15.244 -j DROP #Australia Richmond David Wilson
``` 
 
### nqkolko izvestni hlproxy ip-ta
``` 
iptables -I INPUT -s 62.192.232.29 -j DROP #HLPROXY
iptables -I INPUT -s 178.217.210.103 -j DROP #HLPROXY
iptables -I INPUT -s 92.244.150.126 -j DROP #HLPROXY
iptables -I INPUT -s 93.79.173.47 -j DROP #HLPROXY
iptables -I INPUT -s 89.45.71.86 -j DROP #HLPROXY
iptables -I INPUT -s 78.97.248.238 -j DROP #HLPROXY
iptables -I INPUT -s 178.75.220.26 -j DROP #HLPROXY
iptables -I INPUT -s 109.87.48.17 -j DROP #HLPROXY
iptables -I INPUT -s 86.100.201.67 -j DROP #HLPROXY
iptables -I INPUT -s 95.79.25.83 -j DROP #HLPROXY
iptables -I INPUT -s 87.255.95.87 -j DROP #HLPROXY
iptables -I INPUT -s 95.65.86.236 -j DROP #HLPROXY
iptables -I INPUT -s 46.46.75.196 -j DROP #HLPROXY
iptables -I INPUT -s 77.50.96.23 -j DROP #HLPROXY
iptables -I INPUT -s 77.50.96.23 -j DROP #HLPROXY
``` 

### DSHIELD bad ips (http://feeds.dshield.org/block.txt)
``` 
iptables -I INPUT -s 77.30.45.0/24 -j DROP #Saudi Arabia Dhahran Saudinet Saudi Telecom Company
iptables -I INPUT -s 211.162.79.0/24 -j DROP #China Guangzhou For Great Wall Broadband Network Service Access In Shenzhen 
iptables -I INPUT -s 141.212.121.0/24 -j DROP #United States Los Angeles University Of Michigan College Of Engineering  
iptables -I INPUT -s 85.25.243.0/24 -j DROP #Germany Frankfurt Am Main Intergenia Ag 
iptables -I INPUT -s 173.203.85.0/24 -j DROP #United States San Antonio Rackspace Hosting 
iptables -I INPUT -s 60.191.111.0/24 -j DROP #China Hangzhou South Environmental Project Co. Ltd 
iptables -I INPUT -s 46.211.37.0/24 -j DROP #Ukraine Kiev Kyivstar Gsm 
iptables -I INPUT -s 218.10.18.0/24 -j DROP #China Harbin China Unicom Heilongjiang Province Network 
iptables -I INPUT -s 62.28.131.0/24 -j DROP #Portugal Lisbon Pt Prime - Solucoes Empresariais 
iptables -I INPUT -s 83.232.227.0/24 -j DROP #Netherlands Maastricht Cillikens Brandstoffen B.v. 
iptables -I INPUT -s 213.165.74.0/24 -j DROP #Germany Karlsruhe 1&1 Internet Ag 
iptables -I INPUT -s 121.56.220.0/24 -j DROP #China Baotou Chinanet Neimeng Province Network 
iptables -I INPUT -s 118.123.213.0/24 -j DROP #China Chengdu Chinanet Sichuan Province Network 
iptables -I INPUT -s 92.255.176.0/24 -j DROP #Russian Federation Omsk Cjsc Er-telecom Holding 
iptables -I INPUT -s 98.158.145.0/24 -j DROP #United States Los Angeles Sacs Steel Inc. 
iptables -I INPUT -s 203.39.11.0/24 -j DROP #Australia Canberra Telstra Internet 
iptables -I INPUT -s 27.50.86.0/24 -j DROP #Australia Sydney Servers Australia Pty Ltd
iptables -I INPUT -s 69.10.37.0/24 -j DROP #United States Kansas City Interserver Inc 
``` 
 
### SPAMHOUSE EDROP (http://www.spamhaus.org/drop/edrop.txt) botnet list #1
``` 
iptables -I INPUT -s 31.44.184.0/24 -j DROP
iptables -I INPUT -s 46.166.131.0/24 -j DROP
iptables -I INPUT -s 81.94.43.0/24 -j DROP
iptables -I INPUT -s 86.55.96.0/23 -j DROP
iptables -I INPUT -s 91.226.78.0/24 -j DROP
iptables -I INPUT -s 91.229.90.0/23 -j DROP
iptables -I INPUT -s 91.232.235.0/24 -j DROP
iptables -I INPUT -s 91.233.89.0/24 -j DROP
iptables -I INPUT -s 142.0.192.0/24 -j DROP
iptables -I INPUT -s 188.247.232.0/24 -j DROP
iptables -I INPUT -s 195.88.230.0/23 -j DROP
``` 
### SPAM HOUSE DROP (http://www.spamhaus.org/drop/drop.txt) botnet list #2
``` 
iptables -I INPUT -s 5.62.128.0/17 -j DROP
iptables -I INPUT -s 5.72.0.0/14 -j DROP
iptables -I INPUT -s 14.192.0.0/19 -j DROP
iptables -I INPUT -s 14.192.48.0/21 -j DROP
iptables -I INPUT -s 14.192.56.0/22 -j DROP
iptables -I INPUT -s 31.11.43.0/24 -j DROP
iptables -I INPUT -s 31.14.103.0/24 -j DROP
iptables -I INPUT -s 31.42.128.0/19 -j DROP
iptables -I INPUT -s 31.184.242.0/24 -j DROP
iptables -I INPUT -s 31.222.200.0/21 -j DROP
iptables -I INPUT -s 37.9.58.0/24 -j DROP
iptables -I INPUT -s 37.139.49.0/24 -j DROP
iptables -I INPUT -s 37.148.216.0/21 -j DROP
iptables -I INPUT -s 37.230.212.0/24 -j DROP
iptables -I INPUT -s 37.246.0.0/16 -j DROP
iptables -I INPUT -s 58.83.8.0/22 -j DROP
iptables -I INPUT -s 62.122.32.0/21 -j DROP
iptables -I INPUT -s 62.122.72.0/23 -j DROP
iptables -I INPUT -s 62.182.152.0/21 -j DROP
iptables -I INPUT -s 63.141.32.0/19 -j DROP
iptables -I INPUT -s 64.15.0.0/20 -j DROP
iptables -I INPUT -s 64.44.0.0/16 -j DROP
iptables -I INPUT -s 64.112.0.0/17 -j DROP
iptables -I INPUT -s 64.112.128.0/18 -j DROP
iptables -I INPUT -s 64.185.224.0/20 -j DROP
iptables -I INPUT -s 64.234.224.0/20 -j DROP
iptables -I INPUT -s 66.231.64.0/20 -j DROP
iptables -I INPUT -s 67.211.208.0/20 -j DROP
iptables -I INPUT -s 67.213.128.0/20 -j DROP
iptables -I INPUT -s 67.218.208.0/20 -j DROP
iptables -I INPUT -s 72.13.16.0/20 -j DROP
iptables -I INPUT -s 72.50.192.0/19 -j DROP
iptables -I INPUT -s 74.123.96.0/21 -j DROP
iptables -I INPUT -s 78.31.184.0/21 -j DROP
iptables -I INPUT -s 79.110.16.0/20 -j DROP
iptables -I INPUT -s 79.110.48.0/20 -j DROP
iptables -I INPUT -s 79.110.160.0/20 -j DROP
iptables -I INPUT -s 79.110.176.0/20 -j DROP
iptables -I INPUT -s 81.4.0.0/18 -j DROP
iptables -I INPUT -s 81.22.152.0/23 -j DROP
iptables -I INPUT -s 81.162.128.0/18 -j DROP
iptables -I INPUT -s 84.22.96.0/19 -j DROP
iptables -I INPUT -s 85.120.94.0/23 -j DROP
iptables -I INPUT -s 85.121.39.0/24 -j DROP
iptables -I INPUT -s 85.202.160.0/20 -j DROP
iptables -I INPUT -s 85.202.192.0/20 -j DROP
iptables -I INPUT -s 86.55.140.0/24 -j DROP
iptables -I INPUT -s 86.55.210.0/23 -j DROP
iptables -I INPUT -s 88.135.16.0/20 -j DROP
iptables -I INPUT -s 89.45.14.0/24 -j DROP
iptables -I INPUT -s 89.114.9.0/24 -j DROP
iptables -I INPUT -s 89.114.97.0/24 -j DROP
iptables -I INPUT -s 91.193.110.0/23 -j DROP
iptables -I INPUT -s 91.193.192.0/22 -j DROP
iptables -I INPUT -s 91.194.0.0/23 -j DROP
iptables -I INPUT -s 91.195.10.0/23 -j DROP
iptables -I INPUT -s 91.195.254.0/23 -j DROP
iptables -I INPUT -s 91.197.96.0/22 -j DROP
iptables -I INPUT -s 91.198.109.0/24 -j DROP
iptables -I INPUT -s 91.198.127.0/24 -j DROP
iptables -I INPUT -s 91.200.164.0/22 -j DROP
iptables -I INPUT -s 91.200.176.0/22 -j DROP
iptables -I INPUT -s 91.200.248.0/22 -j DROP
iptables -I INPUT -s 91.201.4.0/22 -j DROP
iptables -I INPUT -s 91.201.124.0/22 -j DROP
iptables -I INPUT -s 91.201.236.0/22 -j DROP
iptables -I INPUT -s 91.203.92.0/22 -j DROP
iptables -I INPUT -s 91.204.40.0/21 -j DROP
iptables -I INPUT -s 91.206.200.0/23 -j DROP
iptables -I INPUT -s 91.208.162.0/24 -j DROP
iptables -I INPUT -s 91.208.228.0/24 -j DROP
iptables -I INPUT -s 91.209.14.0/24 -j DROP
iptables -I INPUT -s 91.209.48.0/24 -j DROP
iptables -I INPUT -s 91.209.58.0/24 -j DROP
iptables -I INPUT -s 91.209.63.0/24 -j DROP
iptables -I INPUT -s 91.209.183.0/24 -j DROP
iptables -I INPUT -s 91.209.184.0/24 -j DROP
iptables -I INPUT -s 91.209.186.0/24 -j DROP
iptables -I INPUT -s 91.209.238.0/24 -j DROP
iptables -I INPUT -s 91.210.172.0/22 -j DROP
iptables -I INPUT -s 91.211.64.0/22 -j DROP
iptables -I INPUT -s 91.212.41.0/24 -j DROP
iptables -I INPUT -s 91.212.45.0/24 -j DROP
iptables -I INPUT -s 91.212.65.0/24 -j DROP
iptables -I INPUT -s 91.212.123.0/24 -j DROP
iptables -I INPUT -s 91.212.135.0/24 -j DROP
iptables -I INPUT -s 91.212.198.0/24 -j DROP
iptables -I INPUT -s 91.212.201.0/24 -j DROP
iptables -I INPUT -s 91.212.220.0/24 -j DROP
iptables -I INPUT -s 91.213.29.0/24 -j DROP
iptables -I INPUT -s 91.213.72.0/24 -j DROP
iptables -I INPUT -s 91.213.93.0/24 -j DROP
iptables -I INPUT -s 91.213.94.0/24 -j DROP
iptables -I INPUT -s 91.213.157.0/24 -j DROP
iptables -I INPUT -s 91.213.174.0/24 -j DROP
iptables -I INPUT -s 91.213.175.0/24 -j DROP
iptables -I INPUT -s 91.213.217.0/24 -j DROP
iptables -I INPUT -s 91.216.3.0/24 -j DROP
iptables -I INPUT -s 91.216.11.0/24 -j DROP
iptables -I INPUT -s 91.216.73.0/24 -j DROP
iptables -I INPUT -s 91.216.190.0/24 -j DROP
iptables -I INPUT -s 91.217.162.0/24 -j DROP
iptables -I INPUT -s 91.217.178.0/24 -j DROP
iptables -I INPUT -s 91.217.200.0/24 -j DROP
iptables -I INPUT -s 91.217.249.0/24 -j DROP
iptables -I INPUT -s 91.220.35.0/24 -j DROP
iptables -I INPUT -s 91.220.62.0/24 -j DROP
iptables -I INPUT -s 91.220.90.0/24 -j DROP
iptables -I INPUT -s 91.223.77.0/24 -j DROP
iptables -I INPUT -s 91.226.10.0/23 -j DROP
iptables -I INPUT -s 91.228.39.0/24 -j DROP
iptables -I INPUT -s 91.228.132.0/24 -j DROP
iptables -I INPUT -s 91.229.46.0/23 -j DROP
iptables -I INPUT -s 91.229.248.0/24 -j DROP
iptables -I INPUT -s 91.230.110.0/24 -j DROP
iptables -I INPUT -s 91.230.111.0/24 -j DROP
iptables -I INPUT -s 91.230.143.0/24 -j DROP
iptables -I INPUT -s 91.230.147.0/24 -j DROP
iptables -I INPUT -s 91.231.156.0/24 -j DROP
iptables -I INPUT -s 91.235.2.0/24 -j DROP
iptables -I INPUT -s 91.236.120.0/24 -j DROP
iptables -I INPUT -s 91.236.121.0/24 -j DROP
iptables -I INPUT -s 91.238.82.0/24 -j DROP
iptables -I INPUT -s 91.238.180.0/23 -j DROP
iptables -I INPUT -s 91.239.15.0/24 -j DROP
iptables -I INPUT -s 91.239.24.0/24 -j DROP
iptables -I INPUT -s 91.240.165.0/24 -j DROP
iptables -I INPUT -s 91.242.217.0/24 -j DROP
iptables -I INPUT -s 91.243.115.0/24 -j DROP
iptables -I INPUT -s 93.120.32.0/19 -j DROP
iptables -I INPUT -s 93.168.18.0/23 -j DROP
iptables -I INPUT -s 93.168.20.0/23 -j DROP
iptables -I INPUT -s 93.168.22.0/23 -j DROP
iptables -I INPUT -s 93.168.24.0/23 -j DROP
iptables -I INPUT -s 93.174.164.0/24 -j DROP
iptables -I INPUT -s 93.175.240.0/20 -j DROP
iptables -I INPUT -s 94.60.121.0/24 -j DROP
iptables -I INPUT -s 94.60.122.0/23 -j DROP
iptables -I INPUT -s 94.61.247.0/24 -j DROP
iptables -I INPUT -s 94.63.146.0/24 -j DROP
iptables -I INPUT -s 94.63.147.0/24 -j DROP
iptables -I INPUT -s 94.63.149.0/24 -j DROP
iptables -I INPUT -s 94.63.150.0/23 -j DROP
iptables -I INPUT -s 94.63.240.0/24 -j DROP
iptables -I INPUT -s 94.63.243.0/24 -j DROP
iptables -I INPUT -s 94.63.244.0/24 -j DROP
iptables -I INPUT -s 94.63.245.0/24 -j DROP
iptables -I INPUT -s 94.63.246.0/24 -j DROP
iptables -I INPUT -s 94.63.247.0/24 -j DROP
iptables -I INPUT -s 94.130.0.0/15 -j DROP
iptables -I INPUT -s 94.154.128.0/18 -j DROP
iptables -I INPUT -s 94.158.240.0/20 -j DROP
iptables -I INPUT -s 94.232.248.0/21 -j DROP
iptables -I INPUT -s 95.64.11.0/24 -j DROP
iptables -I INPUT -s 95.64.13.0/24 -j DROP
iptables -I INPUT -s 95.64.98.0/23 -j DROP
iptables -I INPUT -s 95.215.140.0/22 -j DROP
iptables -I INPUT -s 95.216.0.0/15 -j DROP
iptables -I INPUT -s 103.10.68.0/22 -j DROP
iptables -I INPUT -s 103.14.208.0/22 -j DROP
iptables -I INPUT -s 103.246.72.0/22 -j DROP
iptables -I INPUT -s 109.94.208.0/20 -j DROP
iptables -I INPUT -s 110.44.128.0/20 -j DROP
iptables -I INPUT -s 110.232.160.0/20 -j DROP
iptables -I INPUT -s 113.20.160.0/19 -j DROP
iptables -I INPUT -s 116.197.152.0/21 -j DROP
iptables -I INPUT -s 116.199.128.0/19 -j DROP
iptables -I INPUT -s 119.42.40.0/22 -j DROP
iptables -I INPUT -s 121.46.64.0/18 -j DROP
iptables -I INPUT -s 122.202.96.0/19 -j DROP
iptables -I INPUT -s 128.168.0.0/16 -j DROP
iptables -I INPUT -s 128.199.0.0/16 -j DROP
iptables -I INPUT -s 129.76.64.0/18 -j DROP
iptables -I INPUT -s 130.201.0.0/16 -j DROP
iptables -I INPUT -s 130.222.0.0/16 -j DROP
iptables -I INPUT -s 132.145.0.0/16 -j DROP
iptables -I INPUT -s 132.232.0.0/16 -j DROP
iptables -I INPUT -s 134.23.0.0/16 -j DROP
iptables -I INPUT -s 134.33.0.0/16 -j DROP
iptables -I INPUT -s 134.127.0.0/16 -j DROP
iptables -I INPUT -s 134.172.0.0/16 -j DROP
iptables -I INPUT -s 134.209.0.0/16 -j DROP
iptables -I INPUT -s 136.228.0.0/16 -j DROP
iptables -I INPUT -s 138.43.0.0/16 -j DROP
iptables -I INPUT -s 139.167.0.0/16 -j DROP
iptables -I INPUT -s 140.170.0.0/16 -j DROP
iptables -I INPUT -s 141.136.16.0/24 -j DROP
iptables -I INPUT -s 141.136.17.0/24 -j DROP
iptables -I INPUT -s 141.136.22.0/24 -j DROP
iptables -I INPUT -s 141.136.27.0/24 -j DROP
iptables -I INPUT -s 143.49.0.0/16 -j DROP
iptables -I INPUT -s 143.135.0.0/16 -j DROP
iptables -I INPUT -s 146.185.218.0/24 -j DROP
iptables -I INPUT -s 146.185.235.0/24 -j DROP
iptables -I INPUT -s 146.185.239.0/24 -j DROP
iptables -I INPUT -s 146.185.254.0/24 -j DROP
iptables -I INPUT -s 147.50.0.0/16 -j DROP
iptables -I INPUT -s 148.105.0.0/16 -j DROP
iptables -I INPUT -s 148.178.0.0/16 -j DROP
iptables -I INPUT -s 148.248.0.0/16 -j DROP
iptables -I INPUT -s 150.126.0.0/16 -j DROP
iptables -I INPUT -s 150.141.0.0/16 -j DROP
iptables -I INPUT -s 151.123.0.0/16 -j DROP
iptables -I INPUT -s 152.147.0.0/16 -j DROP
iptables -I INPUT -s 155.190.0.0/16 -j DROP
iptables -I INPUT -s 157.226.0.0/16 -j DROP
iptables -I INPUT -s 157.231.0.0/16 -j DROP
iptables -I INPUT -s 157.232.0.0/17 -j DROP
iptables -I INPUT -s 157.232.0.0/16 -j DROP
iptables -I INPUT -s 159.223.0.0/16 -j DROP
iptables -I INPUT -s 161.232.0.0/16 -j DROP
iptables -I INPUT -s 162.125.0.0/16 -j DROP
iptables -I INPUT -s 167.28.0.0/16 -j DROP
iptables -I INPUT -s 167.97.0.0/16 -j DROP
iptables -I INPUT -s 167.224.0.0/19 -j DROP
iptables -I INPUT -s 170.67.0.0/16 -j DROP
iptables -I INPUT -s 170.106.0.0/16 -j DROP
iptables -I INPUT -s 170.113.0.0/16 -j DROP
iptables -I INPUT -s 170.120.0.0/16 -j DROP
iptables -I INPUT -s 171.25.190.0/24 -j DROP
iptables -I INPUT -s 173.205.0.0/21 -j DROP
iptables -I INPUT -s 173.205.8.0/21 -j DROP
iptables -I INPUT -s 173.205.16.0/21 -j DROP
iptables -I INPUT -s 173.205.24.0/21 -j DROP
iptables -I INPUT -s 173.205.32.0/21 -j DROP
iptables -I INPUT -s 173.205.40.0/21 -j DROP
iptables -I INPUT -s 173.205.48.0/21 -j DROP
iptables -I INPUT -s 173.249.160.0/19 -j DROP
iptables -I INPUT -s 176.47.0.0/16 -j DROP
iptables -I INPUT -s 178.159.176.0/20 -j DROP
iptables -I INPUT -s 186.190.224.0/21 -j DROP
iptables -I INPUT -s 188.211.24.0/23 -j DROP
iptables -I INPUT -s 188.247.135.0/24 -j DROP
iptables -I INPUT -s 188.247.230.0/24 -j DROP
iptables -I INPUT -s 192.26.25.0/24 -j DROP
iptables -I INPUT -s 192.31.212.0/23 -j DROP
iptables -I INPUT -s 192.43.153.0/24 -j DROP
iptables -I INPUT -s 192.43.154.0/23 -j DROP
iptables -I INPUT -s 192.43.156.0/22 -j DROP
iptables -I INPUT -s 192.43.160.0/24 -j DROP
iptables -I INPUT -s 192.43.175.0/24 -j DROP
iptables -I INPUT -s 192.43.176.0/21 -j DROP
iptables -I INPUT -s 192.43.184.0/24 -j DROP
iptables -I INPUT -s 192.67.16.0/24 -j DROP
iptables -I INPUT -s 192.67.160.0/22 -j DROP
iptables -I INPUT -s 192.86.85.0/24 -j DROP
iptables -I INPUT -s 192.101.200.0/21 -j DROP
iptables -I INPUT -s 192.101.240.0/21 -j DROP
iptables -I INPUT -s 192.101.248.0/23 -j DROP
iptables -I INPUT -s 192.112.112.0/20 -j DROP
iptables -I INPUT -s 192.160.44.0/24 -j DROP
iptables -I INPUT -s 192.171.64.0/19 -j DROP
iptables -I INPUT -s 192.197.87.0/24 -j DROP
iptables -I INPUT -s 192.219.120.0/21 -j DROP
iptables -I INPUT -s 192.219.128.0/18 -j DROP
iptables -I INPUT -s 192.219.192.0/20 -j DROP
iptables -I INPUT -s 192.219.208.0/21 -j DROP
iptables -I INPUT -s 192.223.64.0/18 -j DROP
iptables -I INPUT -s 192.229.32.0/19 -j DROP
iptables -I INPUT -s 193.0.212.0/24 -j DROP
iptables -I INPUT -s 193.16.100.0/24 -j DROP
iptables -I INPUT -s 193.16.213.0/24 -j DROP
iptables -I INPUT -s 193.23.126.0/24 -j DROP
iptables -I INPUT -s 193.27.232.0/23 -j DROP
iptables -I INPUT -s 193.27.246.0/23 -j DROP
iptables -I INPUT -s 193.41.38.0/24 -j DROP
iptables -I INPUT -s 193.43.134.0/24 -j DROP
iptables -I INPUT -s 193.46.211.0/24 -j DROP
iptables -I INPUT -s 193.104.12.0/24 -j DROP
iptables -I INPUT -s 193.104.34.0/24 -j DROP
iptables -I INPUT -s 193.104.41.0/24 -j DROP
iptables -I INPUT -s 193.104.94.0/24 -j DROP
iptables -I INPUT -s 193.104.110.0/24 -j DROP
iptables -I INPUT -s 193.104.176.0/24 -j DROP
iptables -I INPUT -s 193.105.141.0/24 -j DROP
iptables -I INPUT -s 193.105.154.0/24 -j DROP
iptables -I INPUT -s 193.105.184.0/24 -j DROP
iptables -I INPUT -s 193.105.207.0/24 -j DROP
iptables -I INPUT -s 193.105.245.0/24 -j DROP
iptables -I INPUT -s 193.106.32.0/22 -j DROP
iptables -I INPUT -s 193.107.16.0/22 -j DROP
iptables -I INPUT -s 193.108.178.0/24 -j DROP
iptables -I INPUT -s 193.110.136.0/24 -j DROP
iptables -I INPUT -s 193.111.235.0/24 -j DROP
iptables -I INPUT -s 193.148.47.0/24 -j DROP
iptables -I INPUT -s 193.169.250.0/23 -j DROP
iptables -I INPUT -s 193.178.120.0/22 -j DROP
iptables -I INPUT -s 193.178.172.0/24 -j DROP
iptables -I INPUT -s 193.200.167.0/24 -j DROP
iptables -I INPUT -s 193.201.192.0/23 -j DROP
iptables -I INPUT -s 193.227.240.0/23 -j DROP
iptables -I INPUT -s 193.228.145.0/24 -j DROP
iptables -I INPUT -s 193.243.166.0/24 -j DROP
iptables -I INPUT -s 194.1.184.0/24 -j DROP
iptables -I INPUT -s 194.1.220.0/23 -j DROP
iptables -I INPUT -s 194.29.185.0/24 -j DROP
iptables -I INPUT -s 194.44.4.0/24 -j DROP
iptables -I INPUT -s 194.50.116.0/24 -j DROP
iptables -I INPUT -s 194.54.156.0/22 -j DROP
iptables -I INPUT -s 194.60.242.0/24 -j DROP
iptables -I INPUT -s 194.63.144.0/22 -j DROP
iptables -I INPUT -s 194.110.160.0/22 -j DROP
iptables -I INPUT -s 194.116.146.0/23 -j DROP
iptables -I INPUT -s 194.126.193.0/24 -j DROP
iptables -I INPUT -s 194.126.251.0/24 -j DROP
iptables -I INPUT -s 194.140.229.0/24 -j DROP
iptables -I INPUT -s 194.165.4.0/23 -j DROP
iptables -I INPUT -s 194.242.2.0/23 -j DROP
iptables -I INPUT -s 195.2.212.0/23 -j DROP
iptables -I INPUT -s 195.5.161.0/24 -j DROP
iptables -I INPUT -s 195.14.112.0/23 -j DROP
iptables -I INPUT -s 195.20.141.0/24 -j DROP
iptables -I INPUT -s 195.28.10.0/23 -j DROP
iptables -I INPUT -s 195.43.128.0/24 -j DROP
iptables -I INPUT -s 195.54.162.0/23 -j DROP
iptables -I INPUT -s 195.78.108.0/23 -j DROP
iptables -I INPUT -s 195.85.204.0/24 -j DROP
iptables -I INPUT -s 195.88.190.0/23 -j DROP
iptables -I INPUT -s 195.88.226.0/23 -j DROP
iptables -I INPUT -s 195.93.184.0/23 -j DROP
iptables -I INPUT -s 195.93.208.0/23 -j DROP
iptables -I INPUT -s 195.95.155.0/24 -j DROP
iptables -I INPUT -s 195.114.8.0/23 -j DROP
iptables -I INPUT -s 195.149.88.0/24 -j DROP
iptables -I INPUT -s 195.149.90.0/24 -j DROP
iptables -I INPUT -s 195.162.6.0/23 -j DROP
iptables -I INPUT -s 195.182.57.0/24 -j DROP
iptables -I INPUT -s 195.184.86.0/23 -j DROP
iptables -I INPUT -s 195.190.157.0/24 -j DROP
iptables -I INPUT -s 195.191.102.0/23 -j DROP
iptables -I INPUT -s 195.225.176.0/22 -j DROP
iptables -I INPUT -s 195.226.197.0/24 -j DROP
iptables -I INPUT -s 195.226.220.0/24 -j DROP
iptables -I INPUT -s 195.246.200.0/24 -j DROP
iptables -I INPUT -s 198.13.0.0/20 -j DROP
iptables -I INPUT -s 198.20.16.0/20 -j DROP
iptables -I INPUT -s 198.23.32.0/20 -j DROP
iptables -I INPUT -s 198.45.32.0/20 -j DROP
iptables -I INPUT -s 198.48.16.0/20 -j DROP
iptables -I INPUT -s 198.57.64.0/20 -j DROP
iptables -I INPUT -s 198.96.224.0/20 -j DROP
iptables -I INPUT -s 198.151.64.0/18 -j DROP
iptables -I INPUT -s 198.151.152.0/22 -j DROP
iptables -I INPUT -s 198.162.208.0/20 -j DROP
iptables -I INPUT -s 198.181.64.0/19 -j DROP
iptables -I INPUT -s 198.183.32.0/19 -j DROP
iptables -I INPUT -s 198.186.25.0/24 -j DROP
iptables -I INPUT -s 198.204.0.0/21 -j DROP
iptables -I INPUT -s 198.205.64.0/19 -j DROP
iptables -I INPUT -s 199.5.152.0/23 -j DROP
iptables -I INPUT -s 199.9.24.0/21 -j DROP
iptables -I INPUT -s 199.26.96.0/19 -j DROP
iptables -I INPUT -s 199.33.145.0/24 -j DROP
iptables -I INPUT -s 199.34.128.0/18 -j DROP
iptables -I INPUT -s 199.46.32.0/19 -j DROP
iptables -I INPUT -s 199.58.248.0/21 -j DROP
iptables -I INPUT -s 199.60.102.0/24 -j DROP
iptables -I INPUT -s 199.71.192.0/20 -j DROP
iptables -I INPUT -s 199.84.64.0/19 -j DROP
iptables -I INPUT -s 199.84.96.0/19 -j DROP
iptables -I INPUT -s 199.88.32.0/20 -j DROP
iptables -I INPUT -s 199.88.48.0/22 -j DROP
iptables -I INPUT -s 199.89.16.0/20 -j DROP
iptables -I INPUT -s 199.120.163.0/24 -j DROP
iptables -I INPUT -s 199.165.32.0/19 -j DROP
iptables -I INPUT -s 199.166.200.0/22 -j DROP
iptables -I INPUT -s 199.185.192.0/20 -j DROP
iptables -I INPUT -s 199.196.192.0/19 -j DROP
iptables -I INPUT -s 199.198.160.0/20 -j DROP
iptables -I INPUT -s 199.198.176.0/21 -j DROP
iptables -I INPUT -s 199.198.184.0/23 -j DROP
iptables -I INPUT -s 199.198.188.0/22 -j DROP
iptables -I INPUT -s 199.200.64.0/19 -j DROP
iptables -I INPUT -s 199.212.96.0/20 -j DROP
iptables -I INPUT -s 199.230.64.0/19 -j DROP
iptables -I INPUT -s 199.230.96.0/21 -j DROP
iptables -I INPUT -s 199.245.138.0/24 -j DROP
iptables -I INPUT -s 199.246.137.0/24 -j DROP
iptables -I INPUT -s 199.246.213.0/24 -j DROP
iptables -I INPUT -s 199.246.215.0/24 -j DROP
iptables -I INPUT -s 199.248.64.0/18 -j DROP
iptables -I INPUT -s 199.254.32.0/20 -j DROP
iptables -I INPUT -s 202.61.108.0/24 -j DROP
iptables -I INPUT -s 203.31.88.0/23 -j DROP
iptables -I INPUT -s 203.34.70.0/23 -j DROP
iptables -I INPUT -s 203.34.71.0/24 -j DROP
iptables -I INPUT -s 204.44.192.0/20 -j DROP
iptables -I INPUT -s 204.44.224.0/20 -j DROP
iptables -I INPUT -s 204.52.255.0/24 -j DROP
iptables -I INPUT -s 204.57.16.0/20 -j DROP
iptables -I INPUT -s 204.89.224.0/24 -j DROP
iptables -I INPUT -s 204.106.128.0/18 -j DROP
iptables -I INPUT -s 204.106.192.0/19 -j DROP
iptables -I INPUT -s 204.107.208.0/24 -j DROP
iptables -I INPUT -s 204.126.244.0/23 -j DROP
iptables -I INPUT -s 204.130.167.0/24 -j DROP
iptables -I INPUT -s 204.147.240.0/20 -j DROP
iptables -I INPUT -s 204.152.224.0/21 -j DROP
iptables -I INPUT -s 204.155.128.0/20 -j DROP
iptables -I INPUT -s 204.187.155.0/24 -j DROP
iptables -I INPUT -s 204.187.156.0/22 -j DROP
iptables -I INPUT -s 204.187.160.0/19 -j DROP
iptables -I INPUT -s 204.187.192.0/19 -j DROP
iptables -I INPUT -s 204.187.224.0/20 -j DROP
iptables -I INPUT -s 204.187.240.0/21 -j DROP
iptables -I INPUT -s 204.187.248.0/22 -j DROP
iptables -I INPUT -s 204.187.252.0/23 -j DROP
iptables -I INPUT -s 204.187.254.0/24 -j DROP
iptables -I INPUT -s 204.194.184.0/21 -j DROP
iptables -I INPUT -s 204.225.159.0/24 -j DROP
iptables -I INPUT -s 204.225.210.0/24 -j DROP
iptables -I INPUT -s 204.236.0.0/19 -j DROP
iptables -I INPUT -s 204.237.136.0/21 -j DROP
iptables -I INPUT -s 204.237.168.0/21 -j DROP
iptables -I INPUT -s 204.237.232.0/21 -j DROP
iptables -I INPUT -s 204.237.240.0/21 -j DROP
iptables -I INPUT -s 205.137.0.0/20 -j DROP
iptables -I INPUT -s 205.142.104.0/22 -j DROP
iptables -I INPUT -s 205.144.0.0/20 -j DROP
iptables -I INPUT -s 205.144.176.0/20 -j DROP
iptables -I INPUT -s 205.159.180.0/24 -j DROP
iptables -I INPUT -s 205.172.244.0/22 -j DROP
iptables -I INPUT -s 205.175.160.0/19 -j DROP
iptables -I INPUT -s 205.189.71.0/24 -j DROP
iptables -I INPUT -s 205.189.72.0/23 -j DROP
iptables -I INPUT -s 205.203.0.0/19 -j DROP
iptables -I INPUT -s 205.203.224.0/19 -j DROP
iptables -I INPUT -s 205.214.128.0/19 -j DROP
iptables -I INPUT -s 205.233.224.0/20 -j DROP
iptables -I INPUT -s 205.235.64.0/20 -j DROP
iptables -I INPUT -s 205.236.189.0/24 -j DROP
iptables -I INPUT -s 206.81.0.0/19 -j DROP
iptables -I INPUT -s 206.123.128.0/19 -j DROP
iptables -I INPUT -s 206.197.28.0/24 -j DROP
iptables -I INPUT -s 206.197.29.0/24 -j DROP
iptables -I INPUT -s 206.197.175.0/24 -j DROP
iptables -I INPUT -s 206.201.48.0/20 -j DROP
iptables -I INPUT -s 206.203.64.0/18 -j DROP
iptables -I INPUT -s 206.209.80.0/20 -j DROP
iptables -I INPUT -s 206.224.160.0/19 -j DROP
iptables -I INPUT -s 206.227.64.0/18 -j DROP
iptables -I INPUT -s 207.22.192.0/18 -j DROP
iptables -I INPUT -s 207.32.128.0/19 -j DROP
iptables -I INPUT -s 207.183.192.0/19 -j DROP
iptables -I INPUT -s 207.189.0.0/19 -j DROP
iptables -I INPUT -s 208.70.168.0/21 -j DROP
iptables -I INPUT -s 208.81.136.0/21 -j DROP
iptables -I INPUT -s 208.85.32.0/21 -j DROP
iptables -I INPUT -s 208.90.0.0/21 -j DROP
iptables -I INPUT -s 208.93.96.0/21 -j DROP
iptables -I INPUT -s 208.117.80.0/20 -j DROP
iptables -I INPUT -s 209.51.32.0/20 -j DROP
iptables -I INPUT -s 209.95.192.0/19 -j DROP
iptables -I INPUT -s 209.145.0.0/19 -j DROP
iptables -I INPUT -s 209.148.64.0/19 -j DROP
iptables -I INPUT -s 209.182.64.0/19 -j DROP
iptables -I INPUT -s 209.198.176.0/20 -j DROP
iptables -I INPUT -s 213.109.96.0/22 -j DROP
iptables -I INPUT -s 213.109.208.0/20 -j DROP
iptables -I INPUT -s 216.151.192.0/20 -j DROP
iptables -I INPUT -s 216.162.112.0/20 -j DROP
iptables -I INPUT -s 216.212.192.0/19 -j DROP
``` 

### Loshi BG ip-ta
``` 
iptables -I INPUT -s 79.132.20.27 -j DROP #Bulgaria Burgas Comnet Bulgaria Holding Ltd. 
iptables -I INPUT -s 95.158.151.2 -j DROP #Bulgaria Pleven Novatel Eood 
iptables -I INPUT -s 87.121.243.38 -j DROP #Bulgaria Ip Address Range For Evo - Vt
iptables -I INPUT -s 212.72.195.5 -j DROP #Bulgaria Sofia Net Is Sat Ltd.
iptables -I INPUT -s 78.142.51.58 -j DROP #Bulgaria Sofia Powernet Ltd 
iptables -I INPUT -s 88.87.0.179 -j DROP #Bulgaria Sofia Telnet Limited 
iptables -I INPUT -s 77.70.47.96 -j DROP #Bulgaria Megalan
iptables -I INPUT -s 77.70.103.186 -j DROP #Bulgaria Mobiltel Ead
iptables -I INPUT -s 77.78.22.70 -j DROP #Bulgaria NetworkX
iptables -I INPUT -s 91.92.177.156 -j DROP #Bulgaria Evro Network
iptables -I INPUT -s 91.92.177.142 -j DROP #Bulgaria Evro Network
iptables -I INPUT -s 91.148.150.59 -j DROP #Bulgaria Powernet
iptables -I INPUT -s 91.148.150.30 -j DROP #Bulgaria Powernet
iptables -I INPUT -s 212.233.234.0/24 -j DROP #Bulgaria Optisprint (djreturn home`)
iptables -I INPUT -s 212.233.213.0/24 -j DROP #Bulgaria Optisprint (djreturn home`)
iptables -I INPUT -s 212.233.133.0/24 -j DROP #Bulgaria Optisprint (djreturn home`)
iptables -I INPUT -s 84.54.145.143 -j DROP #Bulgaria Comnet
iptables -I INPUT -s 87.121.241.49 -j DROP #Bulgaria Citynet
iptables -I INPUT -s 87.121.240.236 -j DROP #Bulgaria Citynet
iptables -I INPUT -s 87.121.241.234 -j DROP #Bulgaria Citynet
iptables -I INPUT -s 87.121.239.240 -j DROP #Bulgaria Citynet
iptables -I INPUT -s 87.120.185.234 -j DROP #Bulgaria Citynet
iptables -I INPUT -s 109.199.148.105 -j DROP #Bulgaria Telnet
iptables -I INPUT -s 91.148.150.111 -j DROP #Bulgaria Sofia Powernet
iptables -I INPUT -s 78.83.92.236 -j DROP #Bulgaria SpectrumNET (PON)
iptables -I INPUT -s 213.222.47.113 -j DROP #Bulgaria Kazanlak Orbitel
iptables -I INPUT -s 93.123.50.237 -j DROP #Bulgaria Sofia Pladi Computers Ltd. Lovech 
iptables -I INPUT -s 85.239.139.9 -j DROP #Bulgaria CIS (Cable Internet Systems Ltd)
iptables -I INPUT -s 77.70.14.122 -j DROP #Bulgaria Megalan
``` 
