#Basic Nfo Firewalls 
### All TCP Bypass's are patched with this

### Create chains ###
```
iptables -N syn_flood
iptables -N LOGGING
iptables -N port-scanning 
 ```
 
### Drop invalid packets ### 
```
/sbin/iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP  
```

### Drop TCP packets that are new and are not SYN ### 
```
/sbin/iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP 
```

### Drop SYN packets with suspicious MSS value ### 
```
/sbin/iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP    
 ```
 
### Drop fragments in all chains ### 
```
iptables -t mangle -A PREROUTING -f -j DROP  
```

### Limit connections per source IP ### 
```
iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset  
 ```
 
### Limit RST packets ### 
```
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP  
```

### Limit new TCP connections per second per source IP ### 
```
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT 
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP  
 ```
 
### SSH brute-force protection ### 
```
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j LOGGING  
 ```
 
### Protection against port scanning ### 
```
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j LOGGING 
iptables -A port-scanning -j DROP
``` 

### Protection against SYN flood ###
```
iptables -A INPUT -p tcp --syn -j syn_flood
iptables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j LOGGING
iptables -A syn_flood -j DROP
 ```
### Logging section ###
```
iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A LOGGING -j DROP;
```
