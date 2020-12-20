# All these methods are shitty AMP attacks that are supposed to be called "bypasses"

### Summary to patch all his shitty methods and some more that he will possibly release soon
### Dropping all common AMP source ports
iptables -t mangle -A PREROUTING -p udp -m multiport --sports 3283,37810,7001,17185,3072,3702,32414,177,6881,5683,41794,2362,11211,53413,17,1900,10001,389,137,5351,502 -j DROP

### FN-LAG Patch | Method Patch
### Port 37810 | Used by DVR IP Camera | UDP
```
iptables -t mangle -A PREROUTING -p udp --sport 37810 -j DROP
 ```

### OVH-KILL Patch | OVH Bypass Patch
### Port 7001 | Used by WLS | UDP
```
iptables -t mangle -A PREROUTING -p udp --sport 7001 -j DROP
iptables -I INPUT -p udp -m length --length 100:140 -m string --string "nAFS" --algo kmp -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j DROP  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 10/sec --limit-burst 15 -j ACCEPT
iptables -A INPUT -p tcp --sport 80 --syn -m state --state NEW -m limit --limit 400/sec --limit-burst 15 -j ACCEPT iptables -A INPUT -p tcp -m connlimit --connlimit-above 150 -j DROP iptables -A INPUT -p tcp --sport 443 --syn -m state --state NEW -m limit --limit 400/sec --limit-burst 15 -j ACCEPT iptables -FORWARD DROP ovh kill patch
```

### OVH-SLAP Patch | OVH Bypass Patch
### Port 17185 | Used by vxWorks//VoIP | UDP
```
iptables -t mangle -A PREROUTING -p udp --sport 17185 -j DROP
 ```

### OVH-DOWN & OVH-DOWNv2 Patch | OVH Bypass Patch | Found on Rebirth Panel by SelfRepNetis
### Port 3072 | Used by WSD | TCP or UDP
```
iptables -t mangle -A PREROUTING -p udp -m multiport --sports 3072,3702 -j DROP
iptables -t mangle -A PREROUTING -p tcp -m multiport --sports 3072,3702 -j DROP
 ```

### OVH-CRUSHv2 Patch | OVH Bypass Patch
### Literally no difference in OVH-CRUSH and OVH-CRUSHv2, just posting a method and renaming it to v2
### Port 3283 | Used by ARD | UDP AMP
```
iptables -t mangle -A PREROUTING -p udp --sport 3283 -m length --length 1048 -j DROP
 ```

### OVH-CRUSH Patch | OVH Bypass Patch | Found on Rebirth Panel by SelfRepNetis
### Port 3283 | Used by ARD | UDP AMP
```
iptables -t mangle -A PREROUTING -p udp --sport 3283 -m length --length 1048 -j DROP
 ```

### NFO-LAG Patch | NFO Method Patch
### Port 32414 | Used by PlexMediaServers | UDP
```
iptables -t mangle -A PREROUTING -p udp --sport 32414 -j DROP
```

### Port 177 | Used by XDMCP | UDP
```
iptables -t mangle -A PREROUTING -p udp --sport 177 -j DROP
 ```

### NFO-CLAP Patch | NFO Method Patch
### Port 6881 | Used by BitTorrent | UDP
```
iptables -t mangle -A PREROUTING -p udp --sport 6881 -m length --length 320:330 -j DROP
 ```

### R6-LAG Patch | Method Patch
### Port 32414 | Used by PlexMediaServers | UDP
```
iptables -t mangle -A PREROUTING -p udp -m length --length 280:300 --sport 32414 -j DROP
```
