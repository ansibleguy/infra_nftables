# NFTables example

## Config

```yaml
nftables:
  tables:
    example:
      vars:
        dns_servers: ['1.1.1.1', '1.1.0.0', '8.8.8.8', '8.8.4.4']
        private_ranges: ['192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8']

      sets:
        blacklist:
          flags: ['dynamic', 'timeout']
          settings:
            timeout: '3m'

      counters:
        invalid_packages:
          comment: 'Invalid'

      chains:
        incoming:
          hook: 'input'
          vars:
            unused: '1.1.1.1'

          rules:
            - sequence: 1
              raw: 'ct state invalid counter name invalid_packages log prefix "DROP invalid sates" drop'
            - seq: 2
              raw: 'ct state {established, related} counter accept comment "Allow open sessions"'
            - s: 3
              raw: 'iifname "lo" accept comment "Allow loopback traffic"'
            - 'icmp type { echo-request} limit rate 5/second accept comment "Allow icmp-ping"'
            - 'icmpv6 type { echo-request} limit rate 5/second accept comment "Allow icmp-ping"'
            - 'icmp code 30 limit rate 5/second accept comment "Allow icmp-traceroute"'
            - 'icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept comment "Allow necessary icmpv6-types for ipv6 to work"'
            - {proto: 'udp', port: 46251, counter: 'invalid_packages'}

        outgoing:
          hook: 'output'
          # policy: 'accept'
          rules:
            - {dest: '$dns_servers', proto: 'udp', port: 53}
            - {dest: '$dns_servers', proto: 'tcp', port: [53, 853]}
            - {proto: ['tcp', 'udp'], port: [80, 443]}
            - {proto: ['icmp', 'icmpv6'], comment: 'Allow outbound icmp'}

        translate:
          hook: 'postrouting'
          type: 'nat'
          policy: 'accept'
          rules:
            - {'src': '$private_ranges', oif: 'eno2', masquerade: true}  # dynamic outbound nat
            - {'src': '$private_ranges', oif: 'eno3', snat: '192.168.0.1'}  # static outbound nat
```

## Result

### Config

```bash
ls -l /etc/nftables.d/
total 4
-rw-r----- 1 root root example.nft
```

```bash
guy@ansible:~# nft list ruleset
> table inet example {
>         counter invalid_packages {
>                 comment "Invalid"
>                 packets 0 bytes 0
>         }
> 
>         set blacklist {
>                 type ipv4_addr
>                 flags dynamic,timeout
>                 counter
>                 timeout 3m
>         }
> 
>         chain iny {
>                 type filter hook input priority filter; policy drop;
>                 ct state invalid counter name "invalid_packages" log prefix "DROP invalid sates" drop
>                 ct state { established, related } counter packets 0 bytes 0 accept comment "Allow open sessions"
>                 iifname "lo" accept comment "Allow loopback traffic"
>                 icmp type { echo-request } limit rate 5/second accept comment "Allow icmp-ping"
>                 icmpv6 type { echo-request } limit rate 5/second accept comment "Allow icmp-ping"
>                 icmp code 30 limit rate 5/second accept comment "Allow icmp-traceroute"
>                 icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept comment "Allow necessary icmpv6-types for ipv6 to work"
>                 udp dport 46251 counter name "invalid_packages" accept
>                 counter packets 0 bytes 0 comment "COUNT example-iny-drop"
>                 log prefix "DROP example-none "
>         }
> 
>         chain outgoing {
>                 type filter hook output priority filter; policy accept;
>                 udp dport 53 ip daddr { 1.1.0.0, 1.1.1.1, 8.8.4.4, 8.8.8.8 } accept
>                 tcp dport { 53, 853 } ip daddr { 1.1.0.0, 1.1.1.1, 8.8.4.4, 8.8.8.8 } accept
>                 meta l4proto { 6, 17 } th dport { 80, 443 } accept
>                 meta l4proto { 1, 58 } accept
>                 counter packets 0 bytes 0 comment "COUNT example-outgoing-accept"
>         }
> 
>         chain translate {
>                 type nat hook postrouting priority filter; policy accept;
>                 oifname "eno2" ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } masquerade
>                 oifname "eno3" ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } snat ip to 192.168.0.1
>                 counter packets 0 bytes 0 comment "COUNT example-translate-accept"
>         }
> }
```

```bash
guy@ansible:~# cat /etc/nftables.d/example.nft 
> #!/usr/sbin/nft -f
> 
> table inet example {
> 
>   # vars
>   define private_ranges = { 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8 }
>   define dns_servers = { 1.1.1.1, 1.1.0.0, 8.8.8.8, 8.8.4.4 }
> 
>   # sets
>   set blacklist {
>     type ipv4_addr;
>     flags dynamic, timeout;
>     timeout 3m;
>     counter
>   }
> 
>   # counters
>   counter invalid_packages {
>     comment "Invalid"
>   }
> 
>   chain incoming {
>     type filter hook input priority 0; policy drop;
> 
>     # vars
>     define unused = { 1.1.1.1 }
> 
> 
>     # rules
>     ct state invalid counter name invalid_packages log prefix "DROP invalid sates" drop
>     ct state {established, related} counter accept comment "Allow open sessions"
>     iifname "lo" accept comment "Allow loopback traffic"
>     icmp type { echo-request} limit rate 5/second accept comment "Allow icmp-ping"
>     icmpv6 type { echo-request} limit rate 5/second accept comment "Allow icmp-ping"
>     icmp code 30 limit rate 5/second accept comment "Allow icmp-traceroute"
>     icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept comment "Allow necessary icmpv6-types for ipv6 to work"
>     udp dport 46251 counter name invalid_packages accept
> 
>     counter comment "COUNT example-incoming-drop"
>     log prefix "DROP example-none "
>   }
> 
>   chain outgoing {
>     type filter hook output priority 0; policy accept;
> 
> 
>     # rules
>     udp dport 53 ip daddr $dns_servers accept
>     tcp dport { 53, 853 } ip daddr $dns_servers accept
>     meta l4proto { tcp, udp } th dport { 80, 443 } accept
>     meta l4proto { icmp, icmpv6 } accept
> 
>     counter comment "COUNT example-outgoing-accept"
>   }
> 
>   chain translate {
>     type nat hook postrouting priority 0; policy accept;
> 
> 
>     # rules
>     oifname "eno2" ip saddr $private_ranges masquerade
>     oifname "eno3" ip saddr $private_ranges snat to 192.168.0.1
> 
>     counter comment "COUNT example-translate-accept"
>   }
> 
> }
```
