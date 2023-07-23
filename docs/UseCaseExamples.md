# Examples for practical Use-Cases of NFTables

Some example configurations that might be useful for you to get started with NFTables.

I'm not perfect - please open an [Issue](https://github.com/ansibleguy/infra_nftables/issues/new) if you find any discrepancies or errors.

----

## Baseline

Example for a very basic ruleset on a IPv4-only host.

```yaml
vars:
  private_ranges: ['192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8']
  ports_internal: [53, 123, 80, 443]  # specify services that are used between your own hosts
  type_icmpv4_basic:
    - 'destination-unreachable'
    - 'echo-reply'
    - 'echo-request'
    - 'time-exceeded'
    - 'parameter-problem'
  code_icmpv4_basic: [30]  # traceroute

chains:
  input:
    hook: 'input'
    policy: 'drop'
    rules:
      - {if: 'lo', comment: 'Allow loopback traffic'}
      - {raw: 'ct state { established, related } accept comment "Allow open sessions"'}
      - {proto: 'icmp', type: '$type_icmpv4_basic'}
      - {proto: 'icmp', code: '$code_icmpv4_basic'}

      - {src: '$private_ranges', port: 22, proto: tcp, comment: 'Allow SSH'}
      - {src: '$private_ranges', proto: ['tcp', 'udp'], port: '$ports_internal', comment: 'Allow internal services'}

  output:
    hook: 'output'
    policy: 'drop'
    rules:
      - {of: 'lo', comment: 'Allow loopback traffic'}
      - {raw: 'ct state { established, related } accept comment "Allow open sessions"'}
      - {proto: 'icmp', type: '$type_icmpv4_basic'}
      - {proto: 'icmp', code: '$code_icmpv4_basic'}

      - {proto: ['tcp', 'udp'], port: '$ports_internal', dest: '$private_ranges', comment: 'Allow internal services'}

      # you can log specific traffic even if allowed (but only on new connections since you don't want to spam your logs..)    
      - {raw: "ct state new tcp dport { 80, 443, 123 } ip daddr != $private_ranges log prefix \"NFTables OUT PUBLIC \""}
      - {proto: ['tcp', 'udp'], port: [80, 443, 123, 53], dest: '!= $private_ranges'}

  nat:
    hook: 'postrouting'
    priority: -100
    type: 'nat'
    policy: 'accept'
    rules:
      - {src: '$private_ranges', dest: '!= $private_ranges', masquerade: true}
```

----

## IPv6 Baseline

Example for a very basic ruleset on a IPv6-only host.

**BE AWARE**: IPv6 might break completely if ICMP6 is blocked for any reason

```yaml
vars:
  trusted_ranges: ['...']  # add your own ipv6 networks/ranges (equivalent to 'private networks' on IPv4)
  ports_internal: [53, 123, 80, 443]  # specify services that are used between your own hosts
  type_icmpv6_basic:
    - 'destination-unreachable'
    - 'packet-too-big'
    - 'time-exceeded'
    - 'parameter-problem'
    - 'mld-listener-query'
    - 'mld-listener-reduction'
    - 'mld-listener-done'
    - 'mld-listener-report'
    - 'mld2-listener-report'
  type_icmpv6_neighbor:
    - 'ind-neighbor-advert'
    - 'ind-neighbor-solicit'
    - 'nd-neighbor-advert'
    - 'nd-neighbor-solicit'
    - 'nd-router-solicit'

chains:
  input:
    hook: 'input'
    policy: 'drop'
    rules:
      - {proto: 'icmp6', type: '$type_icmpv6_basic'}
      - {raw: 'ip6 nexthdr icmpv6 ip6 hoplimit 1 icmpv6 type $type_icmpv6_neighbor accept'}
      - {raw: 'ip6 nexthdr icmpv6 ip6 hoplimit 255 icmpv6 type $type_icmpv6_neighbor accept'}

      - {if: 'lo', comment: 'Allow loopback traffic'}
      - {raw: 'ct state { established, related } accept comment "Allow open sessions"'}

      - {src6: '$trusted_ranges', port: 22, proto: tcp, comment: 'Allow SSH'}
      - {src6: '$trusted_ranges', proto: ['tcp', 'udp'], port: '$ports_internal', comment: 'Allow internal services'}

  output:
    hook: 'output'
    policy: 'drop'
    rules:
      - {proto: 'icmp6', type: '$type_icmpv6_basic'}
      - {raw: 'ip6 nexthdr icmpv6 ip6 hoplimit 1 icmpv6 type $type_icmpv6_neighbor accept'}
      - {raw: 'ip6 nexthdr icmpv6 ip6 hoplimit 255 icmpv6 type $type_icmpv6_neighbor accept'}

      - {of: 'lo', comment: 'Allow loopback traffic'}
      - {raw: 'ct state { established, related } accept comment "Allow open sessions"'}

      - {proto: ['tcp', 'udp'], port: '$ports_internal', dest6: '$trusted_ranges', comment: 'Allow internal services'}

      # you can log specific traffic even if allowed (but only on new connections since you don't want to spam your logs..)    
      - {raw: "ct state new tcp dport { 80, 443, 123 } ip6 daddr != $trusted_ranges log prefix \"NFTables OUT PUBLIC \""}
      - {proto: ['tcp', 'udp'], port: [80, 443, 123, 53], dest6: '!= $trusted_ranges'}
```


----

## Security Baseline

* One should block known attacks that allowed target transport protocols like TCP.

* ICMP traffic should also be limited on public interfaces.

* You can also use the [ansibleguy.addons_nftables](https://github.com/ansibleguy/addons_nftables) to tighten:
  * your outbound rules by only allowing DNS-based destinations
  * your input rules by implementing IP-blocklists (_Tor exit nodes, Spamhaus, ..._)

```yaml
vars:
  private_ranges: ['192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8']
  type_icmpv6_basic:
    - 'destination-unreachable'
    - 'packet-too-big'
    - 'time-exceeded'
    - 'parameter-problem'
    - 'mld-listener-query'
    - 'mld-listener-reduction'
    - 'mld-listener-done'
    - 'mld-listener-report'
    - 'mld2-listener-report'
  type_icmpv6_neighbor:
    - 'ind-neighbor-advert'
    - 'ind-neighbor-solicit'
    - 'nd-neighbor-advert'
    - 'nd-neighbor-solicit'
    - 'nd-router-solicit'
  type_icmpv4_basic:
    - 'destination-unreachable'
    - 'echo-reply'
    - 'echo-request'
    - 'time-exceeded'
    - 'parameter-problem'
  code_icmpv4_basic: [30]  # traceroute
  # for BOGONS see: https://ipinfo.io/bogon
  net_bogons_v4: [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
    '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
  ]
  net_bogons_v6: [
    '::/128', '::1/128', '::ffff:0:0/96', '::/96', '100::/64', '2001:10::/28', '2001:db8::/32', 'fc00::/7', 'fe80::/10',
    'fec0::/10', 'ff00::/8',
  ]

limits:
  limit_icmp_public:  # NOTE: this is a per-rule limit; could also be implemented as per-source limit
    rate: '50/second'
  limit_icmp6_public:
    rate: '150/second'

chains:
  input:
    hook: 'input'
    policy: 'drop'
    rules:
      - {seq: 10, raw: 'ct state invalid log prefix "NFTables DROP invalid states" drop'}
      - {seq: 11, raw: 'ip frag-off & 0x1fff != 0 counter log prefix "NFTables DROP IP fragments " drop'}
      - {seq: 12, raw: 'tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg counter log prefix "NFTables DROP TCP XMAS " drop'}
      - {seq: 13, raw: 'tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter log prefix "NFTables DROP TCP NULL " drop'}
      - {seq: 14, raw: 'tcp flags syn tcp option maxseg size 1-536 counter log prefix "NFTables DROP TCP MSS " drop'}
      - {seq: 15, raw: 'tcp flags & (fin|syn|rst|ack) != syn ct state new counter log prefix "NFTables DROP TCP SYN CT NEW " drop'}

      - {proto: 'icmp', type: '$type_icmpv4_basic', limit: 'limit_icmp_public', src: '!= $private_ranges'}
      - {proto: 'icmp', code: '$code_icmpv4_basic', limit: 'limit_icmp_public', src: '!= $private_ranges'}
      - {proto: 'icmp', type: '$type_icmpv4_basic', src: '$private_ranges'}
      - {proto: 'icmp', code: '$code_icmpv4_basic', src: '$private_ranges'}

      # BE AWARE: IPv6 might break completely if ICMP6 is blocked for any reason
      - {proto: 'icmp6', type: '$type_icmpv6_basic'}
      - {raw: 'ip6 nexthdr icmpv6 ip6 hoplimit 1 icmpv6 type $type_icmpv6_neighbor limit limit_icmp6_public drop'}
      - {raw: 'ip6 nexthdr icmpv6 ip6 hoplimit 255 icmpv6 type $type_icmpv6_neighbor limit limit_icmp6_public drop'}

      # Block bogons on public interfaces
      - {src: '$net_bogons_v4', if: 'wan1', action: 'drop'}
      - {src6: '$net_bogons_v6', if: 'wan1', action: 'drop'}

      # Blocklists using 'addons'
      - {src: '$iplist_tor_exit_nodes', if: 'wan1', action: 'drop'}
      - {src6: '$iplist_tor_exit_nodes_v6', if: 'wan1', action: 'drop'}

  output:
    hook: 'output'
    policy: 'drop'
    rules:
      # Block bogons on public interfaces
      - {dest: '$net_bogons_v4', of: 'wan1', action: 'drop'}
      - {dest6: '$net_bogons_v6', of: 'wan1', action: 'drop'}

      # basically - only allow that you REALLY need - you know the game
      - {proto: 'icmp', type: '$icmpv4_basic'}
      - {proto: 'icmp', code: '$icmpv4_basic_code'}

      # you can log specific traffic even if allowed (but only on new connections since you don't want to spam your logs..)    
      - {raw: "ct state new tcp dport { 80, 443, 123 } ip daddr != $private_ranges log prefix \"NFTables OUT PUBLIC \""}

      - {proto: ['tcp', 'udp'], dest: '$ntp_servers', port: 123, comment: 'NTP'}
      - {proto: 'tcp', dest: '$dns_servers', port: [53, 853], comment: 'DNS'}
      - {proto: 'udp', dest: '$dns_servers', port: 53, comment: 'DNS'}

      # NOTE: you might want to limit outbound HTTP+HTTPS connections using an outbound proxy like 'squid'
      #   benefits of a proxy over ip/dns-based nftables: some dns-records change every minute.. have fun
      - {proto: 'tcp', port: [80, 443], dest: '$trusted_repositories', comment: 'Updates'}
      - {proto: 'tcp', port: [80, 443], dest: '$trusted_peers', comment: 'Application traffic'}
```

----

## Docker host

### Prerequisites

Docker is a special-case for using NFTables.

* **Q:** Why is it a special case?

  **A:** Docker has a dependency on IPTables..


* **Q:** Then why manage this `perfect magic ruleset` at all?

  **A:** If you have looked at the auto-generated IPTables rules you will know that they are not transparent at all. Also: If we want to limit the network capabilities of the host and containers - that is the most straight-forward way to do it!

  If you want to know more about Docker & IPTables: [Docker Packet Filtering](https://docs.docker.com/network/packet-filtering-firewalls/)


* **Q:** How does one manage the ruleset on a Docker host manually?

  **A:** One needs to perform a few tasks to successfully do so:

  1. Edit the behaviour of the Docker service:

    * Flag `--iptables=false`: MUST HAVE! Disables the management of IPTables rules by docker.
    * Flag `--bridge=none`: If none of your containers needs a bridge - you should disable it. How to see if it is needed? Run `ip a` on the host - if any containers have their own IPs - they need a Bridge.
    * Flag `--default-address-pool='base=172.18.0.0/16,size=24'`: Fix the network provided to your containers. Makes managing the ruleset easier.

    In this example we will assume `bridge` is needed by the containers.

    ```text
    # /etc/systemd/system/docker.service.d/override.conf
    [Service]
    ExecStart=
    ExecStart=/usr/bin/dockerd --iptables=false
    ExecStartPost=/usr/bin/systemctl reload nftables.service
    ```

  2. Tell the NFTables role that IPTables is OK.

  ```yaml
  nftables:
    incompatible_packages: ['ufw']  # default = ['iptables', 'ufw']
  ```

### Ruleset
This is a very basic Ruleset for a Docker host.

It limits its containers traffic:
* Allow DNS to internal DNS servers
* Allow SMTP to specific host
* Allow HTTP+S to specific host for Install/Updates
* Allow connections to internal Docker registry (_nested docker_)

For simplicity's sake we don't cover IPv6 in this example.

#### DNS

```yaml
# dns resolution via 'ansibleguy.addons_nftables'
nftables_addons:
  enable:
    dns: true

  timer:
    systemd:
      dns: '*:0/5'  # update every 5min

  config:
    dns_records:
      ntp_servers: ['0.europe.pool.ntp.org', '1.europe.pool.ntp.org']
      repo_debian: ['deb.debian.org', 'debian.map.fastlydns.net', 'security.debian.org']
      repo_docker: 'download.docker.com'  # dns-resolution might not always be up-to-date as the TTL=1min :(
      mail_server: 'mail-server.example'
```

#### Rules

```yaml
vars:
  private_ranges: ['192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8']
  docker_network: '172.18.0.0/16'
  docker_registry: '192.168.100.10'
  mgmt_network: '192.168.100.0/24'
  dns_server: '192.168.10.1'
  type_icmpv4_basic:
    - 'destination-unreachable'
    - 'echo-reply'
    - 'echo-request'
    - 'time-exceeded'
    - 'parameter-problem'
  code_icmpv4_basic: [30]  # traceroute

chains:
  input:
    hook: 'input'
    policy: 'drop'
    rules:
      - {if: 'lo', comment: 'Allow loopback traffic'}
      - {raw: 'ct state { established, related } accept comment "Allow open sessions"'}
      - {proto: 'icmp', type: '$type_icmpv4_basic'}
      - {proto: 'icmp', code: '$code_icmpv4_basic'}

      - {src: '$mgmt_network', port: [22, 2376], proto: tcp, comment: 'Docker Management'}

  output:
    hook: 'output'
    policy: 'drop'
    rules:
      - {of: 'lo', comment: 'Allow loopback traffic'}
      - {raw: 'ct state { established, related } accept comment "Allow open sessions"'}
      - {proto: 'icmp', type: '$type_icmpv4_basic'}
      - {proto: 'icmp', code: '$code_icmpv4_basic'}

      # internal
      - {dest: '$dns_server', port: [53, 853], proto: ['tcp', 'udp'], comment: 'DNS'}
      - {dest: '$docker_registry', port: 5000, proto: tcp, comment: 'Docker Registry'}

      # external
      - {dest: ['$repo_docker', '$repo_debian'], proto: 'tcp', port: [80, 443], comment: 'Repositories'}
      - {dest: '$ntp_servers', proto: ['tcp', 'udp'], port: 123, comment: 'NTP'}
      - {dest: '$mail_server', proto: 'tcp', port: [25, 587], comment: 'Mailing'}

  forward:
    hook: 'forward'
    policy: 'drop'
    rules:
      - {raw: 'ct state { established, related } accept comment "Allow open sessions"'}
      - {proto: 'icmp', type: '$type_icmpv4_basic'}
      - {proto: 'icmp', code: '$code_icmpv4_basic'}
      - {src: '$docker_network', dest: '$docker_network', proto: ['udp', 'tcp', 'icmp'], comment: 'Container to Container Traffic'}

      # internal
      - {src: '$docker_network', dest: '$dns_server', port: [53, 853], proto: ['tcp', 'udp'], comment: 'DNS'}
      - {src: '$docker_network', dest: '$docker_registry', port: 5000, proto: 'tcp', comment: 'Docker Registry (Nested)'}

      # external
      - {src: '$docker_network', dest: ['$repo_docker', '$repo_debian'], proto: 'tcp', port: [80, 443], comment: 'Repositories'}
      - {src: '$docker_network', dest: '$ntp_servers', proto: ['tcp', 'udp'], port: 123, comment: 'NTP'}
      - {src: '$docker_network', dest: '$mail_server', proto: 'tcp', port: [25, 587], comment: 'Mailing'}

  nat:
    hook: 'postrouting'
    priority: -100
    type: 'nat'
    rules:
      - {src: '$docker_network', dest: '!= $docker_network', masquerade: true}  # NAT un-routed docker network to outside
```


----

## Proxmox host

See also: [Proxmox Ports](https://pve.proxmox.com/wiki/Ports)

This is a very basic Ruleset for a Proxmox `PVE` host.

It allows any traffic from VM's to pass through but limits the connections from and to the host itself.

You could - of course - also limit the VM/Container traffic.

For simplicity's sake we don't cover IPv6 in this example.

### DNS

```yaml
# dns resolution via 'ansibleguy.addons_nftables'
nftables_addons:
  enable:
    dns: true

  config:
    dns_records:
      ntp_servers: ['0.europe.pool.ntp.org', '1.europe.pool.ntp.org']
      repo_debian: ['deb.debian.org', 'debian.map.fastlydns.net', 'security.debian.org']
      repo_proxmox: ['download.proxmox.com', 'enterprise.proxmox.com']
      mail_server: 'mail-server.example'
```


### Rules

```yaml
vars:
  private_ranges: ['192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8']
  mgmt_network: '192.168.100.0/24'  # management network
  proxmox_cluster_net: '10.0.0.0/24'  # cluster-specific layer2 network; only proxmox nodes should be in it
  proxmox_net: '192.168.200.0/24'  # routed network; only proxmox nodes should be in it
  proxmox_backup_server: '192.168.210.10'
  type_icmpv4_basic:
    - 'destination-unreachable'
    - 'echo-reply'
    - 'echo-request'
    - 'time-exceeded'
    - 'parameter-problem'
  code_icmpv4_basic: [30]  # traceroute

chains:
  input:
    hook: 'input'
    policy: 'drop'
    rules:
      - {if: 'lo', comment: 'Allow loopback traffic'}
      - {raw: 'ct state { established, related } accept comment "Allow open sessions"'}
      - {proto: 'icmp', type: '$type_icmpv4_basic'}
      - {proto: 'icmp', code: '$code_icmpv4_basic'}

      - {src: '$mgmt_network', port: [22, 3128, '5900-5999', 8006], proto: tcp, comment: 'Proxmox Management'}

      # NOTE: you could limit ports
      - {src: '$proxmox_cluster_net', dest: '$proxmox_cluster_net', proto: ['tcp', 'udp', 'icmp'], comment: 'Proxmox Cluster Traffic'}

      # NOTE: you may get away without this rule - not really sure:
      - {src: '$proxmox_net', dest: '$proxmox_net', proto: 'tcp', port: [22, 5404, 5405, '60000-60050', 111, 8006], comment: 'Proxmox Cluster Traffic'}

  output:
    hook: 'output'
    policy: 'drop'
    rules:
      - {of: 'lo', comment: 'Allow loopback traffic'}
      - {raw: 'ct state { established, related } accept comment "Allow open sessions"'}
      - {proto: 'icmp', type: '$type_icmpv4_basic'}
      - {proto: 'icmp', code: '$code_icmpv4_basic'}

      - {dest: ['$repo_proxmox', '$repo_debian'], proto: 'tcp', port: [80, 443], comment: 'Repositories'}
      - {dest: '$ntp_servers', proto: ['tcp', 'udp'], port: 123, comment: 'NTP'}
      - {dest: '$mail_server', proto: 'tcp', port: [25, 587], comment: 'Mailing'}
      - {dest: '$proxmox_backup_server', proto: 'tcp', port: 8007, comment: 'Proxmox Backup Server'}

      # NOTE: you could limit ports
      - {src: '$proxmox_cluster_net', dest: '$proxmox_cluster_net', proto: ['tcp', 'udp', 'icmp'], comment: 'Proxmox Cluster Traffic'}

      # NOTE: you may get away without this rule - not really sure:
      - {src: '$proxmox_net', dest: '$proxmox_net', proto: 'tcp', port: [22, 5404, 5405, '60000-60050', 111, 8006], comment: 'Proxmox Cluster Traffic'}

  forward:
    hook: 'forward'
    policy: 'accept'  # NOTE: use 'drop' if you want to filter traffic here instead of/in addition to on VMs/Containers
    rules: {}  # NOTE: filtering on interfaces also supports wildcards 'vmbr*' or 'veth*' - important for container networks

  nat:
    hook: 'postrouting'
    priority: -100
    type: 'nat'
    rules: {}  # NOTE: no rules needed; but you could implement custom Source-NAT here
```

----

## Forwarding Server (_Router, Network Firewall, VPN Server_)

To be done


----

## Fail2Ban

See: [Fail2Ban](https://github.com/ansibleguy/infra_nftables/blob/latest/docs/Fail2Ban.md)
