<a href="https://netfilter.org">
<img src="https://netfilter.org/images/netfilter-logo3.png" alt="NFTables logo" width="400"/>
</a>

# Ansible Role - NFTables

Role to provision NFTables firewall on linux servers.

[![Molecule Test Status](https://badges.ansibleguy.net/infra_nftables.molecule.svg)](https://molecule.readthedocs.io/en/latest/)
[![YamlLint Test Status](https://badges.ansibleguy.net/infra_nftables.yamllint.svg)](https://yamllint.readthedocs.io/en/stable/)
[![Ansible-Lint Test Status](https://badges.ansibleguy.net/infra_nftables.ansiblelint.svg)](https://ansible-lint.readthedocs.io/en/latest/)
[![Ansible Galaxy](https://img.shields.io/ansible/role/61265)](https://galaxy.ansible.com/ansibleguy/infra_nftables)
[![Ansible Galaxy Downloads](https://img.shields.io/badge/dynamic/json?color=blueviolet&label=Galaxy%20Downloads&query=%24.download_count&url=https%3A%2F%2Fgalaxy.ansible.com%2Fapi%2Fv1%2Froles%2F61265%2F%3Fformat%3Djson)](https://galaxy.ansible.com/ansibleguy/infra_nftables)


**Tested:**
* Debian 11

## Documentation

NFTables: [Wiki](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)

## Functionality

* **Package installation**
  * Ansible dependencies (_minimal_)
  * NFTables


* **Configuration**
  * Possibility to define **variables, sets and counters** on table level
  * Possibility to define **variables** on chain level
  * **Config will be validated** before being written


  * **Default config**:
    * tables
      * table-type = inet
    * chains
      * chain-type = filter
      * chain-policy = drop
      * priority = 0
      * add counter = yes
      * log implicit dropy = yes
    * sets
      * set-type = ipv4_addr
      * add counter = yes
 

  * **Default opt-ins**:
    * Purging of unmanaged config-files stored in '/etc/nftables.d/'

## Info

* **Info:** Read the [Hook documentation](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks) to know when and how to configure hooks and priorities!


* **Info:** Check out the **config [Example](https://github.com/ansibleguy/infra_nftables/blob/main/Example.md)**.


* **Note:** Most of the role's functionality can be opted in or out.

  For all available options - see the default-config located in the main defaults-file!


* **Warning:** Not every setting/variable you provide will be checked for validity. Bad config might break the role!


* **Info:** Special/complex rules cannot be configured using the rule-dictionary.

  You can use the 'raw' key to provide any custom rule that will be added to the ruleset directly.


* **Info:** If you want to use **Fail2Ban with NFTables**, you should check out this [Documentation](https://github.com/ansibleguy/infra_nftables/blob/main/Fail2Ban.md).


* **Info:** If you encounter the error message 'No such file or directory' when config is written/validated it can indicate a problem with:

  * Missing objects like tables, chains, variables, sets or counters
  * You may have a typo in such a link
  * The installed nftables version may be too old to use a feature/functionality (_nat chain on Debian 10_)


## Setup

For this role to work - you must install its dependencies first:

```
ansible-galaxy install -r requirements.yml
```

## Usage

### Config

Define the config as needed:

```yaml
nftables:
  _defaults:  # defaults inherited by all tables and chains
    table:
      type: 'inet'
    
    chain:
      policy: 'drop'
      type: 'filter'
      priority: 0
      log:
        drop: true

    rules:
      _all: []  # rules added to all chains of all tables
      incoming: []  # rules added to 'incoming' chain of all tables

  tables:
    example:
      # type: 'inet'  # ipv4 + ipv6
      _defaults:
        rules:
          _all: []  # rules added to all chains of this table

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

        route:
          hook: 'forward'

        translate:
          hook: 'postrouting'
          type: 'nat'
          policy: 'accept'
          rules:
            - {'src': '$private_ranges', oif: 'eno2', masquerade: true}  # dynamic outbound nat
            - {'src': '$private_ranges', oif: 'eno3', snat: '192.168.0.1'}  # static outbound nat
```

### Execution

Run the playbook:
```bash
ansible-playbook -K -D -i inventory/hosts.yml playbook.yml
```

There are also some useful **tags** available:
* config

To debug errors - you can set the 'debug' variable at runtime:
```bash
ansible-playbook -K -D -i inventory/hosts.yml playbook.yml -e debug=yes
```
