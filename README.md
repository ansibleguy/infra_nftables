<a href="https://netfilter.org/projects/nftables/index.html">
<img src="https://netfilter.org/images/netfilter-logo3.png" alt="NFTables logo" width="400"/>
</a>

# Ansible Role - NFTables

Role to provision NFTables firewall on linux servers.

[![Molecule Test Status](https://badges.ansibleguy.net/infra_nftables.molecule.svg)](https://github.com/ansibleguy/_meta_cicd/blob/latest/templates/usr/local/bin/cicd/molecule.sh.j2)
[![YamlLint Test Status](https://badges.ansibleguy.net/infra_nftables.yamllint.svg)](https://github.com/ansibleguy/_meta_cicd/blob/latest/templates/usr/local/bin/cicd/yamllint.sh.j2)
[![PyLint Test Status](https://badges.ansibleguy.net/infra_nftables.pylint.svg)](https://github.com/ansibleguy/_meta_cicd/blob/latest/templates/usr/local/bin/cicd/pylint.sh.j2)
[![Ansible-Lint Test Status](https://badges.ansibleguy.net/infra_nftables.ansiblelint.svg)](https://github.com/ansibleguy/_meta_cicd/blob/latest/templates/usr/local/bin/cicd/ansiblelint.sh.j2)
[![Ansible Galaxy](https://badges.ansibleguy.net/galaxy.badge.svg)](https://galaxy.ansible.com/ui/standalone/roles/ansibleguy/infra_nftables)

Molecule Logs: [Short](https://badges.ansibleguy.net/log/molecule_infra_nftables_test_short.log), [Full](https://badges.ansibleguy.net/log/molecule_infra_nftables_test.log)

**Tested:**
* Debian 11
* Debian 12

## Install

```bash
# latest
ansible-galaxy role install git+https://github.com/ansibleguy/infra_nftables

# from galaxy
ansible-galaxy install ansibleguy.infra_nftables

# or to custom role-path
ansible-galaxy install ansibleguy.infra_nftables --roles-path ./roles
```

----

## Documentation

* NFTables: [Wiki](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)
* Check out the [Example](https://github.com/ansibleguy/infra_nftables/blob/latest/docs/Example.md)!
* [Practical Use-Cases](https://github.com/ansibleguy/infra_nftables/blob/latest/docs/UseCaseExamples.md) (_Docker, Proxmox, Network firewall_)
  * Integration of [Fail2Ban with NFTables](https://github.com/ansibleguy/infra_nftables/blob/latest/docs/Fail2Ban.md)
* [Troubleshooting Guide](https://github.com/ansibleguy/infra_nftables/blob/latest/docs/Troubleshoot.md)

## Troubleshoot

* [Troubleshooting Guide](https://github.com/ansibleguy/infra_nftables/blob/latest/docs/Troubleshoot.md)

## Usage

### Config

Define the config as needed:

```yaml
nftables:
  # enable:  # features must be supported by kernel
  #   sets: true
  #   nat: true
  #   deb11_backport: false  # use debian11 backports repository to install newer version on debian 10
  #   bash_completion: false

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
              raw: 'ct state invalid counter name invalid_packages log prefix "DROP invalid states" drop'
            - seq: 2
              raw: 'ct state {established, related} counter accept comment "Allow open sessions"'
            - s: 3
              raw: 'iifname "lo" accept comment "Allow loopback traffic"'
            - {proto: 'icmp', type: 'echo-request', limit: 'rate 10/second', comment: 'Allow icmp-ping'}
            - {proto: 'icmpv6', type: 'echo-request', limit: 'rate 10/second', comment: 'Allow icmp-ping'}
            - {proto: 'icmp', code: 30, limit: 'rate 10/second', comment: 'Allow icmp-traceroute'}
            - {proto: 'icmpv6', limit: 'rate 10/second', comment: 'Allow necessary icmpv6-types for ipv6 to work',
               type: ['nd-neighbor-solicit', 'nd-router-advert', 'nd-neighbor-advert']}
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

If you want to **merge group- & host-rules** you could do it like that:

```yaml
# define the basic ruleset used by all hosts as: 'fw_rules_all'
# define service-specific rules as: 'fw_rules_group'
# define host-specific rules as: 'fw_rules_host'

- name: NFTables
  become: true
  hosts: all
  vars:
    nftables:
      tables:
        example:
          chains: "{{ fw_rules_all |
          combine(fw_rules_group|default({}), recursive=true, list_merge='append') |
          combine(fw_rules_host|default({}), recursive=true, list_merge='append') }}"

  pre_tasks:
    - debug:
        var: nftables

  roles:
    - ansibleguy.infra_nftables
```

### Execution

Run the playbook:
```bash
ansible-playbook -K -D -i inventory/hosts.yml playbook.yml
```

There are also some useful **tags** available:
* config
* purge

To debug errors - you can set the 'debug' variable at runtime:
```bash
ansible-playbook -K -D -i inventory/hosts.yml playbook.yml -e debug=yes
```

----

## Functionality

* **Package installation**
  * Ansible dependencies (_minimal_)
  * NFTables


* **Configuration**
  * Possibility to define
    * **variables** on global level
    * **variables, sets, counters and limits** on table level
    * **variables** on chain level
  * **Config will be validated** before being written


  * **Default config**:
    * Enabled features (_must be supported by kernel_)
      * Sets
      * NAT
    * No rules are added by default
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
    * rules
      * policy = accept (_set it to 'none' if you want to explicitly remove it_)
      * logging drops = yes


  * **Default opt-ins**:
    * Purging of unmanaged config-files stored in '/etc/nftables.d/'

  * **Default opt-outs**:
    * Installing NFTables from Debian 11 backports when running on Debian 10 (_newer version_)
    * Adding [bash-completion script](https://patchwork.ozlabs.org/project/netfilter-devel/patch/1454691182-6573-1-git-send-email-giuseppelng@gmail.com/) for the 'nft' command

----

## Info

* **Note:** Most of the role's functionality can be opted in or out.

  For all available options - see the default-config located in the main defaults-file!


* **Warning:** Not every setting/variable you provide will be checked for validity. Bad config might break the role!


* **Info:** You can add **DNS-Resolution and IP-Blocklist** functionalities to NFTables using the [ansibleguy.addons_nftables](https://github.com/ansibleguy/addons_nftables) role!


* **Warning:** Some **core functionalities** (_NAT/Sets_) might **not be supported by mainstream Distribution kernels**.

  See: [Troubleshooting Guide - 'Unsupported Operation'](https://github.com/ansibleguy/infra_nftables/blob/latest/docs/Troubleshoot.md#unsupported-operation)


* **Info:** Read the [Hook documentation](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks) to know when and how to configure **hooks and priorities**!


* **Info:** Rules can be provided in dictionary format as seen in the examples.

  These are the available fields and aliases:

  | Function             | Keys                                                                      | Note                                                                                                                                                                                                               |
  |----------------------|---------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
  | Rule sequence        | s, id, seq, sequence                                                      | The sequence-id (_integer_) to sort the rules inside a chain. If none is provided one will be auto-generated beginning at 1000. If a duplicate sequence id is provided the role will fail its config-check!        |
  | Input interface      | if, iif, iifname                                                          | -                                                                                                                                                                                                                  |
  | Output interface     | of, oif, oifname                                                          | -                                                                                                                                                                                                                  |
  | Protocol             | proto, pr, protocol                                                       | -                                                                                                                                                                                                                  |
  | Protocol sub-type    | t, type                                                                   | -                                                                                                                                                                                                                  |
  | Protocol sub-code    | co, code                                                                  | -                                                                                                                                                                                                                  |
  | Destination Address/Network | d, dest, target, destination, 'ip daddr', d6, dest6, target6, 'ip6 daddr' | -                                                                                                                                                                                                                  |
  | Destination Port     | dp, port, dport, dest_port                                                | -                                                                                                                                                                                                                  |
  | Source Address/Network | s, src, source, 'ip saddr', s6, src6, source6, 'ip6 saddr'                | -                                                                                                                                                                                                                  |
  | Source Port          | sp, sport, sport, src_port                                                | -                                                                                                                                                                                                                  |
  | Logging / Log message | l, log, 'log prefix'                                                      | If set to 'True' and a 'comment' is provided, it will be used as message. Else no message will be used                                                                                                             |
  | Traffic counter      | count, counter                                                            | If set to 'True' a rule-specific counter will be used. Else it will use the provided pre-defined counter                                                                                                           |
  | Traffic Limit        | lim, limit                                                                | A limit to set for the rule, see: [Anonymous Limits](https://wiki.nftables.org/wiki-nftables/index.php/Rate_limiting_matchings) and [Pre-defined Limits](https://wiki.nftables.org/wiki-nftables/index.php/Limits) |
  | Rule action          | a, action                                                                 | If no action is provided, it will default to 'accept'                                                                                                                                                              | 
  | Source NAT masquerading | m, masque, masquerade                                                     | If NAT masquerading should be used                                                                                                                                                                                 |
  | Source NAT           | snat, src_nat, source_nat, outbound_nat, 'snat to'                        | -                                                                                                                                                                                                                  |
  | Destination NAT      | dnat, dest_nat, destination_nat, 'dnat to'                                | -                                                                                                                                                                                                                  |
  | Redirect             | redir, redirect, 'redirect to'                                            | By using redirect, packets will be forwarded to local machine                                                                                                                                                      |                                                                                                                                                                                                                  |
  | Rule comment         | c, cmt, comment                                                           | -                                                                                                                                                                                                                  |
  | User                 | user, uid                                                                 | Match only traffic originating from specific user                                                                                                                                                                  |
  | Group                | group, gid                                                                | Match only traffic originating from specific group                                                                                                                                                                 |
  | Firewall-Mark        | mark                                                                      | -                                                                                                                                                                                                                  |
  | Priority             | prio, priority                                                            | -                                                                                                                                                                                                                  |
  | Packet length        | len, length                                                               | -                                                                                                                                                                                                                  |
  | Timestamp            | time, timestamp                                                                    | Match timestamp of packet reception                                                                                                                                                                                |
  | Weekday              | day                                                                       | Match day of week (0 = Sunday to 6 = Saturday or "Monday", "tuesday" also "fri", "Sat")                                                                                                                            |
  | Time                 | hour                                                                      | Match 24-hour "HH:MM:SS", with seconds optional                                                                                                                                                                    |

  Only one of Action, Source-NAT, Masquerading or Destination-NAT can be set for one rule!


* **Info:** Special/complex rules cannot be configured using the rule-dictionary.

  You can use the 'raw' key to provide any custom rule that will be added to the ruleset directly.


* **Info:** You can define **variables, sets, counters and limits** on table-level.

  * **Variables** are key-value pairs.
    ```yaml
    var-name: var-value
    var2-name: ['value1', 'value2']
    ```
  * **Sets** have this structure:
    ```yaml
    set-name:
      flags: [list-of-flags]  # optional
      settings:
        setting: value  # optional
    ```
  * **Counters** have this structure:
    ```yaml
    counter-name:
      comment: text  # optional
    ```
  * **Limits** have this structure:
    ```yaml
    limit-name:
      rate: 'over 1024 bytes/second burst 512 bytes'
      comment: text  # optional
    ```

* **Warning:** If you want to add a 'count-only' rule you need to set 'action' explicitly to 'none' - else the default value 'accept' will be added!


* **Info:** If any unsupported field is supplied to the rule-translation it will throw an error as this might lead to unexpected results!


* **Info:** Docker might need IPTables as Package-Dependency. 

  See: [Use-Case Docker Host](https://github.com/ansibleguy/infra_nftables/blob/latest/docs/UseCaseExamples.md#docker-host)
