<a href="https://netfilter.org">
<img src="https://netfilter.org/images/netfilter-logo3.png" alt="NFTables logo" width="300"/>
</a>

# UNSTABLE ROLE - WORK IN PROGRESS

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


* **Configuration**
  * 


  * **Default config**:
    * 
 

  * **Default opt-ins**:
    * 


  * **Default opt-outs**:
    * 

## Info

* **Info:** Read the [Hook documentation](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks) to know when and how to configure hooks and priorities!


* **Note:** this role currently only supports debian-based systems


* **Note:** Most of the role's functionality can be opted in or out.

  For all available options - see the default-config located in the main defaults-file!


* **Warning:** Not every setting/variable you provide will be checked for validity. Bad config might break the role!


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
  _defaults:
    table:
      type: 'inet'
    
    chain:
      policy: 'drop'
      type: 'filter'
      priority: 0
      log:
        drop: true

  tables:
    internet:
      chains:
        incoming:
          hook: 'input'
    
        outgoing:
          hook: 'output'
          policy: 'accept'
    
        route:
          hook: 'forward'
    
        translate:
          hook: 'postrouting'
          type: 'nat'
          policy: 'accept'
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
