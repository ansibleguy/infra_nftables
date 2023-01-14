# Troubleshooting

## Basics

If a table fails to be verified, you can find its generated content inside the '/tmp' directory of the target server!

Per example: '/tmp/nftables_example.nft' if the failed table is called 'example'

You can troubleshoot the config in detail using 'nft -cf /tmp/nftables_example.nft' and manual edits!

## Know-How

There are global [limits](https://wiki.nftables.org/wiki-nftables/index.php/Limits) (_one limit for all connections_) and specific limits - also called [meters](https://wiki.nftables.org/wiki-nftables/index.php/Meters).

### Limits

Limits seem to work best if combined with a drop and accept rule.

In this example we will block ping-flooding on the public interface 'eno1':

```bash
iifname "eno1" icmp type echo-request limit rate over 10/second drop log prefix "NFTables DROP Ping Flooding "  # drop everything that exceeds the limit
iifname "eno1" icmp type echo-request accept  # allow the rest
```

### Meters

**WARNING**: I was not able to test 'meters', as it seems the current Debian 11 kernel does not support 'sets'.

You need to define a [set](https://wiki.nftables.org/wiki-nftables/index.php/Sets) used to cache the IPs exceeding the defined limit.

Make sure your kernel does support 'sets' beforehand!

In this example we will block icmp for every source-ip that exceeds the limit on the public interface 'eno2':

```yaml
tables:
  example:
    sets:
      meter_icmp:
        flags: ['dynamic', 'timeout']
        settings:
          timeout: '3m'  # remove cached addresses automatically after timespan
          size: 65535

    chains:
      input:
        rules:
          - 'iifname "eno2" icmp meter @meter_icmp { ip saddr limit rate 10/second } log prefix "NFTables DROP ICMP Flooding " counter drop'
```

Info source: [Docs](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-using_nftables_to_limit_the_amount_of_connections)

## Known errors

### Unsupported Operation

Also: 'Could not process rule: Operation not supported'

Your kernel might not support this feature.

You might want to upgrade your kernel if you want to use that features and have an older version running.

#### Sets

If you are trying to use 'sets' you could check if the 'nf_tables_set' kernel-module exists and is loaded:

```bash
modprobe nf_tables_set

# if it failed => check if the module exists; should show a 'nf_tables_set.ko' file
find "/lib/modules/$(uname -r)" -name nf_tables_*

# check if your kernel was compiled with it enabled => if not output is shown it was not enabled
cat "/boot/config-$(uname -r)" | grep 'CONFIG_NF_TABLES_SET'
```

#### NAT

```bash
# check if your kernel was compiled with it enabled => if not output is shown it was not enabled
cat "/boot/config-$(uname -r)" | grep 'CONFIG_NFT_NAT'
```

### No such file or directory

If you encounter the error message 'No such file or directory' when config is written/validated it can indicate a problem with:

  * Missing objects like tables, chains, variables, sets or counters
  * You may have a typo in such a link
  * The installed nftables version may be too old to use a feature/functionality (_nat chain on Debian 10_)

### ip or ip6 must be specified with address for inet tables

#### NAT

See: [Wiki](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)#Inet_family_NAT)

You need to supply ip or ip6 in front of the NAT target IP.

```yaml
# before
rule_before:
  if: '$int_private'
  proto: 'tcp'
  port: [80, 443]
  dnat: '192.168.10.1'

# after
rule_after:
  if: '$int_private'
  proto: 'tcp'
  port: [80, 443]
  dnat: 'ip 192.168.10.1'
#        ^^
```

### Could not process rule: Device or resource busy

If many rules throw this error you might have a problem with a NAT rule.

It could be your kernel does not support NFTables-NATing or you try to add NAT rules to chains that don't have the type 'nat' configured.
