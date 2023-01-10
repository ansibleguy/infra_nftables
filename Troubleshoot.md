# Troubleshooting

## Known errors

### Unsupported Operation

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
