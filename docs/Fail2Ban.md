# Fail2Ban with NFTables

## Install

### Systemd

Link the fail2ban service with nftables so the ban-rules get re-added once nftables gets restarted!

* Add the file '/etc/systemd/system/fail2ban.service.d/override.conf'

```
[Unit]
Requires=nftables.service
PartOf=nftables.service

[Install]
WantedBy=multi-user.target nftables.service
```

* Apply the changes:

```bash
systemctl daemon-reload
```

### Fail2Ban config

Settings in '/etc/fail2ban/jail.local'

```
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
chain = chain-to-use  # customizable

[recidive]
banaction = nftables-allports
```

Settings in '/etc/fail2ban/action.d/nftables-common.local'

```
[Init]
nftables_family = inet
nftables_table = table-to-use  # customizable; should NOT BE your primary table
blocktype = drop
# nftables_set_prefix = 'f2b'  # optional
```

## Usage

If you want to reload the nftables config you need to do it by restarting the service:

```bash
systemctl restart nftables.service
```

Other ways won't re-add the Fail2Ban block-rules.

```bash
nft -f /etc/nftables.conf
systemctl reload nftables.service
```

Note: You COULD try to use [PropagatesReloadTo](https://www.freedesktop.org/software/systemd/man/systemd.unit.html#PropagatesReloadTo=) to allow the use of 'reload'.
