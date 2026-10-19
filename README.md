# setup-iptables

Flood and brute-force protection for Debian and Ubuntu servers.

## What it does

- Kernel: SYN cookies on, a single SYN-ACK retry, and a connection-tracking
  table sized to the machine (up to about 1/16 of RAM).
- A `setup-iptables` chain at the top of `INPUT`, for IPv4 and, when the kernel
  has it, IPv6. It drops:
  - everything from addresses in the `blocked` and `blocked6` ipsets;
  - packets that belong to no valid connection, such as NULL, XMAS and FIN scans;
  - pings beyond 10 per second (bursts of 20 are fine);
  - the 4th new SSH connection from one address (one /64 for IPv6) within 60 seconds;
  - optionally, SYNs that carry TCP timestamps on chosen ports (see `TIMESTAMP_FILTER_PORTS`).

  The chain never accepts anything itself. All other traffic continues through
  `INPUT`, so ufw, fail2ban and your own rules keep working. Traffic forwarded
  to containers, such as Docker's published ports, does not pass through
  `INPUT` and is not covered.
- `setup-iptables.service` reapplies the rules at boot and saves the blocklists
  at shutdown.

## Install

```bash
git clone https://github.com/0x204/setup-iptables
cd setup-iptables
sudo bash set.sh
```

Requires systemd. If `ipset` or `iptables` are missing, they are installed with
apt-get. Running the script again, for example after `git pull`, is safe: the
chain is replaced as a whole and nothing is duplicated. Rules left in `INPUT`
by earlier versions of the script are removed.

## Settings

Optional, in `/etc/default/setup-iptables`:

```bash
SSH_PORT=22                              # port that gets the connection limit
TIMESTAMP_FILTER_PORTS=7777,27015:27030  # empty by default
```

Apply changes with `sudo systemctl restart setup-iptables`.

`TIMESTAMP_FILTER_PORTS` drops new connections to the listed ports when the SYN
carries the TCP timestamps option. Windows leaves timestamps off by default;
Linux, macOS, iOS and Android send them. Set it only for services whose clients
all run Windows.

## Blocklist

```bash
sudo ipset add blocked 203.0.113.7              # expires after 50 hours
sudo ipset add blocked 203.0.113.8 timeout 0    # stays until removed
sudo ipset add blocked6 2001:db8::7
sudo ipset del blocked 203.0.113.7
sudo ipset list blocked
```

## Uninstall

```bash
sudo setup-iptables uninstall
```

This removes the chain, the blocklists, the service and the installed script.
Kernel settings return to their defaults after a reboot.

## Tests

```bash
sudo python3 tests/test_set.py
```

The tests run in throwaway network namespaces and leave the host's firewall
alone. They need Python 3.8+, `iptables`, `ipset` and `iproute2`.
