#!/bin/bash
#
# Flood and brute-force protection for Debian/Ubuntu servers: kernel SYN-flood
# settings plus an iptables/ip6tables guard chain with an ipset blocklist,
# re-applied at boot by a systemd unit. See README.md.
#
# Usage: set.sh [install|apply|save|uninstall]    (default: install)

set -euo pipefail

readonly NAME=setup-iptables
readonly CHAIN=setup-iptables
readonly SET4=blocked SET6=blocked6
readonly BLOCK_TIMEOUT=180000 # seconds; entries added with "timeout 0" never expire
readonly BIN=/usr/local/sbin/$NAME
readonly UNIT=/etc/systemd/system/$NAME.service
readonly STATE=/var/lib/$NAME/ipsets
readonly CONFIG=/etc/default/$NAME

SSH_PORT=22
TIMESTAMP_FILTER_PORTS=

warn() {
  echo "$NAME: $*" >&2
}

die() {
  warn "$@"
  exit 1
}

have_ipv6() {
  [[ -e /proc/net/if_inet6 ]]
}

# sysctl(8) exits 0 even when the kernel refuses a value, so write /proc directly.
set_sysctl() {
  echo "$2" >"/proc/sys/${1//.//}"
}

load_config() {
  if [[ -r $CONFIG ]]; then
    # shellcheck source=/dev/null
    . "$CONFIG"
  fi
  [[ $SSH_PORT =~ ^[0-9]+$ ]] || die "SSH_PORT must be a single port number"
  [[ -z $TIMESTAMP_FILTER_PORTS || $TIMESTAMP_FILTER_PORTS =~ ^[0-9]+([,:][0-9]+)*$ ]] ||
    die "TIMESTAMP_FILTER_PORTS must list ports or port ranges, e.g. 7777,27015:27030"
}

apply_kernel_settings() {
  # conntrack's sysctls only show up once the module is loaded.
  [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]] || modprobe nf_conntrack

  set_sysctl net.ipv4.tcp_syncookies 1
  set_sysctl net.ipv4.tcp_synack_retries 1
  # Loose pickup (the kernel default) lets conntrack adopt connections opened
  # before the rules were loaded. Earlier versions turned it off, which cut
  # every SSH session that was open at the time.
  set_sysctl net.netfilter.nf_conntrack_tcp_loose 1

  # Room for connections worth ~1/16 of RAM (an entry costs ~384 bytes),
  # one hash bucket each. Only the host's initial namespace may change this.
  local mem_kb entries
  mem_kb=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
  entries=$((mem_kb * 1024 / 16 / 384))
  if ! { set_sysctl net.netfilter.nf_conntrack_buckets "$entries" &&
    set_sysctl net.netfilter.nf_conntrack_max "$entries"; } 2>/dev/null; then
    warn "cannot resize the conntrack table here (container?), keeping its current size"
  fi
}

ensure_sets() {
  if ! ipset -q list -n "$SET4" >/dev/null && [[ -r $STATE ]]; then
    ipset -exist restore <"$STATE" || warn "could not restore the blocklist saved in $STATE"
  fi
  ipset -exist create "$SET4" hash:ip family inet timeout "$BLOCK_TIMEOUT"
  if have_ipv6; then
    ipset -exist create "$SET6" hash:ip family inet6 timeout "$BLOCK_TIMEOUT"
  fi
}

# Earlier versions appended these straight to INPUT, so a rerun never replaced
# them. Their timestamp REJECT is unique to this script; without it, rules that
# merely look the same belong to someone else.
remove_legacy_rules() {
  iptables -w -C INPUT -p tcp -m tcp --tcp-option 8 -j REJECT 2>/dev/null || return 0
  local rule
  while read -r rule; do
    # shellcheck disable=SC2086 # the spec has to be split into words
    while iptables -w -D INPUT $rule 2>/dev/null; do :; done
  done <<'EOF'
-p tcp -m tcp --tcp-option 8 -j REJECT
-p tcp -m tcp --tcp-option 5 -j REJECT
-p tcp -m tcp --tcp-option 4 -j RETURN
-p tcp -m tcp -m set --match-set blocked src -j DROP
-m conntrack --ctstate INVALID -j DROP
-p tcp --tcp-flags ALL NONE -j DROP
-p tcp --tcp-flags ALL ALL -j DROP
-p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
-p tcp --tcp-flags SYN,RST SYN,RST -j DROP
-p tcp --tcp-flags FIN,RST FIN,RST -j DROP
-p tcp --tcp-flags ACK,FIN FIN -j DROP
-p tcp --tcp-flags ACK,PSH PSH -j DROP
-p tcp --tcp-flags ACK,URG URG -j DROP
-p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
-p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
-p icmp -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
EOF
}

# The chain only drops; everything else returns to INPUT, so rules added by
# ufw, fail2ban or the admin still decide what is accepted. Pings sharing an
# ICMP id are one conntrack flow, so their limit comes before ESTABLISHED.
guard_rules() {
  local blocklist=$1 ping=$2 recent="-m recent --name ssh ${3:-}"
  cat <<EOF
*filter
:$CHAIN - [0:0]
-A $CHAIN -i lo -j RETURN
-A $CHAIN -m set --match-set $blocklist src -j DROP
-A $CHAIN -m conntrack --ctstate INVALID -j DROP
-A $CHAIN $ping -m limit --limit 10/second --limit-burst 20 -j RETURN
-A $CHAIN $ping -j DROP
-A $CHAIN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A $CHAIN -p tcp --syn --dport $SSH_PORT $recent --set
-A $CHAIN -p tcp --syn --dport $SSH_PORT $recent --update --seconds 60 --hitcount 4 -j DROP
EOF
  if [[ -n $TIMESTAMP_FILTER_PORTS ]]; then
    echo "-A $CHAIN -p tcp -m tcp --syn --tcp-option 8 -m multiport --dports $TIMESTAMP_FILTER_PORTS -j DROP"
  fi
  echo COMMIT
}

# iptables-restore swaps the chain's contents in one transaction.
load_guard() {
  local cmd=$1
  shift
  guard_rules "$@" | "$cmd-restore" -w --noflush
  "$cmd" -w -C INPUT -j "$CHAIN" 2>/dev/null || "$cmd" -w -I INPUT -j "$CHAIN"
}

cmd_apply() {
  load_config
  apply_kernel_settings
  ensure_sets
  remove_legacy_rules
  load_guard iptables "$SET4" "-p icmp --icmp-type echo-request"
  if have_ipv6; then
    # Count SSH attempts per /64: one IPv6 client usually owns the whole block.
    load_guard ip6tables "$SET6" "-p ipv6-icmp --icmpv6-type echo-request" "--mask ffff:ffff:ffff:ffff::"
  fi
}

cmd_save() {
  local sets=() set tmp
  for set in "$SET4" "$SET6"; do
    if ipset -q list -n "$set" >/dev/null; then
      sets+=("$set")
    fi
  done
  ((${#sets[@]})) || return 0
  mkdir -p "${STATE%/*}"
  tmp=$(mktemp "$STATE.XXXXXX")
  for set in "${sets[@]}"; do
    ipset save "$set"
  done >"$tmp"
  mv "$tmp" "$STATE"
}

install_packages() {
  local missing=()
  command -v ipset >/dev/null || missing+=(ipset)
  command -v iptables-restore >/dev/null || missing+=(iptables)
  ((${#missing[@]})) || return 0
  command -v apt-get >/dev/null || die "install ${missing[*]} and run again"
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${missing[@]}"
}

write_unit() {
  cat >"$UNIT" <<EOF
[Unit]
Description=Firewall guard chain and blocklist ($NAME)
Documentation=https://github.com/0x204/setup-iptables
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target shutdown.target
After=local-fs.target systemd-modules-load.service systemd-sysctl.service
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BIN apply
ExecStop=$BIN save

[Install]
WantedBy=multi-user.target
EOF
}

cmd_install() {
  [[ -d /run/systemd/system ]] || die "systemd is not running; '$0 apply' loads the rules until reboot"
  load_config
  install_packages
  if [[ ! ${BASH_SOURCE[0]} -ef $BIN ]]; then
    install -D -m 0755 "${BASH_SOURCE[0]}" "$BIN"
  fi
  write_unit
  systemctl daemon-reload
  systemctl enable "$NAME.service"
  systemctl restart "$NAME.service"
  echo "$NAME: rules are active and will be reapplied at boot; settings live in $CONFIG"
}

cmd_uninstall() {
  if [[ -e $UNIT ]]; then
    systemctl disable --now "$NAME.service"
    rm -f "$UNIT"
    systemctl daemon-reload
  fi
  local cmd set
  for cmd in iptables ip6tables; do
    while "$cmd" -w -D INPUT -j "$CHAIN" 2>/dev/null; do :; done
    if "$cmd" -w -S "$CHAIN" >/dev/null 2>&1; then
      "$cmd" -w -F "$CHAIN"
      "$cmd" -w -X "$CHAIN"
    fi
  done
  for set in "$SET4" "$SET6"; do
    if ipset -q list -n "$set" >/dev/null; then
      ipset destroy "$set" || warn "$set is still used by other rules, left in place"
    fi
  done
  rm -rf "${STATE%/*}" "$BIN"
}

main() {
  ((EUID == 0)) || die "run as root"
  case ${1:-install} in
    install) cmd_install ;;
    apply) cmd_apply ;;
    save) cmd_save ;;
    uninstall) cmd_uninstall ;;
    *) die "usage: ${0##*/} [install|apply|save|uninstall]" ;;
  esac
}

main "$@"
