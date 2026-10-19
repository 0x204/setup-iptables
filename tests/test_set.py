#!/usr/bin/env python3
"""Integration tests for set.sh.

Run as root:  python3 tests/test_set.py

Requires iptables, ipset and iproute2. Every test builds fresh network
namespaces (a server where set.sh runs and a client wired to it with a veth
pair) inside a private mount namespace, so the host is left untouched.
"""

import contextlib
import ctypes
import filecmp
import os
import random
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "set.sh")
INSTALLED = "/usr/local/sbin/setup-iptables"
UNIT = "/etc/systemd/system/setup-iptables.service"
CONFIG = "/etc/default/setup-iptables"
IPV6 = os.path.exists("/proc/net/if_inet6")

SERVER, CLIENT, CLIENT2, BLOCKED = "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.66"

# Where set.sh writes, plus /run for netns handles: every test starts empty.
SCRATCH_MOUNTS = ("/etc/default", "/etc/systemd/system", "/usr/local/sbin", "/var/lib", "/run")

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

# What earlier versions of set.sh appended to INPUT.
LEGACY_RULES = """\
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
""".splitlines()

CLONE_NEWNET = 0x40000000
libc = ctypes.CDLL(None, use_errno=True)


def setns(fd):
    if libc.setns(fd, CLONE_NEWNET):
        raise OSError(ctypes.get_errno(), "setns failed")


def unshare_net():
    if libc.unshare(CLONE_NEWNET):
        raise OSError(ctypes.get_errno(), "unshare failed")


def sh(*cmd, **kwargs):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs).stdout


def on_client(*cmd):
    return sh("ip", "netns", "exec", "client", *cmd)


def read_lines(path):
    with open(path) as f:
        return f.read().splitlines()


@contextlib.contextmanager
def client_side():
    """Sockets created in this block live in the client namespace."""
    own = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
    client = os.open("/run/netns/client", os.O_RDONLY)
    try:
        setns(client)
        yield
    finally:
        setns(own)
        os.close(client)
        os.close(own)


def connect(host, port, source=None, timeout=1.0):
    """Return a connected socket, or None if the handshake did not complete."""
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        if source:
            sock.bind((source, 0))
        sock.connect((host, port))
    except OSError:
        sock.close()
        return None
    return sock


def reaches(host, port, source=None, timeout=1.0):
    """True if a TCP handshake with host:port completes."""
    sock = connect(host, port, source, timeout)
    if sock:
        sock.close()
    return sock is not None


def client_reaches(port, source=CLIENT, timeout=1.0):
    with client_side():
        return reaches(SERVER, port, source, timeout)


def recv(sock, size, timeout=2.0):
    sock.settimeout(timeout)
    try:
        return sock.recv(size)
    except socket.timeout:
        return None


def receive(sock, timeout):
    deadline = time.monotonic() + timeout
    while (left := deadline - time.monotonic()) > 0 and select.select([sock], [], [], left)[0]:
        yield sock.recv(65535)


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def probe(port, flags):
    """Send a crafted TCP segment from the client; return the reply's flags or None."""
    sport = random.randint(20000, 60000)
    header = struct.pack("!HHIIBBHHH", sport, port, random.getrandbits(32), 0, 5 << 4, flags, 65535, 0, 0)
    pseudo = socket.inet_aton(CLIENT) + socket.inet_aton(SERVER) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, 20)
    segment = header[:16] + struct.pack("!H", checksum(pseudo + header)) + header[18:]
    with client_side():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    with sock:
        sock.sendto(segment, (SERVER, 0))
        for packet in receive(sock, 0.5):
            ihl = (packet[0] & 0x0F) * 4
            if struct.unpack("!HH", packet[ihl:ihl + 4]) == (port, sport):
                return packet[ihl + 13]
    return None


def ping_burst(count):
    """Send echo requests from the client back to back; return how many got a reply."""
    ident = random.getrandbits(16)
    with client_side():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    with sock:
        for seq in range(count):
            header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
            sock.sendto(header[:2] + struct.pack("!H", checksum(header)) + header[4:], (SERVER, 0))
        answered = set()
        for packet in receive(sock, 1.0):
            ihl = (packet[0] & 0x0F) * 4
            kind, _, _, reply_id, seq = struct.unpack("!BBHHH", packet[ihl:ihl + 8])
            if kind == 0 and reply_id == ident:
                answered.add(seq)
    return len(answered)


def tcp_stat(name):
    with open("/proc/thread-self/net/netstat") as f:
        keys, values = (line.split() for line in f if line.startswith("TcpExt:"))
    return int(values[keys.index(name)])


class Listener:
    """TCP server that accepts connections in a background thread."""

    def __init__(self, host, port):
        self.sock = socket.create_server((host, port))
        self.conns = []
        self._accepted = threading.Semaphore(0)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(conn)
            self._accepted.release()

    def wait(self, timeout=1.0):
        return self._accepted.acquire(timeout=timeout)

    def close(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        for conn in self.conns:
            conn.close()


class SetShTest(unittest.TestCase):
    def setUp(self):
        host_ns = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
        self.addCleanup(os.close, host_ns)
        self.addCleanup(setns, host_ns)
        unshare_net()
        for path in SCRATCH_MOUNTS:
            sh("mount", "-t", "tmpfs", "tmpfs", path)
            self.addCleanup(sh, "umount", "-R", path)
        sh("ip", "link", "set", "lo", "up")
        sh("ip", "netns", "add", "client")
        self.addCleanup(sh, "ip", "netns", "delete", "client")
        sh("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1", "netns", "client")
        sh("ip", "addr", "add", f"{SERVER}/24", "dev", "veth0")
        sh("ip", "link", "set", "veth0", "up")
        for addr in (CLIENT, CLIENT2, BLOCKED):
            on_client("ip", "addr", "add", f"{addr}/24", "dev", "veth1")
        on_client("ip", "link", "set", "lo", "up")
        on_client("ip", "link", "set", "veth1", "up")

    def run_script(self, *args, env=None, ok=True):
        result = subprocess.run(["bash", SCRIPT, *args], check=False, capture_output=True, text=True, env=env)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def apply(self):
        self.run_script("apply")

    def configure(self, **settings):
        with open(CONFIG, "w") as f:
            f.writelines(f"{key}={value}\n" for key, value in settings.items())

    def listen(self, port, host=SERVER):
        listener = Listener(host, port)
        self.addCleanup(listener.close)
        return listener

    def client_connect(self, port):
        with client_side():
            sock = connect(SERVER, port)
        self.assertIsNotNone(sock, f"the client cannot reach port {port}")
        self.addCleanup(sock.close)
        return sock

    def client_timestamps(self, enabled):
        on_client("sysctl", "-qw", f"net.ipv4.tcp_timestamps={int(enabled)}")

    def fake_commands(self, *names):
        """Stub out commands so they only log their arguments; return (env, log path)."""
        bin_dir, log = "/run/fake-bin", "/run/fake.log"
        os.makedirs(bin_dir, exist_ok=True)
        for name in names:
            path = os.path.join(bin_dir, name)
            with open(path, "w") as f:
                f.write(f'#!/bin/sh\necho "{name} $*" >> {log}\n')
            os.chmod(path, 0o755)
        return dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}"), log

    def test_clients_with_tcp_timestamps_can_connect(self):
        self.apply()
        self.client_timestamps(True)
        listener = self.listen(8080)
        self.assertTrue(client_reaches(8080))
        self.assertTrue(listener.wait())

    def test_server_can_connect_to_hosts_using_tcp_timestamps(self):
        self.apply()
        self.client_timestamps(True)
        with client_side():
            peer = Listener(CLIENT, 9000)
        self.addCleanup(peer.close)
        self.assertTrue(reaches(CLIENT, 9000))

    def test_connections_opened_before_apply_keep_working(self):
        # Older versions set loose=0, so conntrack dropped connections it had not seen start.
        sh("sysctl", "-qw", "net.netfilter.nf_conntrack_tcp_loose=0")
        self.client_timestamps(True)
        listener = self.listen(2222)
        client = self.client_connect(2222)
        self.assertTrue(listener.wait())
        self.apply()
        client.sendall(b"ping")
        self.assertEqual(recv(listener.conns[0], 4), b"ping")
        listener.conns[0].sendall(b"pong")
        self.assertEqual(recv(client, 4), b"pong")

    def test_lost_segments_are_recovered_with_sack(self):
        self.apply()
        self.client_timestamps(False)
        on_client("iptables", "-A", "INPUT", "-p", "tcp", "--sport", "8080", "-m", "statistic",
                  "--mode", "nth", "--every", "40", "--packet", "5", "-j", "DROP")
        listener = self.listen(8080)
        client = self.client_connect(8080)
        self.assertTrue(listener.wait())
        payload = os.urandom(1 << 21)
        threading.Thread(target=listener.conns[0].sendall, args=(payload,), daemon=True).start()
        received = 0
        while received < len(payload) and (chunk := recv(client, 1 << 16, timeout=10)):
            received += len(chunk)
        self.assertEqual(received, len(payload))
        self.assertGreater(tcp_stat("TCPSackRecovery"), 0)

    def test_blocked_source_cannot_connect(self):
        self.apply()
        sh("ipset", "add", "blocked", BLOCKED)
        self.client_timestamps(False)
        self.listen(8080)
        self.assertTrue(client_reaches(8080))
        self.assertFalse(client_reaches(8080, source=BLOCKED))

    def test_blocked_source_is_dropped_for_udp_too(self):
        self.apply()
        sh("ipset", "add", "blocked", BLOCKED)
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(server.close)
        server.bind((SERVER, 5000))
        for source, expected in ((CLIENT, b"hello"), (BLOCKED, None)):
            with client_side():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            with sock:
                sock.bind((source, 0))
                sock.sendto(b"hello", (SERVER, 5000))
            self.assertEqual(recv(server, 5, timeout=0.5), expected)

    def test_malformed_segments_get_no_answer(self):
        self.apply()
        self.assertEqual(probe(9, SYN), RST | ACK)
        for name, flags in (("NULL", 0), ("XMAS", FIN | PSH | URG), ("FIN", FIN)):
            with self.subTest(name):
                self.assertIsNone(probe(9, flags))

    def test_ssh_connection_burst_is_throttled(self):
        self.apply()
        self.listen(22)
        attempts = [client_reaches(22, timeout=0.8) for _ in range(5)]
        self.assertEqual(attempts, [True, True, True, False, False])

    def test_ssh_throttling_is_per_source(self):
        self.apply()
        self.listen(22)
        for _ in range(4):
            client_reaches(22, timeout=0.8)
        self.assertTrue(client_reaches(22, source=CLIENT2))

    def test_ssh_port_is_configurable(self):
        self.configure(SSH_PORT=2200)
        self.apply()
        self.listen(2200)
        attempts = [client_reaches(2200, timeout=0.8) for _ in range(4)]
        self.assertEqual(attempts, [True, True, True, False])

    def test_loopback_traffic_is_not_limited(self):
        self.apply()
        self.listen(22, host="127.0.0.1")
        attempts = [reaches("127.0.0.1", 22, timeout=0.8) for _ in range(5)]
        self.assertEqual(attempts, [True] * 5)

    def test_kernel_syn_flood_settings(self):
        sh("sysctl", "-qw", "net.ipv4.tcp_syncookies=0", "net.ipv4.tcp_synack_retries=5")
        self.apply()
        values = sh("sysctl", "-n", "net.ipv4.tcp_syncookies", "net.ipv4.tcp_synack_retries")
        self.assertEqual(values.split(), ["1", "1"])

    def test_ping_flood_is_rate_limited(self):
        self.apply()
        answered = ping_burst(60)
        self.assertGreater(answered, 0)
        self.assertLess(answered, 60)

    def test_timestamp_filter_drops_only_timestamped_syns_to_listed_ports(self):
        self.configure(TIMESTAMP_FILTER_PORTS=8080)
        self.apply()
        self.listen(8080)
        self.listen(8081)
        self.client_timestamps(True)
        self.assertFalse(client_reaches(8080))
        self.assertTrue(client_reaches(8081))
        self.client_timestamps(False)
        self.assertTrue(client_reaches(8080))

    def test_invalid_settings_are_rejected_before_any_change(self):
        self.configure(SSH_PORT="22,23")
        result = self.run_script("apply", ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("setup-iptables", sh("iptables", "-S"))
        self.assertEqual(sh("ipset", "list", "-n"), "")

    def test_reapplying_changes_nothing(self):
        self.apply()
        state = sh("iptables", "-S") + sh("ipset", "list", "-t")
        self.apply()
        self.assertEqual(sh("iptables", "-S") + sh("ipset", "list", "-t"), state)

    def test_rules_of_other_tools_are_kept(self):
        sh("iptables", "-N", "f2b-sshd")
        sh("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT")
        sh("iptables", "-A", "INPUT", "-j", "f2b-sshd")
        self.apply()
        self.apply()
        rules = sh("iptables", "-S").splitlines()
        self.assertIn("-A INPUT -p tcp -m tcp --dport 8443 -j ACCEPT", rules)
        self.assertIn("-A INPUT -j f2b-sshd", rules)

    def test_rules_left_by_older_versions_are_removed(self):
        sh("ipset", "create", "blocked", "hash:ip", "timeout", "180000")
        for rule in LEGACY_RULES:
            sh("iptables", "-A", "INPUT", *rule.split())
        self.apply()
        self.assertEqual(sh("iptables", "-S", "INPUT").splitlines(),
                         ["-P INPUT ACCEPT", "-A INPUT -j setup-iptables"])

    def test_lookalike_admin_rules_are_kept(self):
        sh("iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
        self.apply()
        self.assertIn("-A INPUT -m conntrack --ctstate INVALID -j DROP", sh("iptables", "-S", "INPUT").splitlines())

    def test_blocklist_survives_reboot(self):
        self.apply()
        sh("ipset", "add", "blocked", "192.0.2.10", "timeout", "0")
        sh("ipset", "add", "blocked", "192.0.2.11")
        self.run_script("save")
        unshare_net()  # reboot: empty network stack, same disk
        self.apply()
        members = sh("ipset", "list", "blocked")
        self.assertIn("192.0.2.10 timeout 0\n", members)
        self.assertIn("192.0.2.11 timeout ", members)

    def test_reapply_keeps_blocklist_edits(self):
        self.apply()
        sh("ipset", "add", "blocked", "192.0.2.10")
        self.run_script("save")
        sh("ipset", "del", "blocked", "192.0.2.10")
        self.apply()
        self.assertNotIn("192.0.2.10", sh("ipset", "list", "blocked"))

    @unittest.skipIf(IPV6, "IPv6 is enabled on this kernel")
    def test_hosts_without_ipv6_are_supported(self):
        self.apply()
        self.assertNotIn("setup-iptables", sh("ip6tables", "-S"))

    @unittest.skipUnless(IPV6, "IPv6 is disabled on this kernel")
    def test_ipv6_traffic_goes_through_the_guard(self):
        self.apply()
        self.assertIn("-A INPUT -j setup-iptables", sh("ip6tables", "-S", "INPUT").splitlines())
        sh("ipset", "add", "blocked6", "2001:db8::1")

    def test_install_enables_the_boot_service(self):
        os.makedirs("/run/systemd/system")
        env, log = self.fake_commands("systemctl", "apt-get")
        self.run_script("install", env=env)
        self.assertTrue(os.access(INSTALLED, os.X_OK))
        self.assertTrue(filecmp.cmp(SCRIPT, INSTALLED, shallow=False))
        sh("systemd-analyze", "verify", UNIT)
        self.assertEqual(read_lines(log), [
            "systemctl daemon-reload",
            "systemctl enable setup-iptables.service",
            "systemctl restart setup-iptables.service",
        ])

    def test_install_fetches_missing_packages_first(self):
        os.makedirs("/run/systemd/system")
        env, log = self.fake_commands("systemctl", "apt-get")
        env["PATH"] = "/run/fake-bin:/usr/bin:/bin"  # no sbin: ipset and iptables look missing
        self.run_script("install", env=env)
        update, install, *rest = read_lines(log)
        self.assertEqual(update.split()[:2], ["apt-get", "update"])
        self.assertEqual(install.split()[:2], ["apt-get", "install"])
        self.assertLessEqual({"iptables", "ipset"}, set(install.split()))
        self.assertEqual(rest[-1], "systemctl restart setup-iptables.service")

    def test_uninstall_removes_rules_sets_and_files(self):
        os.makedirs("/run/systemd/system")
        env, log = self.fake_commands("systemctl", "apt-get")
        self.run_script("install", env=env)
        self.apply()
        self.run_script("uninstall", env=env)
        self.assertNotIn("setup-iptables", sh("iptables", "-S"))
        self.assertEqual(sh("ipset", "list", "-n"), "")
        self.assertFalse(os.path.exists(INSTALLED))
        self.assertFalse(os.path.exists(UNIT))
        self.assertIn("systemctl disable --now setup-iptables.service", read_lines(log))


def main():
    if os.geteuid() != 0:
        sys.exit("run as root: the tests create network namespaces")
    if not os.environ.get("SETUP_IPTABLES_SANDBOX"):
        os.environ["SETUP_IPTABLES_SANDBOX"] = "1"
        os.execvp("unshare", ["unshare", "--mount", "--propagation", "private", sys.executable, *sys.argv])
    with contextlib.suppress(FileNotFoundError):  # conntrack may be built in, with no kmod around
        subprocess.run(["modprobe", "-q", "nf_conntrack"], check=False)
    unittest.main()


if __name__ == "__main__":
    main()
