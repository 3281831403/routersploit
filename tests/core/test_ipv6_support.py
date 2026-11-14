import socket

import pytest

import routersploit.core.exploit.exploit as exploit_module
from routersploit.core.exploit import utils
from routersploit.core.exploit.exceptions import OptionValidationError
from routersploit.core.exploit.exploit import Exploit, multi
from routersploit.core.exploit.option import OptIP, OptPort
from routersploit.core.http.http_client import HTTPClient
from routersploit.core.tcp.tcp_client import TCPCli, TCPClient
from routersploit.core.udp.udp_client import UDPCli, UDPClient


def _ipv6_available():
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.close()
        return True
    except OSError:
        return False


requires_ipv6 = pytest.mark.skipif(not _ipv6_available(), reason="IPv6 not available")


# --- address validation -----------------------------------------------------

@pytest.mark.parametrize("address", [
    "192.168.1.1",
    "0.0.0.0",
    "255.255.255.255",
])
def test_is_ipv4_accepts(address):
    assert utils.is_ipv4(address) is True
    assert utils.is_ip(address) is True


@pytest.mark.parametrize("address", [
    "2001:db8::1",
    "::1",
    "::",
    "fe80::1",
    "fe80::1%eth0",
    "2001:db8::1%1",
    "::ffff:192.168.1.1",
])
def test_is_ipv6_accepts(address):
    assert utils.is_ipv6(address) is True
    assert utils.is_ip(address) is True


@pytest.mark.parametrize("address", [
    "",
    "InvalidIP",
    "256.1.1.1",
    "1.2.3",
    "file://targets.txt",
    "targets.txt",
    "fe80::1%",
    "[2001:db8::1]",
    "2001:db8::zz",
])
def test_is_ip_rejects(address):
    assert utils.is_ipv4(address) is False
    assert utils.is_ipv6(address) is False
    assert utils.is_ip(address) is False


def test_is_target_file():
    assert utils.is_target_file("file://targets.txt") is True
    assert utils.is_target_file("192.168.1.1") is False
    assert utils.is_target_file("") is False


@pytest.mark.parametrize("entry, expected", [
    ("192.168.1.1", ("192.168.1.1", None)),
    ("192.168.1.1:8080", ("192.168.1.1", 8080)),
    ("2001:db8::1", ("2001:db8::1", None)),
    ("[2001:db8::1]", ("2001:db8::1", None)),
    ("[2001:db8::1]:8080", ("2001:db8::1", 8080)),
    ("[fe80::1%eth0]:443", ("fe80::1%eth0", 443)),
    ("fe80::1%eth0", ("fe80::1%eth0", None)),
    ("  10.0.0.1:22  ", ("10.0.0.1", 22)),
])
def test_parse_target_entry(entry, expected):
    assert utils.parse_target_entry(entry) == expected


@pytest.mark.parametrize("entry", [
    "",
    "not-an-ip",
    "192.168.1.256",
    "[2001:db8::1",
    "[192.168.1.1]:80",
    "[2001:db8::1]80",
    "192.168.1.1:notaport",
    "192.168.1.1:0",
    "192.168.1.1:70000",
])
def test_parse_target_entry_rejects(entry):
    with pytest.raises(ValueError):
        utils.parse_target_entry(entry)


# --- URL / host:port formatting --------------------------------------------

def test_bracket_ipv6():
    assert utils.bracket_ipv6("2001:db8::1") == "[2001:db8::1]"
    assert utils.bracket_ipv6("fe80::1%eth0") == "[fe80::1%eth0]"
    assert utils.bracket_ipv6("192.168.1.1") == "192.168.1.1"
    assert utils.bracket_ipv6("[::1]") == "[::1]"


@pytest.mark.parametrize("address, port, expected", [
    ("192.168.1.1", 80, "192.168.1.1:80"),
    ("2001:db8::1", 80, "[2001:db8::1]:80"),
    ("fe80::1%eth0", 8080, "[fe80::1%eth0]:8080"),
    ("2001:db8::1", None, "[2001:db8::1]"),
])
def test_format_hostport(address, port, expected):
    assert utils.format_hostport(address, port) == expected


# --- OptIP ------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "",
    "192.168.1.1",
    "2001:db8::1",
    "::1",
    "fe80::1%eth0",
    "file://targets.txt",
])
def test_opt_ip_accepts(value):
    opt_ip = OptIP("", "Test IP Description")
    opt_ip.__set__(None, value)

    assert opt_ip.value == value
    assert opt_ip.display_value == value
    assert opt_ip.__get__(None, None) == value


@pytest.mark.parametrize("value", [
    "InvalidIP",
    "256.1.1.1",
    "2001:db8::zz",
    "http://targets.txt",
])
def test_opt_ip_rejects(value):
    opt_ip = OptIP("", "Test IP Description")

    with pytest.raises(OptionValidationError):
        opt_ip.__set__(None, value)


# --- HTTP URL assembly ------------------------------------------------------

class _HTTPClient(HTTPClient):
    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")


@pytest.mark.parametrize("target, port, expected", [
    ("192.168.1.1", 80, "http://192.168.1.1:80/"),
    ("2001:db8::1", 80, "http://[2001:db8::1]:80/"),
    ("fe80::1%eth0", 8080, "http://[fe80::1%eth0]:8080/admin"),
])
def test_http_url_brackets_ipv6(target, port, expected):
    client = _HTTPClient()
    client.target = target
    client.port = port

    path = "/admin" if expected.endswith("/admin") else "/"
    assert client.get_target_url(path=path) == expected


def test_http_url_brackets_ipv6_with_ssl():
    client = _HTTPClient()
    client.target = "2001:db8::1"
    client.port = 443
    client.ssl = "true"

    assert client.get_target_url() == "https://[2001:db8::1]:443"


# --- TCP client family / peer / connect ------------------------------------

def test_tcp_peer_ipv4_unchanged():
    client = TCPCli("192.168.1.1", 80)

    assert client.peer == "192.168.1.1:80"
    assert client.tcp_client.family == socket.AF_INET
    client.close()


def test_tcp_peer_ipv6_is_bracketed():
    client = TCPCli("2001:db8::1", 8080)

    assert client.peer == "[2001:db8::1]:8080"
    assert client.tcp_client.family == socket.AF_INET6
    client.close()


def test_tcp_peer_ipv6_zone_is_bracketed():
    client = TCPCli("fe80::1%eth0", 80)

    assert client.peer == "[fe80::1%eth0]:80"
    assert client.tcp_client.family == socket.AF_INET6
    client.close()


@requires_ipv6
def test_tcp_connect_ipv6_loopback():
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("::1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    try:
        client = TCPCli("::1", port, verbosity=False)
        try:
            assert client.connect() is True
            assert client.tcp_client.family == socket.AF_INET6
            assert client.peer == "[::1]:{}".format(port)
        finally:
            client.close()
    finally:
        server.close()


def test_tcp_connect_ipv4_loopback():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    try:
        client = TCPCli("127.0.0.1", port, verbosity=False)
        try:
            assert client.connect() is True
            assert client.tcp_client.family == socket.AF_INET
            assert client.peer == "127.0.0.1:{}".format(port)
        finally:
            client.close()
    finally:
        server.close()


def test_tcp_scoped_address_uses_scope_id(monkeypatch):
    captured = {}

    def fake_getaddrinfo(host, port, family=0, type=0, *args, **kwargs):
        captured["args"] = (host, port, family, type)
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1", port, 0, 3))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert TCPCli._socket_address("fe80::1%eth0", 80) == ("fe80::1", 80, 0, 3)
    assert captured["args"] == ("fe80::1%eth0", 80, socket.AF_INET6, socket.SOCK_STREAM)

    # unscoped addresses are passed through unchanged
    assert TCPCli._socket_address("2001:db8::1", 80) == ("2001:db8::1", 80)
    assert TCPCli._socket_address("192.168.1.1", 80) == ("192.168.1.1", 80)


# --- UDP client family / peer / send ---------------------------------------

def test_udp_peer_ipv4_unchanged():
    client = UDPCli("192.168.1.1", 161)

    assert client.peer == "192.168.1.1:161"
    assert client.udp_client.family == socket.AF_INET
    client.close()


def test_udp_peer_ipv6_is_bracketed():
    client = UDPCli("2001:db8::1", 161)

    assert client.peer == "[2001:db8::1]:161"
    assert client.udp_client.family == socket.AF_INET6
    client.close()


def test_udp_scoped_address_uses_scope_id(monkeypatch):
    captured = {}

    def fake_getaddrinfo(host, port, family=0, type=0, *args, **kwargs):
        captured["args"] = (host, port, family, type)
        return [(socket.AF_INET6, socket.SOCK_DGRAM, 17, "", ("fe80::1", port, 0, 3))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert UDPCli._socket_address("fe80::1%eth0", 69) == ("fe80::1", 69, 0, 3)
    assert captured["args"] == ("fe80::1%eth0", 69, socket.AF_INET6, socket.SOCK_DGRAM)


@requires_ipv6
def test_udp_send_ipv6_loopback():
    server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.bind(("::1", 0))
    server.settimeout(5)
    port = server.getsockname()[1]

    try:
        client = UDPCli("::1", port, verbosity=False)
        try:
            assert client.udp_client.family == socket.AF_INET6
            assert client.send(b"hello") is True

            data, _ = server.recvfrom(16)
            assert data == b"hello"
        finally:
            client.close()
    finally:
        server.close()


def test_udp_send_ipv4_loopback():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(5)
    port = server.getsockname()[1]

    try:
        client = UDPCli("127.0.0.1", port, verbosity=False)
        try:
            assert client.udp_client.family == socket.AF_INET
            assert client.send(b"hello") is True

            data, _ = server.recvfrom(16)
            assert data == b"hello"
        finally:
            client.close()
    finally:
        server.close()


# --- multi target list handling --------------------------------------------

class _ListExploit(Exploit):
    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target port")

    def __init__(self):
        self.visited = []

    def run(self):
        self.attack()

    @multi
    def attack(self):
        self.visited.append((self.target, self.port))


def test_multi_target_list(tmp_path, monkeypatch):
    errors = []
    monkeypatch.setattr(exploit_module, "print_error", lambda *args, **kwargs: errors.append(args))

    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "192.168.1.1\n"
        "192.168.1.2:2222\n"
        "\n"
        "2001:db8::1\n"
        "[2001:db8::2]:2323\n"
        "[fe80::3%eth0]:4444\n"
        "not-an-ip\n"
        "10.0.0.1\n"
        "192.168.1.3:70000\n"
        "10.0.0.2\n"
    )

    exploit = _ListExploit()
    exploit.port = 80
    exploit.target = "file://{}".format(target_file)
    exploit.run()

    assert exploit.visited == [
        ("192.168.1.1", 80),
        ("192.168.1.2", 2222),
        ("2001:db8::1", 80),
        ("2001:db8::2", 2323),
        ("fe80::3%eth0", 4444),
        ("10.0.0.1", 80),
        ("10.0.0.2", 80),
    ]

    # malformed lines are reported with their line number and skipped
    assert len(errors) == 2
    assert "{}:7".format(target_file) in errors[0][0]
    assert "{}:9".format(target_file) in errors[1][0]

    # original options are restored
    assert exploit.target == "file://{}".format(target_file)
    assert exploit.port == 80


def test_multi_target_list_keeps_module_port(tmp_path, monkeypatch):
    monkeypatch.setattr(exploit_module, "print_error", lambda *args, **kwargs: None)

    target_file = tmp_path / "targets.txt"
    target_file.write_text("192.168.1.1\n2001:db8::1\n2001:db8::2:2323\n")

    exploit = _ListExploit()
    exploit.port = 23
    exploit.target = "file://{}".format(target_file)
    exploit.run()

    # entries without a port use the port configured on the module;
    # an unbracketed IPv6 literal is an address, not ip:port
    assert exploit.visited == [
        ("192.168.1.1", 23),
        ("2001:db8::1", 23),
        ("2001:db8::2:2323", 23),
    ]
    assert exploit.target == "file://{}".format(target_file)
    assert exploit.port == 23


def test_multi_without_target_file_runs_once():
    exploit = _ListExploit()
    exploit.target = "2001:db8::1"
    exploit.port = 8080
    exploit.run()

    assert exploit.visited == [("2001:db8::1", 8080)]
    assert exploit.target == "2001:db8::1"
    assert exploit.port == 8080


def test_multi_restores_options_when_exploit_raises(tmp_path):
    class _RaisingExploit(Exploit):
        target = OptIP("", "Target IPv4 or IPv6 address")
        port = OptPort(80, "Target port")

        @multi
        def attack(self):
            raise RuntimeError("boom")

    target_file = tmp_path / "targets.txt"
    target_file.write_text("192.168.1.1\n2001:db8::1\n")

    exploit = _RaisingExploit()
    exploit.target = "file://{}".format(target_file)
    exploit.port = 80

    with pytest.raises(RuntimeError):
        exploit.attack()

    assert exploit.target == "file://{}".format(target_file)
    assert exploit.port == 80


# --- module wiring ----------------------------------------------------------

def test_tcp_client_uses_module_port_when_not_overridden():
    class _TCP(TCPClient):
        target = OptIP("", "Target IPv4 or IPv6 address")
        port = OptPort(1234, "Target TCP port")

    client = _TCP()
    client.target = "2001:db8::1"

    tcp_cli = client.tcp_create()

    assert tcp_cli.tcp_target == "2001:db8::1"
    assert tcp_cli.tcp_port == 1234
    assert tcp_cli.peer == "[2001:db8::1]:1234"
    tcp_cli.close()


def test_udp_client_uses_module_port_when_not_overridden():
    class _UDP(UDPClient):
        target = OptIP("", "Target IPv4 or IPv6 address")
        port = OptPort(5353, "Target UDP port")

    client = _UDP()
    client.target = "fe80::1%eth0"

    udp_cli = client.udp_create()

    assert udp_cli.udp_target == "fe80::1%eth0"
    assert udp_cli.udp_port == 5353
    assert udp_cli.peer == "[fe80::1%eth0]:5353"
    udp_cli.close()
