import socket

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_status
from routersploit.core.exploit.printer import print_error
from routersploit.core.exploit.utils import is_ipv4
from routersploit.core.exploit.utils import is_ipv6
from routersploit.core.exploit.utils import format_hostport


TCP_SOCKET_TIMEOUT = 8.0


class TCPCli:
    """ TCP Client provides methods to handle communication with TCP server """

    def __init__(self, tcp_target: str, tcp_port: int, verbosity: bool = False) -> None:
        """ TCP client constructor

        :param str tcp_target: target TCP server ip address
        :param int tcp_port: target TCP server port
        :param bool verbosity: display verbose output
        :return None:
        """

        self.tcp_target = tcp_target
        self.tcp_port = tcp_port
        self.verbosity = verbosity

        self.peer = format_hostport(self.tcp_target, self.tcp_port)

        if is_ipv4(self.tcp_target):
            self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif is_ipv6(self.tcp_target):
            self.tcp_client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            print_error("Target address is not valid IPv4 nor IPv6 address", verbose=self.verbosity)
            return None

        self.tcp_client.settimeout(TCP_SOCKET_TIMEOUT)

    @staticmethod
    def _socket_address(address: str, port: int) -> tuple:
        """ Builds address tuple accepted by socket.connect

        IPv6 addresses carrying a zone identifier (e.g. fe80::1%eth0) cannot be
        passed to socket.connect as a string, the zone must be given as a separate
        scope identifier, so it is resolved via getaddrinfo.
        """

        if is_ipv6(address) and "%" in address:
            return socket.getaddrinfo(address, port, socket.AF_INET6, socket.SOCK_STREAM)[0][4]

        return (address, port)

    def connect(self) -> bool:
        """ Connect to TCP server

        :return bool: True if connection was successful, False otherwise
        """
        try:
            self.tcp_client.connect(self._socket_address(self.tcp_target, self.tcp_port))
            print_status(self.peer, "TCP Connection established", verbose=self.verbosity)
            return True

        except Exception as err:
            print_error(self.peer, "TCP Error while connecting to the server", err, verbose=self.verbosity)

        return False

    def send(self, data: bytes) -> bool:
        """ Send data to TCP server

        :param bytes data: data that should be sent to TCP server
        :return bool: True if sending data was successful, False otherwise
        """
        try:
            self.tcp_client.send(data)
            return True
        except Exception as err:
            print_error(self.peer, "TCP Error while sending data", err, verbose=self.verbosity)

        return False

    def recv(self, num: int) -> bytes:
        """ Receive data from TCP server

        :param int num: number of bytes that should be received from the server
        :return bytes: data that was received from the server
        """

        try:
            response = self.tcp_client.recv(num)
            return response
        except Exception as err:
            print_error(self.peer, "TCP Error while receiving data", err, verbose=self.verbosity)

        return None

    def recv_all(self, num: int) -> bytes:
        """ Receive all data sent by the server

        :param int num: number of total bytes that should be received
        :return bytes: data that was received from the server
        """

        try:
            response = b""
            received = 0
            while received < num:
                tmp = self.tcp_client.recv(num - received)

                if tmp:
                    received += len(tmp)
                    response += tmp
                else:
                    break

            return response
        except Exception as err:
            print_error(self.peer, "TCP Error while receiving all data", err, verbose=self.verbosity)

        return None

    def close(self) -> bool:
        """ Close connection to TCP server

        :return bool: True if closing connection was successful, False otherwise
        """

        try:
            self.tcp_client.close()
            return True
        except Exception as err:
            print_error(self.peer, "TCP Error while closing tcp socket", err, verbose=self.verbosity)

        return False


# pylint: disable=no-member
class TCPClient(Exploit):
    """ TCP Client exploit """

    target_protocol = Protocol.TCP

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def tcp_create(self, target: str = None, port: int = None) -> TCPCli:
        """ Creates TCP client

        :param str target: target TCP server ip address
        :param int port: target TCP server port
        :return TCPCli: TCP client object
        """

        tcp_target = target if target else self.target
        tcp_port = port if port else self.port

        tcp_client = TCPCli(tcp_target, tcp_port, verbosity=self.verbosity)
        return tcp_client
