#!/usr/bin/env python
import logging
import os
import platform
import signal
import struct
import sys
import thread
import time
from SocketServer import ThreadingTCPServer, StreamRequestHandler
import pdb
import paramiko
import psutil
from multiprocessing import Process

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)-5s %(lineno)-3d - %(message)s',
    # filename=log_file,
    # filemode='a',
)


def byte_to_int(b):
    """
    Convert Unsigned byte to int
    :param b: byte value
    :return:  int value
    """
    return b & 0xFF


def port_from_byte(b1, b2):
    """

    :param b1: First byte of port
    :param b2: Second byte of port
    :return: Port in Int
    """
    return byte_to_int(b1) << 8 | byte_to_int(b2)


def host_from_ip(a, b, c, d):
    a = byte_to_int(a)
    b = byte_to_int(b)
    c = byte_to_int(c)
    d = byte_to_int(d)
    return "%d.%d.%d.%d" % (a, b, c, d)


def build_command_response(reply):
    start = b'\x05%s\x00\x01\x00\x00\x00\x00\x00\x00'
    return start % reply.get_byte_string()


def close_session(session):
    session.get_client_socket().close()
    logging.debug("Session[%s] closed" % session.get_id())


class Session(object):
    index = 0

    def __init__(self, client_socket):
        Session.index += 1
        self.__id = Session.index
        self.__client_socket = client_socket
        self._attr = {}

    def get_id(self):
        return self.__id

    def set_attr(self, key, value):
        self._attr[key] = value

    def get_client_socket(self):
        return self.__client_socket


class AddressType(object):
    IPV4 = 1
    DOMAIN_NAME = 3
    IPV6 = 4


class SocksCommand(object):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class SocksMethod(object):
    NO_AUTHENTICATION_REQUIRED = 0
    GSS_API = 1
    USERNAME_PASSWORD = 2


class ServerReply(object):
    def __init__(self, value):
        self.__value = value

    def get_byte_string(self):
        if self.__value == 0:
            return b'\x00'
        elif self.__value == 1:
            return b'\x01'
        elif self.__value == 2:
            return b'\x02'
        elif self.__value == 3:
            return b'\x03'
        elif self.__value == 4:
            return b'\x04'
        elif self.__value == 5:
            return b'\x05'
        elif self.__value == 6:
            return b'\x06'
        elif self.__value == 7:
            return b'\x07'
        elif self.__value == 8:
            return b'\x08'

    def get_value(self):
        return self.__value


class ReplyType(object):
    SUCCEEDED = ServerReply(0)
    GENERAL_SOCKS_SERVER_FAILURE = ServerReply(1)
    CONNECTION_NOT_ALLOWED_BY_RULESET = ServerReply(2)
    NETWORK_UNREACHABLE = ServerReply(3)
    HOST_UNREACHABLE = ServerReply(4)
    CONNECTION_REFUSED = ServerReply(5)
    TTL_EXPIRED = ServerReply(6)
    COMMAND_NOT_SUPPORTED = ServerReply(7)
    ADDRESS_TYPE_NOT_SUPPORTED = ServerReply(8)


class SocketPipe(object):
    BUFFER_SIZE = 1024 * 1024

    def __init__(self, socket1, socket2):
        self._socket1 = socket1
        self._socket2 = socket2
        self.__running = False

    def __transfer(self, socket1, socket2):
        while self.__running:
            try:
                data = socket1.recv(self.BUFFER_SIZE)
                if len(data) > 0:
                    socket2.sendall(data)
                else:
                    break
            except IOError:
                self.stop()
        self.stop()

    def start(self):
        self.__running = True
        thread.start_new_thread(self.__transfer, (self._socket1, self._socket2))
        thread.start_new_thread(self.__transfer, (self._socket2, self._socket1))

    def stop(self):
        self._socket1.close()
        # do not close socket!
        #self._socket2.close()
        self.__running = False

    def is_running(self):
        return self.__running


class CommandExecutor(object):
    def __init__(self, remote_server_host, remote_server_port, session, transport):
        # self.__proxy_socket = socket(AF_INET, SOCK_STREAM)
        self.__remote_server_host = remote_server_host
        self.__remote_server_port = remote_server_port
        self.__client = session.get_client_socket()
        self.__session = session
        self.transport = transport

    def do_connect(self):
        """
         o SOCKS CONNECT method
         :return: None
         """

        dst_addr, dst_port = self.__get_address()
        if dst_addr is None:
            return
        if dst_port is None:
            return
        connection = self.transport.get_connection()
        if connection is None:
            self.__client.send(build_command_response(ReplyType.NETWORK_UNREACHABLE))
            return
        try:
            # channel = connection.open_channel('direct-tcpip', (dst_addr, dst_port), ('', 0))
            channel = connection.open_channel(
                'direct-tcpip', dest_addr=tuple((dst_addr, dst_port)), src_addr=tuple(('127.0.0.1', 0)),
            )
        except paramiko.ChannelException:
            self.__client.send(build_command_response(ReplyType.NETWORK_UNREACHABLE))
            return
        self.__client.send(build_command_response(ReplyType.SUCCEEDED))
        socket_pipe = SocketPipe(self.__client, channel)
        socket_pipe.start()
        while socket_pipe.is_running():
            pass
        #TODO remove that debug print
        print connection

    def do_bind(self):
        pass

    def do_udp_associate(self):
        pass

    def __get_address(self):
        return self.__remote_server_host, self.__remote_server_port


class User(object):
    def __init__(self, username, password):
        self.__username = username
        self.__password = password

    def get_username(self):
        return self.__username

    def get_password(self):
        return self.__password

    def __repr__(self):
        return '<user: username=%s, password=%s>' % (self.get_username(), self.__password)


class UserManager(object):
    def __init__(self):
        self.__users = {}

    def add_user(self, user):
        self.__users[user.get_username()] = user

    def remove_user(self, username):
        if username in self.__users:
            del self.__users[username]

    def check(self, username, password):
        if username in self.__users and self.__users[username].get_password() == password:
            return True
        else:
            return False

    def get_user(self, username):
        return self.__users[username]

    def get_users(self):
        return self.__users


class Socks5RequestHandler(StreamRequestHandler):
    def __init__(self, request, client_address, server, *args, **kwargs):
        self.transport = kwargs.get('transport')
        StreamRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        session = Session(self.connection)
        logging.debug('Create session[%s] for %s:%d' % (
            1, self.client_address[0], self.client_address[1]))
        # print self.server.allowed
        if self.server.allowed and self.client_address[0] not in self.server.allowed:
            close_session(session)
            return
        client = self.connection
        client.recv(1)
        try:
            method_num, = struct.unpack('b', client.recv(1))
        except struct.error, e:
            # logging.error(e.message)
            return
        methods = struct.unpack('b' * method_num, client.recv(method_num))
        auth = self.server.is_auth()
        if methods.__contains__(SocksMethod.NO_AUTHENTICATION_REQUIRED) and not auth:
            client.send(b"\x05\x00")
        elif methods.__contains__(SocksMethod.USERNAME_PASSWORD) and auth:
            client.send(b"\x05\x02")
            if not self.__do_username_password_auth():
                logging.error('Session[%d] authentication failed' % session.get_id())
                close_session(session)
                return
        else:
            client.send(b"\x05\xFF")
            return
        try:
            version, command, reserved, address_type = struct.unpack('b' * 4, client.recv(4))
        except struct.error, e:
            return
        except IOError, e:
            return
        host = None
        port = None
        if address_type == AddressType.IPV4:
            ip_a, ip_b, ip_c, ip_d, p1, p2 = struct.unpack('b' * 6, client.recv(6))
            host = host_from_ip(ip_a, ip_b, ip_c, ip_d)
            port = port_from_byte(p1, p2)
        elif address_type == AddressType.DOMAIN_NAME:
            host_length, = struct.unpack('b', client.recv(1))
            host = client.recv(host_length)
            p1, p2 = struct.unpack('b' * 2, client.recv(2))
            port = port_from_byte(p1, p2)
        else:  # address type not support
            client.send(build_command_response(ReplyType.ADDRESS_TYPE_NOT_SUPPORTED))

        command_executor = CommandExecutor(host, port, session, transport=self.transport)
        if command == SocksCommand.CONNECT:
            logging.debug("Session[%s] Request connect %s:%s" % (session.get_id(), host, port))
            command_executor.do_connect()

        close_session(session)

    def __do_username_password_auth(self):
        client = self.connection
        client.recv(1)
        length = byte_to_int(struct.unpack('b', client.recv(1))[0])
        username = client.recv(length)
        length = byte_to_int(struct.unpack('b', client.recv(1))[0])
        password = client.recv(length)
        user_manager = self.server.get_user_manager()
        if user_manager.check(username, password):
            client.send(b"\x01\x00")
            return True
        else:
            client.send(b"\x01\x01")
            return False


class Socks5Server(ThreadingTCPServer):
    """
    SOCKS5 proxy server
    """

    def __init__(self, socks_host, socks_port, auth=False, user_manager=UserManager(), allowed=None, transport=None):
        self.transport = transport
        ThreadingTCPServer.__init__(self, (socks_host, socks_port), Socks5RequestHandler)
        self.__port = socks_port
        self.__users = {}
        self.__auth = auth
        self.__user_manager = user_manager
        self.__sessions = {}
        self.allowed = allowed

    def serve_forever(self, poll_interval=0.5):
        logging.info("Create SOCKS5 server at port %d" % self.__port)
        ThreadingTCPServer.serve_forever(self, poll_interval)

    def finish_request(self, request, client_address):
        return self.RequestHandlerClass(request, client_address, self, transport=self.transport)

    def is_auth(self):
        return self.__auth

    def set_auth(self, auth):
        self.__auth = auth

    def get_all_managed_session(self):
        return self.__sessions

    def get_bind_port(self):
        return self.__port

    def get_user_manager(self):
        return self.__user_manager

    def set_user_manager(self, user_manager):
        self.__user_manager = user_manager


def signal_handler(signal, frame):
    sys.exit(0)


class SshTransport():
    def __init__(self, ssh_host, ssh_user, ssh_password, ssh_port):
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password
        self.ssh_port = ssh_port
        self.connection = None
        self.client = None
        # self.connection = self._get_connection()
        self.errors = 0
        self.max_errors = 50

    def _get_connection(self):
        if self.connection:
            self.connection.close()
        self.connection = None
        try:
            logging.info('Connecting to %s port %d' % (self.ssh_host, self.ssh_port))
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.ssh_host, port=self.ssh_port, username=self.ssh_user,
                password=self.ssh_password, timeout=5,
            )
            self.connection = self.client.get_transport()
            if self.connection.is_authenticated():
                logging.info('Authenticated to %s ([%s]:%d).' % (self.ssh_host, self.ssh_host, self.ssh_port))
            else:
                logging.info('NOT Authenticated to %s ([%s]:%d), ignoring...' % \
                             (self.ssh_host, self.ssh_host, self.ssh_port))
            self.connection.set_keepalive(5)
        except Exception as e:
            logging.info('FATAL ERROR: %s' % e.message)
            self.errors = self.errors + 1
            return
        return self.connection

    def get_connection(self):
        if self.errors > self.max_errors:
            return
        # do not use is_authenticated!
        if self.connection is None or self.connection.is_active() is not True:
            self._get_connection()
        return self.connection


def _kill_self(pid, timeout=3):
    p = psutil.Process(pid)
    for _t in reversed(range(0, timeout)):
        logging.info("Exit in %s seconds..." % (_t + 1))
        time.sleep(1)
    p.terminate()
    sys.exit(0)


def main_worker(ssh_host, ssh_user, ssh_password, ssh_port, socks_host, socks_port):
    transport = SshTransport(
        ssh_host=ssh_host, ssh_user=ssh_user,
        ssh_password=ssh_password, ssh_port=ssh_port,
    )
    connection = transport.get_connection()
    if not connection:
        logging.error('Bad ssh connection')
        return
    # pdb.set_trace()

    Socks5Server.allow_reuse_address = True
    socks5_server = Socks5Server(
        socks_host=socks_host, socks_port=socks_port, auth=False, user_manager=UserManager(),
        allowed=None, transport=transport
    )
    pid = os.getpid()
    # socks5_server.s
    try:
        socks5_server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        proc = Process(target=_kill_self, args=(pid,))
        proc.start()
        try:
            if transport.connection:
                transport.connection.close()
        except Exception:
            pass
        try:
            socks5_server.server_close()
        except Exception:
            pass
        try:
            socks5_server.shutdown()
        except Exception:
            pass
        logging.info("SOCKS5 server shutdown")
        proc.join()


def main():
    import requests
    import argparse
    import json

    def get_ip_by_sproxy_conn(socks_host, socks_port, _timeout=10, ):
        proxy_conn = 'socks5://{host}:{port}'. \
            format(host=socks_host, port=socks_port, )
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,q=0.8',
        }
        try:
            resp = requests.get('https://lumtest.com/myip.json',
                                proxies=dict(http=proxy_conn, https=proxy_conn),
                                timeout=_timeout, headers=headers,
                                )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.ReadTimeout):
            logging.error("FAILED %s" % proxy_conn)
            return False
        if resp.status_code != 200:
            logging.error("FAILED CODE %s" % proxy_conn)
            resp.close()
            return False
        resp.close()
        try:
            data = json.loads(resp.content)
        except ValueError:
            logging.error("FAILED JSON %s" % proxy_conn)
            return False
        return data

    parser = argparse.ArgumentParser()
    parser.add_argument('-ssh', help='ssh', dest='ssh_host', required=True)
    parser.add_argument('-p', '-P', dest='ssh_port', help='port', type=int, default=22)
    parser.add_argument('-l', dest='ssh_user', help='login', required=True)
    parser.add_argument('-pw', dest='ssh_password', help='password')
    parser.add_argument('-D', dest='socks', help='dynamic SOCKS', default='127.0.0.1:7000')
    args, unknown = parser.parse_known_args(sys.argv[1:])

    socks_host, socks_port = args.socks.split(':')
    socks_host = socks_host.strip()
    socks_port = int(socks_port)
    proc = Process(
        target=main_worker,
        args=(
            args.ssh_host, args.ssh_user, args.ssh_password, args.ssh_port, socks_host, socks_port
        )
    )
    proc.start()
    # sleep before test
    time.sleep(5)
    if proc.is_alive():
        external_ip = get_ip_by_sproxy_conn(socks_host=socks_host, socks_port=socks_port)
        if not external_ip:
            logging.error('Cannot access external IP address, exiting...')
            proc.terminate()
            return
        else:
            logging.info(external_ip)
        try:
            proc.join()
        except (KeyboardInterrupt, SystemExit):
            pass


if __name__ == '__main__':
    main()
