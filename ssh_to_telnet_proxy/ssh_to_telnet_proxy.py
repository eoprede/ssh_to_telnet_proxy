#!/usr/bin/env python3

# This file is based on paramiko's demo_server example, which has been crudely modified to proxy telnet connections to other devices.

import os
import socket
import sys
import threading
import traceback
import logging
import _thread
import argparse
import signal
import re

import paramiko
from paramiko.py3compat import b, u, decodebytes

from telnetlib import Telnet
import time

logger = logging.getLogger(__name__)


__version__ = "0.2"
__license__ = "MIT"

DoGSSAPIKeyExchange = True

LISTEN_PORT = 2200

BUF_LEN = 16384

TELNET_LOGIN_STRINGS = [
    b"Username: ",
    b"UserName: ",
    b"login: ",
    b"Login: ",
    b" name:",
    b" any key",
]

TELNET_PASSWORD_STRINGS = [b"Password: ", b"password"]
TELNET_LOGIN_TIMEOUT = 5
SSH_KEY = "test_rsa.key"
LOGFILE = "ssh_to_telnet_proxy.log"

# TELNET TERMINAL ESCAPE CHARACTERS
TELNET_ESCAPE_REGEXP = r"(\x1b\[\d+;\d+\S|\x1b\[\?\d+\S|\x1b\[\d+\S|\x1bE)+"
# REGEX to capture all characters between move cursor to first column ansi escape codes http://ascii-table.com/ansi-escape-sequences.php
TELNET_ESCAPE_NEWLINES = (
    r"\x1b\[24;1H(\x1b\[\d+;\d+\S|\x1b\[\?\d+\S|\x1b\[\d+\S|\x1bE)*\x1b\[24;1H"
)
# Move cursor to first column ascii code
TELNET_BEGIN_LINE_EXP = r"\x1b\[24;1H"


class TelnetConnection(Telnet):
    """
    This is a modified Telnet class from telnet lib, designed to pass telnet connection data to paramiko SSH channel
    Attributes
    ----------
    target : str
        Remote system to telnet to
    telnet_port : int
        Telnet port
    timeout : int
        Connection timeout
    channel : paramiko.Channel()
        SSH channel to forward data to
    """

    def __init__(self, target, telnet_port, timeout=10, channel=None):
        super().__init__(target, telnet_port, timeout=10)
        self.chan = channel

    def interact(self):
        """
        Multithreaded interact does everything this function does, but better
        """
        self.mt_interact()

    def mt_interact(self):
        """
        Originally this method would initiate terminal-like connection.
        After modifications, this method forwards traffic between SSH and Telnet connections
        """
        logger.debug("multithread")
        _thread.start_new_thread(self.listener, ())
        """
        It uses _thread as it was written initially to be python 2 and 3 compatible,
        now that this code is purely python 3 it should be probably changed to threading library
        """
        while 1:
            f = self.chan.makefile("rU")
            line = f.readline()
            logger.debug(line)
            if not line:
                logger.debug("not line")
                break
            try:
                # GNS3 console requires "\r\n", so I am ensuring that I always send it
                line = line.rstrip(os.linesep) + "\r\n"
                self.write(line.encode("ascii"))
            except ConnectionAbortedError:
                return

    def decode_lines(self, data):
        """
        Helper function to decode byte data into strings and split lines

        Parameters
        ----------
        data : bytes
            Bytes received from ssh/telnet connection to be decoded

        Returns
        -------
        lines : list
            List of decoded strings separated by new lines
        """
        logger.debug(data)
        lines = []
        # First try to decode as ascii
        try:
            lines = data.decode("ascii").splitlines(True)
        except UnicodeDecodeError as e:
            # IF ascii fails try to decode as utf-8
            logger.debug("Error decoding as ascii: {}".format(e))
            try:
                lines = data.decode("utf-8").splitlines(True)
            # last option: try to decode as cp1252
            except UnicodeDecodeError as e:
                logger.debug("error decoding as unicode")
                lines = data.decode("cp1252").splitlines(True)
        return lines

    def listener(self):
        """Helper for mt_interact() -- this executes in the other thread."""
        while 1:
            try:
                data = self.read_very_eager()
            except EOFError:
                print("*** Connection closed by remote host ***")
                try:
                    self.chan.close()
                except EOFError:
                    return
                return
            if data:
                # try to decode data as ascii, utf-8 or cp1252
                lines = self.decode_lines(data)
                for index, line in enumerate(lines):
                    logger.debug("[{:03d}][BEFORE]: {}".format(index, repr(line)))
                    # substitude first ocurrence of all codes between two move cursor to first column ansi code with \n
                    new_line = re.sub(TELNET_ESCAPE_NEWLINES, "\n", line, count=1)
                    # remove all ansi codes and carriage returns
                    new_line = re.sub(TELNET_ESCAPE_REGEXP, "", new_line).replace(
                        "\r", ""
                    )
                    logger.debug("[{:03d}][ AFTER]: {}".format(index, repr(new_line)))
                    self.chan.send(new_line)


class Server(paramiko.ServerInterface):
    """
    Paramiko server interface. Taken straight from the demo_server.py from Paramiko repository
    """

    def __init__(self):
        self.event = threading.Event()
        self.user = ""
        self.passwd = ""

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """
        Server will accept any credentials and will store them to decode later
        """

        self.user = username
        self.passwd = password
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_gssapi_with_mic(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        """
        .. note::
            We are just checking in `AuthHandler` that the given user is a
            valid krb5 principal! We don't check if the krb5 principal is
            allowed to log in on the server, because there is no way to do that
            in python. So if you develop your own SSH server with paramiko for
            a certain platform like Linux, you should call ``krb5_kuserok()`` in
            your local kerberos library to make sure that the krb5_principal
            has an account on the server and is allowed to log in as a user.

        .. seealso::
            `krb5_kuserok() man page
            <http://www.unix.com/man-page/all/3/krb5_kuserok/>`_
        """
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return True

    def get_allowed_auths(self, username):
        return "gssapi-keyex,gssapi-with-mic,password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


# Pending of making a FSM to control login
def start_telnet(target, telnet_port, timeout, channel, un, passwd):
    """
    Creates telnet session to specified device and proxies it to ssh server channel

    Attributes
    ----------
    target : str
        IP or FQDN of system to connect to
    telnet_port : int
        Port for telnet connection
    timeout : int
        Timeout for telnet connection
    channel : paramiko.Channel()
        Server channel to proxy data to and from
    un : str
        Username for telnet connection
    passwd : str
        Password for telnet connection
    """
    logger.debug("Entering function")
    try:
        tn = TelnetConnection(target, telnet_port, timeout=timeout, channel=channel)
        if un != "skip_login":
            case = tn.expect(TELNET_LOGIN_STRINGS, TELNET_LOGIN_TIMEOUT)
            logger.debug(case)
            if case[0] == 5:
                tn.write("\n".encode("ascii"))
                case = tn.expect(TELNET_LOGIN_STRINGS, TELNET_LOGIN_TIMEOUT)
            tn.write((un + "\r\n").encode("ascii"))
            tn.expect(TELNET_PASSWORD_STRINGS, TELNET_LOGIN_TIMEOUT)
            tn.write((passwd + "\r\n").encode("ascii"))
        tn.interact()
        tn.close()
    except ConnectionRefusedError:
        print("Connection refused by {0}:{1}".format(target, str(telnet_port)))
        channel.close()
    except OSError:
        print("Error in the connection to {0}:{1}".format(target, str(telnet_port)))
        channel.close()
    except EOFError:
        print("Session terminated to {0}:{1}".format(target, str(telnet_port)))


def start_cml_ssh(target, server_channel, un, passwd, port=22, device_str=""):
    """
    Creates ssh session to specified CML server, opens connection to virtual device if specified
    and proxies this connection to the SSH client

    Attributes
    ----------
    target : str
        IP or FQDN of CML system to connect to
    server_channel : paramiko.Channel()
        Server channel to proxy data to and from
    un : str
        Username for CML connection
    pw : str
        Password for CML connection
    port : int
        Port for CML connection
    device_str : int
        Virual device to open connection to, i.e. /lab_1/n0/0

    """
    proxy_client = paramiko.SSHClient()
    proxy_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    logger.debug("Connecting to {0}:{1} with un {2}".format(target, port, un))
    try:
        proxy_client.connect(
            target, port=port, username=un, password=passwd, look_for_keys=False
        )
    except paramiko.ssh_exception.AuthenticationException:
        logger.debug("Failed to connect to {} - Authentication Error".format(target))
        server_channel.sendall(
            "Failed to connect to {} - Authentication Error\r\n".format(target)
        )
        server_channel.close()
        return
    transport = proxy_client.get_transport()
    client_channel = transport.open_session()
    client_channel.get_pty()
    client_channel.invoke_shell()
    if device_str:
        """
        If device_str is passed, I need to open terminal connection to the specified virtual device
        Then I need to ensure I get to devoce promtp (i.e. Router> or Router#) and pass it along,
        otherwise automation tools like Ansible fail.
        This function blindly sends 2 carriage returns in hopes of getting to the prompt and it has been reliably working for me in my lab
        If it fails, some while loop with looking for prompt with > or # that is not console> may be required
        """
        client_channel.send(" open {}\n".format(device_str))
        logger.debug("Connecting to device {}".format(device_str))
        time.sleep(1)
        if client_channel.recv_ready():
            line = decode_bytes(client_channel.recv(BUF_LEN))
            if "not found!" in line:
                server_channel.sendall(
                    "Could not connect to device {}\r\n".format(device_str)
                )
                logger.debug("Could not connect to device {}\r\n".format(device_str))
                server_channel.close()
                client_channel.close()
                return
        client_channel.send("\r\n".format(device_str))
        time.sleep(1)
        if client_channel.recv_ready():
            line = decode_bytes(client_channel.recv(BUF_LEN))
        client_channel.send("\r\n".format(device_str))

    while True:
        if server_channel.recv_ready():
            buf = decode_bytes(server_channel.recv(BUF_LEN))
            client_channel.send(buf)
        if server_channel.recv_stderr_ready():
            buf = decode_bytes(server_channel.recv_stderr(BUF_LEN))
            client_channel.send_stderr(buf)
        if client_channel.recv_ready():
            line = decode_bytes(client_channel.recv(BUF_LEN))
            server_channel.send(line)

        if (
            server_channel.closed
            or server_channel.eof_received
            or server_channel.eof_sent
            or not server_channel.active
        ):
            client_channel.close()
            break
        if (
            client_channel.closed
            or client_channel.eof_received
            or client_channel.eof_sent
            or not client_channel.active
        ):
            server_channel.close()
            break


def decode_bytes(data):
    """
    Helper function to decode bytes into string, I think it ends up being called per character
    """
    lines = ""
    try:
        lines = data.decode("ascii")
    except UnicodeDecodeError as e:
        try:
            lines = data.decode("utf-8")
        # last option: try to decode as cp1252
        except UnicodeDecodeError as e:
            lines = data.decode("cp1252")
    return lines


def start_ssh_session_thread(client=None, host_key=None, cml=None):
    """
    New thread for the SSH session. Will spawn telnet or ssh client to proxy connection to
    """
    logger.debug("Enter function")
    try:
        t = paramiko.Transport(client, gss_kex=DoGSSAPIKeyExchange)
        logger.debug("set gss host")
        #        t.set_gss_host(socket.gethostname())
        logger.debug("load server moduli")
        try:
            t.load_server_moduli()
        except:
            print("(Failed to load moduli -- gex will be unsupported.)")
            raise
        logger.debug("add server key")
        t.add_server_key(host_key)
        logger.debug("start server")
        server = Server()
        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            print("*** SSH negotiation failed.")
            sys.exit(1)
        # wait for auth
        chan = t.accept(20)
        if chan is None:
            print("*** No channel.")
            sys.exit(1)
        print("Authenticated!")
        server.event.wait(10)
        if not server.event.is_set():
            print("*** Client never asked for a shell.")
            sys.exit(1)
        logger.debug("Obtain user and password")
        target = server.user.split("@")[-1]
        if ":" in target:
            telnet_port = int(target.split(":")[-1])
            target = ":".join(target.split(":")[:-1])
        else:
            telnet_port = 23
        un = "@".join(server.user.split("@")[:-1])
        logger.debug("un: <{}>; user: {}".format(un, server.user))
        if cml:
            if ":" in cml:
                ssh_port = int(cml.split(":")[-1])
                cml = ":".join(cml.split(":")[:-1])
            else:
                ssh_port = 22
            # to handle case when no device string is provided
            if not un:
                un = target
                target = ""
            print("Connecting to {0}:{1} with user {2}".format(cml, str(ssh_port), un))
            start_cml_ssh(
                cml, chan, un, server.passwd, port=ssh_port, device_str=target
            )
        else:
            print(
                "Connecting to {0}:{1} with user {2}".format(
                    target, str(telnet_port), un
                )
            )
            start_telnet(target, telnet_port, 10, chan, un, server.passwd)
    except Exception as e:
        logger.error("*** Caught exception: " + str(e.__class__) + ": " + str(e))
        traceback.print_exc()
        try:
            t.close()
        except:
            pass
        sys.exit(1)


def load_arguments():
    """Function used to process command line arguments

    Returns:
        [dict] -- dictionary with arguments parsed
    """
    # Define parser
    parser = argparse.ArgumentParser(
        description="Proxy that translates SSH into telnet sessions"
    )
    parser.add_argument(
        "-l",
        "--log",
        type=str,
        dest="loglevel",
        default="info",
        choices=["error", "debug", "info", "critical", "warning"],
        help="Set the log level DEBUG,INFO,... (default = info)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        dest="port",
        default=LISTEN_PORT,
        required=False,
        help="Port that will be used to setup ssh server. By default is port {port}".format(
            port=LISTEN_PORT
        ),
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        required=False,
        action="store_true",
        default=False,
        help="Print version",
    )
    parser.add_argument(
        "-k",
        "--key",
        dest="key",
        required=False,
        type=str,
        default=SSH_KEY,
        help="ssh private key that will be used by the server",
    )
    parser.add_argument(
        "-f",
        "--logfile",
        dest="logfile",
        required=False,
        type=str,
        default=LOGFILE,
        help="paramiko logfile",
    )
    parser.add_argument(
        "--cml", dest="cml", required=False, type=str, help="Proxy to given CML2 server"
    )

    # Parse arguments
    args = parser.parse_args()

    # return arguments parsed
    return args


def signal_handler(sig, frame):
    logger.debug("Exiting {}".format(__file__))
    sys.exit(0)


def main():
    # exit script upon CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    # process script arguments
    args = load_arguments()
    # display version and exit
    if args.version:
        print("ssh_to_telnet_proxy" + " : " + __version__)
        sys.exit(0)

    # set logging basic configuration
    logging.basicConfig(
        level=args.loglevel.upper(),
        format="%(asctime)s "
        "%(filename)s: "
        "%(levelname)s: "
        "%(funcName)s(): "
        "%(lineno)d:\t"
        "%(message)s",
    )

    # setup paramiko local logging
    paramiko.util.log_to_file(args.logfile)
    # Define server key
    host_key = paramiko.RSAKey(filename=args.key)

    # now connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", args.port))
    except Exception as e:
        print("*** Bind failed: " + str(e))
        traceback.print_exc()
        sys.exit(1)

    try:
        while True:
            client = None
            try:
                sock.listen(100)
                print("Listening for connection ...")
                client, addr = sock.accept()
            except Exception as e:
                print("*** Listen/accept failed: " + str(e))
                traceback.print_exc()
                sys.exit(1)

            print("Got a connection!")

            try:
                new_thread = threading.Thread(
                    name="ssh_session",
                    target=start_ssh_session_thread,
                    kwargs={"client": client, "host_key": host_key, "cml": args.cml},
                )
                new_thread.start()
            except Exception as e:
                logger.error(
                    "*** Caught exception: " + str(e.__class__) + ": " + str(e)
                )
                traceback.print_exc()
                sys.exit(1)

    except KeyboardInterrupt:
        print("Server closing")
        sock.close()


if __name__ == "__main__":
    main()
