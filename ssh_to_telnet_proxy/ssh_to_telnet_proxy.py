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

logger = logging.getLogger(__name__)


__version__ = "0.1.4rc2"
__license__ = "MIT"

DoGSSAPIKeyExchange = True

LISTEN_PORT = 2200

TELNET_LOGIN_STRINGS = [
    b"Username: ", 
    b"UserName: ",
    b"login: ",
    b"Login: ",
    b" name:",
    b" any key"
]

TELNET_PASSWORD_STRINGS = [ b"Password: ", b"password"]
TELNET_LOGIN_TIMEOUT = 5
SSH_KEY = "test_rsa.key"
LOGFILE = "ssh_to_telnet_proxy.log"

# TELNET TERMINAL ESCAPE CHARACTERS
TELNET_ESCAPE_REGEXP = r'(\x1b\[\d+;\d+\S|\x1b\[\?\d+\S|\x1b\[\d+\S|\x1bE)+'
# REGEX to capture all characters between move cursor to first column ansi escape codes http://ascii-table.com/ansi-escape-sequences.php
TELNET_ESCAPE_NEWLINES = r'\x1b\[24;1H(\x1b\[\d+;\d+\S|\x1b\[\?\d+\S|\x1b\[\d+\S|\x1bE)*\x1b\[24;1H'
# Move cursor to first column ascii code
TELNET_BEGIN_LINE_EXP = r'\x1b\[24;1H'


class TelnetConnection(Telnet):
    def __init__(self, target, telnet_port, timeout=10, channel=None):
        super().__init__(target, telnet_port, timeout=10)
        self.chan = channel

    def interact(self):
        self.mt_interact()
    
    def mt_interact(self):
        """Multithreaded version of interact()."""
        logger.debug("multithread")
        _thread.start_new_thread(self.listener, ())
        while 1:
            f = self.chan.makefile("rU")
            line = f.readline()
            logger.debug(line)
            if not line:
                logger.debug("not line")
                break
            try:
                # GNS3 console requires "\r\n", so I am ensuring that I always send it
                line = line.rstrip(os.linesep)+"\r\n"
                self.write(line.encode('ascii'))
            except ConnectionAbortedError:
                return

    def decode_lines(self, data):

        logger.debug(data)
        lines = []
        # First try to decode as ascii
        try:
            lines = data.decode('ascii').splitlines(True)
        except UnicodeDecodeError as e:
            # IF ascii fails try to decode as utf-8
            logger.debug("Error decoding as ascii: {}".format(e))
            try:
                lines = data.decode('utf-8').splitlines(True)
            # last option: try to decode as cp1252
            except UnicodeDecodeError as e:
                logger.debug("error decoding as unicode")
                lines = data.decode('cp1252').splitlines(True)
        return lines


    def listener(self):
        """Helper for mt_interact() -- this executes in the other thread."""
        while 1:
            try:
                data = self.read_very_eager()
            except EOFError:
                print('*** Connection closed by remote host ***')
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
                    new_line = re.sub(TELNET_ESCAPE_NEWLINES, '\n', line, count=1)
                    # remove all ansi codes and carriage returns
                    new_line = re.sub(TELNET_ESCAPE_REGEXP, '', new_line).replace('\r', '')
                    logger.debug("[{:03d}][ AFTER]: {}".format(index, repr(new_line)))
                    self.chan.send(new_line)

class Server(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()
        self.user = ''
        self.passwd = ''

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        #if (username == "robey") and (password == "foo"):
            #return paramiko.AUTH_SUCCESSFUL

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
    logger.debug("Entering function")
    try:
        tn = TelnetConnection(target, telnet_port, timeout=timeout, channel=channel)
        if un != "skip_login":
            case = tn.expect(TELNET_LOGIN_STRINGS, TELNET_LOGIN_TIMEOUT)
            logger.debug(case)
            if case[0] == 5:
                tn.write("\n".encode('ascii'))
                case = tn.expect(TELNET_LOGIN_STRINGS, TELNET_LOGIN_TIMEOUT)
            tn.write((un + "\r\n").encode('ascii'))
            tn.expect(TELNET_PASSWORD_STRINGS, TELNET_LOGIN_TIMEOUT)
            tn.write((passwd + "\r\n").encode('ascii'))      
        tn.interact()
        tn.close()
    except ConnectionRefusedError:
        print("Connection refused by {0}:{1}".format(target,str(telnet_port)))
        channel.close()
    except OSError:
        print("Error in the connection to {0}:{1}".format(target,str(telnet_port)))
        channel.close()
    except EOFError:
        print("Session terminated to {0}:{1}".format(target,str(telnet_port)))



def start_ssh_session_thread(client=None, host_key=None):
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
            telnet_port=23
        un = "@".join(server.user.split("@")[:-1])
        logger.debug("un: <{}>; user: {}".format(un, server.user))
        print ('Connecting to {0}:{1} with user {2}'.format(target, str(telnet_port), un))
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
    """ Function used to process command line arguments
    
    Returns:
        [dict] -- dictionary with arguments parsed
    """    
      # Define parser
    parser = argparse.ArgumentParser(
        description="Proxy that translates SSH into telnet sessions")
    parser.add_argument('-l', '--log', type=str, dest='loglevel', default='info', choices=['error', 'debug', 'info', 'critical', 'warning'],
                        help="Set the log level DEBUG,INFO,... (default = info)")
    parser.add_argument('-p', '--port', type=int, dest='port', default=LISTEN_PORT, required=False,
                        help="Port that will be used to setup ssh server. By default is port {port}".format(port=LISTEN_PORT))
    parser.add_argument('-v', '--version', dest='version', required=False, action='store_true', default=False,
                        help="Print version")
    parser.add_argument('-k', '--key', dest='key', required=False, type=str, default=SSH_KEY,
                        help="ssh private key that will be used by the server")
    parser.add_argument('-f', '--logfile', dest='logfile', required=False, type=str, default=LOGFILE,
                        help="paramiko logfile")


    # Parse arguments
    args = parser.parse_args()
    
    # return arguments parsed
    return args

def signal_handler(sig, frame):
    logger.debug('Exiting {}'.format(__file__))
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
    logging.basicConfig(level=args.loglevel.upper(),
                        format='%(asctime)s '
                            '%(filename)s: '    
                            '%(levelname)s: '
                            '%(funcName)s(): '
                            '%(lineno)d:\t'
                            '%(message)s')

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
                new_thread = threading.Thread(name="ssh_session",
                                              target=start_ssh_session_thread,
                                              kwargs={"client": client, "host_key": host_key})
                new_thread.start()
            except Exception as e:
                logger.error("*** Caught exception: " + str(e.__class__) + ": " + str(e))
                traceback.print_exc()
                sys.exit(1)

    except KeyboardInterrupt:
        print('Server closing')
        sock.close()



if __name__ == "__main__":
    main()
