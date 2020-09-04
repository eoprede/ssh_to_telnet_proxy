#!/usr/bin/env python3

# This file is based on paramiko's demo_server example, which has been crudely modified to proxy telnet connections to other devices.

import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback
import logging
import _thread



import paramiko
from paramiko.py3compat import b, u, decodebytes

from telnetlib import Telnet

logger = logging.getLogger(__name__)


__version__ = "0.1.0rc1"


DoGSSAPIKeyExchange = True

LISTEN_PORT = 2200

TELNET_LOGIN_STRINGS = [
    b"Username: ", 
    b"UserName",
    b"login: ",
    b"Login: "
]

TELNET_PASSWORD_STRINGS = [ b"Password: ", b"password"]
TELNET_LOGIN_TIMEOUT = 5

# setup logging
paramiko.util.log_to_file("demo_server.log")

host_key = paramiko.RSAKey(filename="test_rsa.key")
# host_key = paramiko.DSSKey(filename='test_dss.key')

print("Read key: " + u(hexlify(host_key.get_fingerprint())))

class TelnetConnection(Telnet):
    def __init__(self, target, telnet_port, timeout=10, channel=None):
        super().__init__(target, telnet_port, timeout=10)
        self.chan = channel

    def interact(self):
        self.mt_interact()
        return
    
    def mt_interact(self):
        """Multithreaded version of interact()."""
        logger.debug("multithread")
        _thread.start_new_thread(self.listener, ())
        while 1:
            f = self.chan.makefile("rU")
            line = f.readline()
            if not line:
                break
            try:
                # GNS3 console requires "\r\n", so I am ensuring that I always send it
                line = line.rstrip(os.linesep)+"\r\n"
                self.write(line.encode('ascii'))
            except ConnectionAbortedError:
                return

    def listener(self):
        """Helper for mt_interact() -- this executes in the other thread."""
        while 1:
            try:
                data = self.read_very_eager()
            except EOFError:
                print('*** Connection closed by remote host ***')
                self.chan.close()
                return
            if data:
                self.chan.send(data.decode('ascii'))

class Server(paramiko.ServerInterface):
    # 'data' is the output of base64.b64encode(key)
    # (using the "user_rsa_key" files)
    data = (
        b"AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp"
        b"fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC"
        b"KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT"
        b"UWT10hcuO4Ks8="
    )
    good_pub_key = paramiko.RSAKey(data=decodebytes(data))

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

    def check_auth_publickey(self, username, key):
        print("Auth attempt with key: " + u(hexlify(key.get_fingerprint())))
        if (username == "robey") and (key == self.good_pub_key):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

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


def start_telnet(target, telnet_port, timeout, channel, un, passwd):
    try:
        tn = TelnetConnection(target, telnet_port, timeout=timeout, channel=channel)
        if un != "skip_login":
            tn.expect(TELNET_LOGIN_STRINGS, TELNET_LOGIN_TIMEOUT)
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
    finally:
        channel.close()

def main():


    logging.basicConfig(level="DEBUG",
                        format='%(asctime)s '
                            '%(filename)s: '    
                            '%(levelname)s: '
                            '%(funcName)s(): '
                            '%(lineno)d:\t'
                            '%(message)s')

    # now connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", LISTEN_PORT))
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
                t = paramiko.Transport(client, gss_kex=DoGSSAPIKeyExchange)
                t.set_gss_host(socket.getfqdn(""))
                try:
                    t.load_server_moduli()
                except:
                    print("(Failed to load moduli -- gex will be unsupported.)")
                    raise
                t.add_server_key(host_key)
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

                target = server.user.split("@")[-1]
                if ":" in target:
                    telnet_port = int(target.split(":")[-1])
                    target = ":".join(target.split(":")[:-1])
                else:
                    telnet_port=23
                un = "@".join(server.user.split("@")[:-1])

                logger.debug("un: <{}>; user: {}".format(un, server.user))

                print ('Connecting to {0}:{1} with {2} {3}'.format(target, str(telnet_port), un, server.passwd))

                #start_telnet(target, telnet_port, 10, chan, un, server.passwd)
                new_thread = threading.Thread(name="telnet_connection",
                                              target=start_telnet,
                                              args=(target, telnet_port, 10, chan, un, server.passwd))
                new_thread.start()
                


            except Exception as e:
                print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
                traceback.print_exc()
                try:
                    t.close()
                except:
                    pass
                sys.exit(1)

    except KeyboardInterrupt:
        print('Server closing')
        sock.close()


if __name__ == "__main__":
    main()