- [Introduction](#introduction)
- [Usage:](#usage)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Installation via `make`](#installation-via-make)
  - [Uninstall](#uninstall)
  - [Systemd service](#systemd-service)
  - [Windows](#windows)
- [Pending](#pending)

# Introduction

This code was created to allow easy way to test automation against virtual network devices created in simulators like ViRL, CML and GNS3. Initial release would accept SSH connection and proxy them to specified telnet server. Since Cisco in CMLv2 removed easy way to access virtual device via telnet, the new functionality was added to automatically SSH into CMLv2, open console connection to specified device, get to prompt and then pass that promt and session to SSH client.


# Usage:

Basi usage of the script is shown below:
```
usage: ssh_to_telnet_proxy [-h] [-l {error,debug,info,critical,warning}]
                           [-p PORT] [-v] [-k KEY] [-f LOGFILE]

Proxy that translates SSH into telnet sessions

optional arguments:
  -h, --help            show this help message and exit
  -l {error,debug,info,critical,warning}, --log {error,debug,info,critical,warning}
                        Set the log level DEBUG,INFO,... (default = info)
  -p PORT, --port PORT  Port that will be used to setup ssh server. By default
                        is port 2200
  -v, --version         Print version
  -k KEY, --key KEY     ssh private key that will be used by the server
  -f LOGFILE, --logfile LOGFILE
                        paramiko logfile
  --cml                 proxy to specified CML server
```

Where:
- `-p`: tcp port where server will listen for ssh sessions. By default it uses port 2200.
- `-v`: displays script version.
- `-k`: RSA private key that will be used to start the server. It can be generated via `ssh-keygen`. By default will use local `test_rsa.key`.
- `-f`: name of paramiko log file. By default `ssh_to_telnet_proxy.log` file will be used.
- `-l`: indicates debug level. Default value is info.
- `cml`: instead of telnet proxy, proxy all the inbound connections to specified CML host


Once started the script will listen on the specified port.

Initiate SSH connection, provide username in format username@system_to_proxy_to[:port]. If port is not specified it will use standard telnet port (23)

Skipping username authentication and password is posible by using username `skip_login`: skip_login@system_to_proxy_to[:port]

If used in CML mode, cml server needs to be specified in format cml_server[:port] (i.e. cmlv2.domain.local:22) and username should contain system to proxy to in format user@/lab_name/device/console (i.e. eoprede@/lab_1/n0/0)

# Installation

## Requirements

kerberos developer libraries are needed to install `gssapi` python library.

- Ubuntu, debian
  - `libkrb5-dev`
- centos
  - `krb5-devel`

Following python libraries are needed:
- `paramiko`
- `gssapi`

It is recommended to force upgrade of paramiko library to use `gssapi` library.

## Installation via `make`

Firt build the package:

```
make build
```

Then install it:
```
sudo make install
```


# Uninstall

Use `make` to uninstall it

```
sudo make uninstall
```

# Systemd service

[`ssh2telnet.service`](systemd/ssh2telnet.service) is included. It will be automatically installed to
`/etc/systemd/system` so the proxy starts at boot. If service is killed it will be restarted as well.

It is called with key=`/root/.ssh/id_rsa` and default port `2200`.

``` ini
[Unit]
Description=SSH to Telnet service to access secure some telnet devices.

After=network-online.target
Wants=network-online.target

[Service]
Type=simple

ExecStart=/usr/local/bin/ssh_to_telnet_proxy -k /root/.ssh/id_rsa -p 2200

Restart=on-failure
RestartSec=10s
StartLimitInterval=300
StartLimitBurst=0

[Install]
WantedBy=multi-user.target
```

# Windows

This code is fully functional in Windows as well, however it has some kinks due to some windows-specific library implementations. Most annoying issue is that when listening to socket connection, windows will not process any keyboard interrupts. So if you started your server and wanted to quit it, you'd have to issue Ctrl-C in your script window, then try to SSH to its port and only then it would close.

