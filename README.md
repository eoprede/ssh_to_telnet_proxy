- [Introduction](#introduction)
- [Usage:](#usage)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Installation via `make`](#installation-via-make)
- [Uninstall](#uninstall)
- [Systemd service](#systemd-service)
- [Pending](#pending)

# Introduction

This repo is a fork of [ssh_to_telnet_proxy](https://github.com/eoprede/ssh_to_telnet_proxy). It has been modified to allow multiple simultaneous sessions and allow command line arguments.


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
```

Where:
- `-p`: tcp port where server will listen for ssh sessions. By default it uses port 2200.
- `-v`: displays script version.
- `-k`: RSA private key that will be used to start the server. It can be generated via `ssh-keygen`. By default will use local `test_rsa.key`.
- `-f`: name of paramiko log file. By default `ssh_to_telnet_proxy.log` file will be used.
- `-l`: indicates debug level. Default value is info.


Once started the script will listen on the specified port.

Initiate SSH connection, provide username in format username@system_to_proxy_to[:port]. If port is not specified it will use standard telnet port (23).

Skipping username authentication and password is posible by using username `skip_login`: skip_login@system_to_proxy_to[:port].

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




# Pending

- [ ] Define tests
- [ ] Test windows compatibiity
