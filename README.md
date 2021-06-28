- [Introduction](#introduction)
- [Usage:](#usage)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Installation via `make`](#installation-via-make)
  - [Uninstall](#uninstall)
  - [Systemd service](#systemd-service)
  - [Windows](#windows)

# Introduction

This code was created to allow easy way to test automation against virtual network devices created in simulators like ViRL, CML and GNS3, where it is not always possible to allow direct SSH connection into the nodes and you have to access them via virtual console connection. Initial release would accept SSH connection and proxy them to specified telnet server. Since Cisco in CMLv2 removed easy way to access virtual device via telnet, the new functionality was added to automatically SSH into CMLv2, open console connection to specified device, get to prompt and then pass that promt and session to SSH client.


# Usage:

Basic usage of the script is shown below:
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

If using make for install, you will need to install development tools, for example on CentOS it's done via `sudo yum group install "Development Tools"`

- Ubuntu, debian
  - `libkrb5-dev`
- centos
  - `krb5-devel`
  - `python3-devel`

Following python libraries are needed:
- `paramiko`
- `python-gssapi` for Linux
- `pywin32` for Windows

You will also need to install `wheel` and `setuptools` via pip in order to be able to build the package if you decide to go that route.

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

[`ssh2telnet.service`](systemd/ssh2telnet.service) is included. It should be copied to`/etc/systemd/system` to register it as a service. 
Then you can start it with `systemctl start ssh2telnet` and make it start automatically on boot with `systemctl enable ssh2telnet`

By default it is called with key=`/root/.ssh/id_rsa` and port `2200`. Ypu will need to modify ExecStart line if you want to listen on different port, start system in CML proxy or have log file in a different location.

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

## Install as a service

There are multiple ways of installing python script as a service, but probably the easiest way is to use [NSSM](https://nssm.cc/) 

Download the tool, unpack it and then start service install
```
nssm.exe install SSHTelnetProxy
```
Then fill out the service details
```
Application path: path to your python.exe, either your system install or virtual environment/Scripts folder if you are using one
Startup directory: path to the folder where python.exe you are using is
Arguments: full path to ssh_to_telnet_proxy.py as well as all the arguments you want to use
```
No other configuration is necessary. Service is installed and can be used like any other normal Windows Service.