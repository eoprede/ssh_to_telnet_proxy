### SSH to Telnet proxy
This is an early version of script that will allow you to proxy telnet connections via SSH. Could be useful if you have an old Cisco device that doesn't support SSH, but you still want to run Ansible playbooks against it or something of that sort.

WARNING!

This has not been tested much. I have tested it on my Windows 10 lapton with Python 3.7 against an older 3750 switch, as well as 7200 router in GNS3. 

Note that the way sockets are implemented in Windows, there's no way to stop the script with Ctrl+C. You either have to close the window, or you have to do Ctrl+C and then send some traffic over to port 2200, which will then "unfreeze" the socket and allow keyboard interruption to work.

### Usage

Run the scrpt, it will listen on port 2200. Initiate SSH connection, provide username in format username@system_to_proxy_to:port and password. Hopefully it works after that.

For GNS3, since you logging in directly into the device without any username and password, you can login via SSH with skip_login@system_to_proxy_to:port and any password. You also should disable logging to console with "no logging console" command prior to running any automation, as it is very likely to get confused with extra console output.