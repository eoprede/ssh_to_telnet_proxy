### SSH to Telnet proxy
This is an extremely rough alpha version of script that will allow you to proxy telnet connections via SSH. Could be useful if you have an old Cisco device that doesn't support SSH, but you still want to run Ansible playbooks against it or something of that sort.

WARNING!

This has been barely tested. I can use it on my windows laptop with python 3.7 to proxy connections to older 3750 for ansible ios_facts. I have not tested anything else.

### Usage

Run the scrpt, it will listen on port 2200. Initiate SSH connection, provide username in format username@system_to_proxy_to:port and password. Hopefully it works after that.