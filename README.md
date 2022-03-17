# LDN
Python package for local wireless communication with a Nintendo Switch

Currently, this package is able to scan for nearby LDN networks, but it is not yet possible to join or create them. Eventually, this package is supposed to implement the LDN protocol completely.

This package can be installed with `pip install ldn`.

### Documentation
* [The communication protocol (LDN)](https://github.com/Kinnay/NintendoClients/wiki/LDN-Protocol)
* [The classes and functions in this package](https://ldn.readthedocs.io)

### Usage Instructions
This package requires a Linux system with Python 3.8 or later. Your wireless hardware must also be able to receive and transmit action frames in monitor mode.

Because LDN operates at the data link layer, it requires low-level access to your WLAN hardware. This package requires at least `CAP_NET_ADMIN` privileges. The easiest way to get these privileges is running your scripts as root: `sudo -E python3 script.py`.

It is important that no other software interferes with your network hardware. You probably need to stop the network-manager service before using this package: `sudo service network-manager stop`. Unfortunately, this means that you cannot access the internet while using the package. To restart the network-manager service, run `sudo service network-manager start`. If you are using a wired connection, you may be able to skip this step.
