# LDN
Python package for local wireless communication with a Nintendo Switch

This package is able to scan for nearby LDN networks, join them, and even host your own networks. To get started, check out the examples folder or documentation.

This package can be installed with `pip install ldn`.

There is also a [Discord server](https://discord.gg/x8np6Hhxwk).

### Documentation
* [The communication protocol (LDN)](https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol)
* [The classes and functions in this package](https://ldn.readthedocs.io)

### Usage Instructions
This package requires a Linux system with Python 3.12 or later. Your wireless hardware must also be able to receive and transmit action frames in monitor mode.

Because LDN operates at the data link layer, it requires low-level access to your WLAN hardware. This package requires at least `CAP_NET_ADMIN` privileges. The easiest way to get these privileges is running your scripts as root: `sudo -E python3 script.py`.

It is important that no other software interferes with your network hardware. You probably need to stop the NetworkManager service before using this package: `sudo service NetworkManager stop`. Unfortunately, this means that you cannot access the internet while using the package. To restart the NetworkManager service, run `sudo service NetworkManager start`. If you are using a wired connection, you may be able to skip this step.

### Troubleshooting
Using LDN is hard. Check out the list of [common issues](https://github.com/kinnay/LDN/wiki/Common-Issues). If your problem is still not solved, feel free to create an issue on github.

### Design Considerations
The LDN protocol is neither ad-hoc nor infrastructure, but somewhere in between. When a station joins the network, it must first authenticate and associate itself with the AP. Once authenticated, all nodes in the network can communicate directly with each other. It also seems that frames from the host have FromDS enabled, while frames from other stations in the network have neither FromDS nor ToDS enabled.

Joining a network has never been an issue, but this protocol makes it difficult to implement an AP. Initially, this package attempted to use an interface in AP mode for hosting a network. However, in AP mode, it is impossible to receive frames that are sent to the broadcast address (`ff:ff:ff:ff:ff:ff`). These are dropped by either the kernel or the driver. Using an interface in IBSS (ad-hoc) mode also did not work, because all association requests are dropped in that mode.

Currently, the package implements the access point entirely in monitor mode. Two monitor mode interfaces are created, one in active mode and one in passive mode. This may depend on the driver, but my `mt7921e` driver could not send frames in active monitor mode, while passive mode does not acknowledge incoming frames. Creating two monitor mode interfaces solved this issue. The data frames are parsed, decrypted and written to a TAP interface so that Linux becomes aware of them. This seems to work quite well.
