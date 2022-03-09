
## Welcome to LDN
This package implements [LDN](https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol), which is the local wireless protocol used by the Nintendo Switch.

* [Overview](#overview)
* [Contributing](#contributing)
* [API Reference](#api-reference)

## Overview
LDN uses hidden wireless networks and custom action frames to connect nearby Switch consoles. Because LDN operates at the data link layer, emulating it requires low-level access to your WLAN hardware. This package only supports Linux systems.

* [Documentation about LDN](https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol)
* [Source code of this package](https://github.com/kinnay/LDN)

It is important that no other software interferes with your network hardware. You probably need to stop the network-manager service before using this package.

## Contributing
Feel free to open a pull request or issue on [github](https://github.com/kinnay/LDN). Please try to follow the current code style as much as possible.

## API Reference
* [ldn](reference/ldn.md)
