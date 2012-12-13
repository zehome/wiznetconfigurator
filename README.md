WIZNet WIZ1000 / WIZ110SR / WIZ1x0SR Configurator
=================================================

This project intends to perform the configuration over the network
of WIZnet WIZ1000, WIZ110SR / WIZ1x0SR devices.

This program is compatible with Linux, *BSD, and Windows.

How it works
------------
This program implements several configurator written by WIZnet,
but modified to support as many S2E devices as possible.

I only have WIZ1000 & WIZ110SR for now, so that's what I'm supporting.

Thoses devices can communicate over the network to find them, and configure them.

 - Default broadcast address 192.168.11.255
 - Default search password: "wiznet"

Read the source for more details.

Exemples
--------

$ python main.py --help

Broadcast search on 192.168.11.255 and print config for each device found:

$ python main.py -b 192.168.11.255

Broadcast set debug_enabled on 192.168.11.255 and mac = aa:bb:cc:dd:ee:ff

$ python main.py -b 192.168.11.255 -m aa:bb:cc:dd:ee:ff --debug-enabled

Set debug_enabled only on 192.168.11.2

$ python main.py -a 192.168.11.2 --debug-enabled


Author
------
Laurent COUSTET

Licence
-------
BSD
