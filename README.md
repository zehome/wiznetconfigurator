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

```
$ python main.py --help
Usage: main.py [options]

Options:
  -h, --help            show this help message and exit
  -b BROADCAST_ADDRESS  Broadcast address
  -a ADDRESS            Device IP address
  --device-type=DEVICE_TYPE
  [...]
```

Broadcast search on 192.168.11.255 and print config for each device found:

```
$ python main.py -b 192.168.11.255
Config for 192.168.11.2 XX:XX:XX:XX:XX:XX WIZ1000 v1.4
    mac='00:08:XX:XX:XX:XX'
    operation_mode='server'
    ip='192.168.11.2'
    netmask='255.255.255.0'
    gateway='192.168.11.1'
    port='5000'
    remote_ip='192.168.11.3'
    remote_port='5000'
    baudrate='115200'
    databit='8'
    parity='none'
    stop_bit='1'
    flow='none'
    packing_byte='0'
    packing_length='0'
    packing_interval='0'
    tcp_timeout='0'
    debug_enabled='False'
    firmware_version='1.4'
    ip_config_mode='static'
    ip_protocol='tcp'
    connected='False'
    remote_use_dns='False'
    dns_server='0.0.0.0'
    remote_host_dns='                                '
    serial_trigger_status='False'
    serial_trigger_command='0x2b 0x2b 0x2b '
    pppoe_login='                                '
    pppoe_password='                                '
    wiznet_password_enabled='False'
    wiznet_password='        '
    rfc2217_port='23'
    rfc2217_password='wiznet  '
    search_password='wiznet  '
    keepalive_interval='20'
    remote_ip_udp='192.168.11.3'
```

Broadcast set debug_enabled on 192.168.11.255 and mac = aa:bb:cc:dd:ee:ff

```
$ python main.py -b 192.168.11.255 -m aa:bb:cc:dd:ee:ff --debug-enabled
```

Set debug_enabled only on 192.168.11.2

```
$ python main.py -a 192.168.11.2 --debug-enabled
```

Author
------
Laurent COUSTET

Licence
-------
BSD
