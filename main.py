#!/usr/bin/env python

"""
Configuration system for wiz1000 serial to ethernet converters.
(c) 2012 Laurent COUSTET <ed hum zehome.com>
LICENCE: BSD
"""

import time
import struct
import socket
import select
import logging
from optparse import OptionParser

logger = logging.getLogger("wiz1000")

WIZNET_OPERATION_MODES = {0x00: "client", 0x01: "server", 0x02: "mixed"}
WIZNET_PARITY = {0x00: "none", 0x01: "odd", 0x02: "even"}
WIZNET_FLOWCONTROL = {0x00: "none", 0x01: "xon/xoff", 0x02: "ctr/rts"}
WIZNET_IPCONFIGMODE = {0x00: "static", 0x01: "dhcp", 0x02: "pppoe"}
WIZNET_PROTOCOL = {0x00: "tcp", 0x01: "udp"}
WIZNET_BAUDRATES = {
    0xA0: 1200, 0xF4: 9600,  0xFE: 57600,
    0xD0: 2400, 0xFA: 19200, 0xFF: 115200,
    0xE8: 4800, 0xFD: 38400, 0xBB: 230400,
}


def hexdump(msg):
    return ' '.join(["%02x" % (ord(c),) for c in msg])


class S2E(object):
    """Represents a wiznet device"""
    _type = "Unknown"
    _basic_fields = [
        ("mac",                     "mac"),
        ("operation_mode",          "dictvalues", WIZNET_OPERATION_MODES),
        ("ip",                      "ip"),
        ("netmask",                 "ip"),
        ("gateway",                 "ip"),
        ("port",                    "short"),
        ("remote_ip",               "ip"),
        ("remote_port",             "short"),
        ("baudrate",                "dictvalues", WIZNET_BAUDRATES),
        ("databit",                 "byte"),
        ("parity",                  "dictvalues", WIZNET_PARITY),
        ("stop_bit",                "byte"),
        ("flow",                    "dictvalues", WIZNET_FLOWCONTROL),
        ("packing_byte",            "byte"),
        ("packing_length",          "short"),
        ("packing_interval",        "short"),
        ("tcp_timeout",             "short"),
        ("debug_enabled",           "bool", True),
        ("firmware_version",        "firmversion"),
        ("ip_config_mode",          "dictvalues", WIZNET_IPCONFIGMODE),
        ("ip_protocol",             "dictvalues", WIZNET_PROTOCOL),
        ("connected",               "bool", False),
        ("remote_use_dns",          "bool", False),
        ("dns_server",              "ip"),
        ("remote_host_dns",         "str", 32),
        ("serial_trigger_status",   "bool", False),
        ("serial_trigger_command",  "bytes", 3),
        ("pppoe_login",             "str", 32),
        ("pppoe_password",          "str", 32),
        ("wiznet_password_enabled", "bool", False),
        ("wiznet_password",         "str", 8, "%-8s"),
    ]
    _extended_fields = []
    UDP_LOCAL_PORT = None
    UDP_REMOTE_PORT = None

    def __init__(self, data=None):
        self._fields = self._basic_fields + self._extended_fields
        for field in self._fields:
            setattr(self, field[0], None)
        self.type = self._type
        self.data = data
        if self.data is not None:
            # Try to unpack
            self.unpack()

    def unpack(self):
        if self.data is not None:
            unpacker = Unpacker(self.data, pos=0)
            unpacker.unpack(self)

    def pack(self):
        packer = Packer()
        return packer.pack(self)

    def set_option(self, attr, value):
        if attr not in [f[0] for f in self._fields]:
            raise AttributeError("No such attribute '%s'" % (attr,))
        setattr(self, attr, value)

    def print_config(self):
        print "Config for %s" % (self,)
        for field in self._fields:
            print "\t%s='%s'" % (field[0], getattr(self, field[0], None))

    def __unicode__(self):
        return u"%(ip)s %(mac)s %(type)s v%(firmware_version)s" % self.__dict__

    def __str__(self):
        return self.__unicode__()

    def __repr__(self):
        return self.__unicode__()


class WIZ1x0SR(S2E):
    _type = "WIZ1x0SR"
    _extended_fields = []
    UDP_LOCAL_PORT = 5001
    UDP_REMOTE_PORT = 1460


class WIZ1000(S2E):
    _type = "WIZ1000"
    _extended_fields = [
        ("rfc2217_port",        "short"),
        ("rfc2217_password",    "str", 8, "%-8s"),
        ("search_password",     "str", 8, "%-8s"),
        ("keepalive_interval",  "short"),
        ("remote_ip_udp",       "ip"),
    ]
    UDP_LOCAL_PORT = 1138
    UDP_REMOTE_PORT = 5003


class Unpacker(object):
    """Helper class to unpack data received from WIZNet device"""
    def __init__(self, data, pos=0):
        self.data = data
        self.initialpos = self.pos = pos
    
    def unpack(self, s2e):
        self.pos = self.initialpos
        for field in s2e._fields:
            name = field[0]
            unpacker = getattr(self, "unpack_%s" % (field[1]), )
            unpacked = unpacker(*field[2:])
            logger.debug("Unpacked %s = %s" % (name, unpacked))
            setattr(s2e, name, unpacked)
        return s2e

    def unpack_ip(self):
        ip = struct.unpack(">BBBB", self.data[self.pos:self.pos + 4])
        self.pos += 4
        return ".".join(["%d" for x in xrange(4)]) % ip

    def unpack_firmversion(self):
        version = struct.unpack(">BB", self.data[self.pos:self.pos + 2])
        self.pos += 2
        return ".".join([ "%d" for x in xrange(2)]) % version

    def unpack_mac(self):
        mac = struct.unpack(">BBBBBB", self.data[self.pos:self.pos + 6])
        self.pos += 6
        return ":".join([ "%02x" for x in xrange(6)]) % mac

    def unpack_short(self):
        short = struct.unpack(">H", self.data[self.pos:self.pos + 2])[0]
        self.pos += 2
        return short

    def unpack_byte(self):
        byte = struct.unpack("B", self.data[self.pos])[0]
        self.pos += 1
        return byte

    def unpack_bytes(self, length):
        fmt = "B" * length
        outfmt = "0x%02x " * length
        bytes = struct.unpack(fmt, self.data[self.pos:self.pos + length])
        self.pos += length
        return outfmt % bytes

    def unpack_bool(self, inverted=False):
        fmt = "B"
        b = bool(struct.unpack(fmt, self.data[self.pos])[0])
        self.pos += 1
        if inverted:
            return not b
        else:
            return b
    
    def unpack_str(self, length, outfmt="%s"):
        fmt = ">%(length)ss" % {"length": length}
        value = struct.unpack(fmt, self.data[self.pos:self.pos + length])[0]
        self.pos += length
        return outfmt % (value,)
    
    def unpack_dictvalues(self, dictvalues, default=None):
        """1 Byte of data to dict value"""
        fmt = "B"
        key = struct.unpack(fmt, self.data[self.pos])[0]
        self.pos += 1
        return dictvalues.get(key, default)

class Packer(object):
    """Pack/Unpack data for WIZNet devices"""
    def pack(self, s2e):
        output = []
        for field in s2e._fields:
            name = field[0]
            packer = getattr(self, "pack_%s" % (field[1],))
            fieldvalue = getattr(s2e, name)
            packed = packer(fieldvalue, *field[2:])
            logger.debug("Packed %s %s -> `%s'" % (name, fieldvalue, packed))
            output.append(packed)
        return ''.join(output)

    def pack_ip(self, str_ip):
        """ip address should be in string form "1.2.3.4"""
        return struct.pack(">BBBB", *[ int(c) for c in str_ip.split(".") ])

    def pack_firmversion(self, version):
        return struct.pack(">BB", * [ int(c) for c in version.split(".") ])

    def pack_mac(self, str_mac):
        """mac address should be in string form "00:XX:22::FF:FF:FF"""
        return struct.pack(">BBBBBB", *[ int(c, 16) for c in str_mac.split(":") ])

    def pack_short(self, value):
        return struct.pack(">H", value)

    def pack_byte(self, value):
        return struct.pack(">B", int(value))

    def pack_bool(self, value, inverted=False):
        fmt = ">B"
        if inverted:
            value = not value
        if value:
            intval = 0x01
        else:
            intval = 0x00
        return struct.pack(fmt, intval)

    def pack_str(self, mystr, length, *args):
        fmt = "%(length)ss" % {"length": length }
        return struct.pack(fmt, mystr)

    def pack_dictvalues(self, value, dictvalues, *args):
        fmt = ">B"
        bytevalue = None
        for k, v in dictvalues.items():
            if v == value:
                bytevalue = k
                break
        assert(bytevalue is not None)
        return struct.pack(fmt, bytevalue)

    def pack_bytes(self, value, length):
        fmt = "B" * length
        return struct.pack(fmt, *[ int(x, 16) for x in value.split() ])


class WizSearchException(Exception):
    pass


class WizSearch(object):
    DEVICE_TYPES = {
        "wiz1000": WIZ1000,
        "wiz1x0sr": WIZ1x0SR,
    }

    def __init__(self, address="192.168.11.255",
                 broadcast=False,
                 bind_address="0.0.0.0",
                 device_type="wiz1000",
                 allowed_mac=None,
                 search_password="wiznet", timeout=2.0):

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

        if broadcast:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        s.bind((
            bind_address,
            WizSearch.DEVICE_TYPES[device_type].UDP_LOCAL_PORT,
        ))
        self.device_s = s

        self.search_password = search_password
        self.timeout = timeout
        self.address = (
            address,
            WizSearch.DEVICE_TYPES[device_type].UDP_REMOTE_PORT,
        )
        self.device_type = device_type
        self._devices_list = []
        self.allowed_mac = allowed_mac or []
        self.broadcast = broadcast

    def sendto(self, data):
        logger.debug("sendto %s" % (data[:4],))
        self.device_s.sendto(data, self.address)

    def recvfrom(self, size=1500):
        data, addr = self.device_s.recvfrom(size)
        if not self.broadcast and addr != self.address:
            raise WizSearchException(
                "Unexpected packet recevied from %s, expected was %s" % (
                    addr, self.address))
        logger.debug("recvfrom: %s" % (data[:4]))
        return data

    def get_devices(self):
        devices = {}
        for device in self._devices_list:
            if device.mac in devices:
                raise WizSearchException(
                    "Multiple devices found with mac '%s'" % (
                        device.mac,
                    ))
            devices[device.mac] = device
        return devices

    def update(self):
        """
        Search devices. timeout is expressed in seconds.
        """
        self._devices_list = []
        self.sendto("FIND%-8s" % (self.search_password,))

        start = time.time()
        while start + self.timeout > time.time():
            rfds, _, _ = select.select([self.device_s], [], [], 0.5)

            for sock in rfds:
                data = self.recvfrom()
                if data[0:4] in ("IMIN", "SETC"):
                    try:
                        dev = WizSearch.DEVICE_TYPES[self.device_type](data[4:])
                        # devices.append(self.extract_IMIN(data, wiztype))
                        if not self.allowed_mac or dev.mac in self.allowed_mac:
                            self._devices_list.append(dev)
                    except:
                        logger.exception("parsing error.")

        if not self._devices_list:
            logger.error("Timeout, no devices found")
        return self._devices_list

    def send_config(self, device):
        data = device.pack()
        self.sendto("SETT%s" % (data,))
        ack = self.recvfrom()
        if ack[:4] != "SETC":
            logger.error("Unexpected data '%s'" % (data[:4]))
        if ack[4:] != data:
            logger.error("ACK failed")
        else:
            logger.debug("ACK sucess")

    def set_options(self, **kwargs):
        devices = self.get_devices()
        for dev in devices.values():
            for opt, val in kwargs.items():
                dev.set_option(opt, val)
            if kwargs:
                self.send_config(dev)
            else:
                dev.print_config()

    @staticmethod
    def main():
        parser = OptionParser()
        parser.add_option(
            "-b", dest="broadcast_address",
            action="store",
            help="Broadcast address",
        )
        parser.add_option(
            "-a", dest="address",
            help="Device IP address",
        )
        parser.add_option(
            "--device-type",
            choices=["wiz1000", "wiz1x0sr"],
            default="wiz1000",
            help="Device type",
        )
        parser.add_option(
            "-m", dest="mac_list",
            help="Limit actions to theses mac address",
        )
        parser.add_option(
            "-s", dest="device_search_password",
            default="wiznet",
            help="Search password",
        )

        # Generate options based on fields descriptions
        fields = WIZ1000._basic_fields + WIZ1000._extended_fields
        for field in fields:
            option = "--%s" % (field[0].replace("_", "-"),)
            kwargs = {}
            if field[1] == "bool":
                kwargs["action"] = "store_true"
            if field[1] == "short":
                kwargs["type"] = "int"
            if field[1] == "dictvalues":
                choices = field[2].values()
                if isinstance(choices[0], int):
                    kwargs["type"] = "int"
                else:
                    kwargs["choices"] = choices
                kwargs["help"] = ",".join(["%s" % (v,) for v in choices])
            parser.add_option(option, dest=field[0], **kwargs)
            if field[1] == "bool":
                # For boolean field, add --no-option
                kwargs["action"] = "store_false"
                parser.add_option("--no-%s" % (field[0].replace("_", "-"),),
                                  dest=field[0], **kwargs)
        options, _ = parser.parse_args()

        kwargs = {}
        for field in fields:
            value = getattr(options, field[0])
            if value is not None:
                kwargs[field[0]] = value

        search_kwargs = {
            "broadcast": True,
            "address": "192.168.11.255",
            "device_type": options.device_type,
            "search_password": options.device_search_password,
        }
        if options.mac_list:
            search_kwargs["allowed_mac"] = options.mac_list.split(',')
        if options.broadcast_address:
            search_kwargs["address"] = options.broadcast_address
        if options.address:
            search_kwargs["address"] = options.address
            search_kwargs["broadcast"] = False
        searcher = WizSearch(**search_kwargs)
        searcher.update()
        searcher.set_options(**kwargs)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    WizSearch.main()
