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

logger = logging.getLogger("wiz1000")

WIZ1000_UDP_LOCAL_PORT = 1138
WIZ1000_UDP_REMOTE_PORT = 5003

WIZ1x0SR_UDP_LOCAL_PORT = 5001
WIZ1x0SR_UDP_REMOTE_PORT = 1460

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
    return ' '.join([ "%02x" % (ord(c),) for c in msg])

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

    def __unicode__(self):
        return u"%(ip)s %(mac)s %(type)s v%(firmware_version)s" % self.__dict__
    def __str__(self):
        return self.__unicode__()
    def __repr__(self):
        return self.__unicode__()

class WIZ1x0SR(S2E):
    _type = "WIZ1x0SR"
    _extended_fields = []

class WIZ1000(S2E):
    _type = "WIZ1000"
    _extended_fields = [
        ("rfc2217_port",        "short"),
        ("rfc2217_password",    "str", 8, "%-8s"),
        ("search_password",     "str", 8, "%-8s"),
        ("keepalive_interval",  "short"),
        ("remote_ip_udp",       "ip"),
    ]

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
        return ".".join([ "%d" for x in xrange(4)]) % ip

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
        return struct.pack(">B", value)

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

class WizSearch(object):
    def __init__(self, bind_address="0.0.0.0"):
        # WIZ1000 UDP IPv4 Socket
        wiz1000_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        wiz1000_s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        wiz1000_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        wiz1000_s.bind((bind_address, WIZ1000_UDP_LOCAL_PORT))
        self.wiz1000_sock = wiz1000_s
        # WIZ1x0SR UDP IPv4 Socket
        wiz1x0sr_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        wiz1x0sr_s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        wiz1x0sr_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        wiz1x0sr_s.bind((bind_address, WIZ1x0SR_UDP_LOCAL_PORT))
        self.wiz1x0sr_sock = wiz1x0sr_s

    def search(self, search_password="wiznet", timeout=5.0):
        """
        Search devices using UDP broadcast. timeout is expressed in seconds.
        """
        devices = []
        wiz1000_addr = ('192.168.11.255', WIZ1000_UDP_REMOTE_PORT)
        wiz1x0sr_addr = ('192.168.11.255', WIZ1x0SR_UDP_REMOTE_PORT)

        # Targetting WIZ1000 S2E (V4.1+)
        logger.info("Sending FIND packet to %s..", wiz1000_addr)
        self.wiz1000_sock.sendto("FIND%-8s" % (search_password,), wiz1000_addr)
        # Targetting WIZ1x0SR
        logger.info("Sending FIND packet to %s..", wiz1x0sr_addr)
        self.wiz1x0sr_sock.sendto("FIND%-8s" % (search_password,), wiz1x0sr_addr)
        
        start = time.time()
        while start + timeout > time.time():
            rfds, wfds, efds = select.select([ self.wiz1000_sock, 
                                               self.wiz1x0sr_sock,
                                             ], [], [], 0.5)
            for sock in rfds:
                data, raddr = sock.recvfrom(1500)
                logger.debug("Received len(data)=%d from %s", len(data), raddr)
                if data[0:4] == "IMIN":
                    if raddr[1] == WIZ1x0SR_UDP_REMOTE_PORT:
                        klass = WIZ1x0SR
                    else:
                        klass = WIZ1000
                    try:
                        s2e = klass(data[4:])
                        # devices.append(self.extract_IMIN(data, wiztype))
                        devices.append(s2e)
                    except:
                        logger.exception("parsing error.")
                        print "Unrecognized device %s responded to IMIN." % (
                            raddr,)
        return devices
        logger.info("Search timeout occured.")

if __name__ == "__main__":
    import pprint

    logging.basicConfig(level=logging.DEBUG)
    searcher = WizSearch()
    devices = searcher.search("wiznet", 1.0)
    pprint.pprint(devices)

    for device in devices:
        device.flow = "none"
        device.baudrate = 115200
        device.debug_enabled = False
        if isinstance(device, WIZ1000):
            rport = WIZ1000_UDP_REMOTE_PORT
            lport = WIZ1000_UDP_LOCAL_PORT
        else:
            rport = WIZ1x0SR_UDP_REMOTE_PORT
            lport = WIZ1x0SR_UDP_LOCAL_PORT

        addr = ('192.168.11.255', rport)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        sock.bind(('0.0.0.0', lport))
        sock.sendto("SETT%s" % (device.pack(),), addr)
        data, raddr = sock.recvfrom(1500)
        print "Sent: %s" % (hexdump(device.pack()),)
        print "Received: %s" % (hexdump(data),)
