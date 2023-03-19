import argparse
import usb
import usb.core

SEQUENCE_START_BIT = 0b10000000
SEQUENCE_END_BIT = 0b01000000
SEQUENCE_LENGTH_BITS = 0b00111111
ESC = b"\x1b"


class MSR605X:
    """ Represents a MSR605X device

    There are three levels of abstraction that this class can be used at:
    - raw 64 byte hid packets: _send_packet and _recv_packet
    - plain MSR605 serial protocol messages: send_message and recv_message
    - higher level functions: reset, ... (more to be added)

    """

    def __init__(self, **kwargs):
        if "idVendor" not in kwargs:
            kwargs["idVendor"] = 0x0801
            kwargs["idProduct"] = 0x0003
        self.dev: usb.core.Device = usb.core.find(**kwargs)
        self.hid_endpoint = None

    def close(self):
        """ Close the connection to the MSR605X """
        if self.dev:
            self.dev.reset()
            usb.util.dispose_resources(self.dev)

    def _connect(self):
        """ Establish a connection to the MSR605X """
        dev = self.dev
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
        dev.set_configuration()
        config = dev.get_active_configuration()
        interface = config.interfaces()[0]
        self.hid_endpoint = interface.endpoints()[0]

    def connect(self, tries=5):
        """ Connect with auto-retry """
        ret = None
        while ret is None:
            if tries == 0:
                raise RuntimeError("Failed to connect to MSR605X")
            tries -= 1

            self.close()
            self._connect()
            self.reset()
            self.send_message(ESC + b'v')
            ret = self.recv_message(timeout=1000)
        assert ret[0:1] == ESC

    @staticmethod
    def _make_header(start_of_sequence: bool, end_of_sequence: bool, length: int):
        if length < 0 or length > 63:
            raise ValueError("Length must be a non-negative number no more than 63")
        header = length
        if start_of_sequence:
            header |= SEQUENCE_START_BIT
        if end_of_sequence:
            header |= SEQUENCE_END_BIT
        return bytes([header])

    def _encapsulate_message(self, message):
        idx = 0
        while idx < len(message):
            payload = message[idx:idx + 63]
            header = self._make_header(idx == 0, len(message) - idx < 64, len(payload))
            padding = b"\0" * (63 - len(payload))
            yield header + payload + padding
            idx += 63

    def _send_packet(self, packet):
        self.dev.ctrl_transfer(0x21, 9, wValue=0x0300, wIndex=0, data_or_wLength=packet)

    def _recv_packet(self, **kwargs):
        try:
            return bytes(self.hid_endpoint.read(64, **kwargs))
        except usb.core.USBError as error:
            if error.errno == 110:
                return None
            raise error

    def send_message(self, message):
        """ Send a message to the MSR605X """
        for packet in self._encapsulate_message(message):
            self._send_packet(packet)

    def recv_message(self, timeout=0):
        """ Receive message from the MSR605X """
        message = b""
        while True:
            packet = self._recv_packet(timeout=timeout)
            if packet is None and not message:
                return None
            payload_length = packet[0] & SEQUENCE_LENGTH_BITS
            payload = packet[1:1 + payload_length]
            message = message + payload
            # note: we don't actually check the sequence start bit currently, we probably should to
            # check this in case we somehow start reading in the middle of a message
            if packet[0] & SEQUENCE_END_BIT:
                break
        return payload

    def reset(self):
        """ Sends reset message to the MSR605X """
        self.send_message(ESC + b"a")

    def _send_command_and_recv_response(self, command):
        self.reset()
        self.send_message(ESC + command)
        ret = self.recv_message()
        assert ret[0:1] == ESC
        return ret[1:].decode()

    def get_firmware_version(self):
        """ Get the firmware version of the connected MSR605X """
        return self._send_command_and_recv_response(b"v")

    def read_raw(self):
        """ Read a card from the MSR605X """
        msr.reset()
        self.send_message(ESC + b"m")
        ret = self.recv_message()
        assert ret[0:1] == ESC
        return ret[1:]

    def read_iso(self):
        """ Read a card from the MSR605X """
        return self._send_command_and_recv_response(b"r")

    def set_hico(self):
        """ Set the MSR605X to high coercivity mode """
        msr.reset()
        self.send_message(ESC + b"x")
        ret = self.recv_message()
        assert ret[0:1] == ESC
        return ret[1:].decode()

    def set_loco(self):
        """ Set the MSR605X to coercivity mode """
        msr.reset()
        self.send_message(ESC + b"y")
        ret = self.recv_message()
        assert ret[0:1] == ESC
        return ret[1:].decode()

    def write_iso(self, tracks, hico):
        """ Write a card to the MSR605X """
        msr.reset()
        if hico:
            self.set_hico()
        else:
            self.set_loco()
        self.send_message(b'\x1bw\x1bs'
                          b'\x1b\x01' + tracks[0].encode() +
                          b'\x1b\x02' + tracks[1].encode() +
                          b'\x1b\x03' + tracks[2].encode() + b'?\x1c')
        ret = self.recv_message()
        assert ret[0:1] == ESC
        rcode = int(ret[1:].decode())
        if rcode != 0:
            print("Write failed: error code", rcode)
        else:
            print("Write success")

    def erase(self):
        """ Erase a card
        0: Track 1 only
        2: Track 2 only
        4: Track 3 only
        3: Track 1 & 2
        5: Track 1 & 3
        6: Track 2 & 3
        7: Track 1, 2 & 3
        """
        msr.reset()
        self.send_message(ESC + b'c' + b'7')
        ret = self.recv_message()
        assert ret[0:1] == ESC
        rcode = int(ret[1:].decode())
        if rcode != 0:
            print("Erase failed: error code", rcode)
        else:
            print("Erase success")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MSR605X CLI")
    subparsers = parser.add_subparsers(dest="subcommand", help="subcommand help")
    parser_read = subparsers.add_parser("read", help="read help")

    parser_write = subparsers.add_parser("write", help="read help")
    parser_write.add_argument("data", help="Semicolon delimited data")
    parser_write.add_argument("-l", help="Low coercivity mode (default HiCo mode)", action="store_true", default=False)

    parser_erase = subparsers.add_parser("erase", help="erase help")
    args = parser.parse_args()

    msr = None
    if args.subcommand in ["read", "write", "erase"]:
        msr = MSR605X()
        msr.connect()
        msr.reset()

    if args.subcommand == "read":
        print("Reading card...")
        print(msr.read_iso())
    elif args.subcommand == "write":
        tracks = args.data.split(";")
        if len(tracks) < 1 or len(tracks) > 3:
            print("Invalid data: expected 1 to 3 tracks")
            exit(1)
        print("Writing card...")
        msr.write_iso(tracks, not args.l)
    elif args.subcommand == "erase":
        print("Erasing card...")
        msr.erase()
    else:
        parser.print_help()

    if msr is not None:
        msr.close()
