import struct

import zigpy.types as t


class PcapWriter:
    """Class responsible to write in PCAP format."""

    def __init__(self, file):
        """Initialize PCAP file and write global header."""
        self.file = file

    def write_header(self):
        self.file.write(
            struct.pack("<L", 0xA1B2C3D4)
            + struct.pack("<H", 2)
            + struct.pack("<H", 4)
            + struct.pack("<L", 0)
            + struct.pack("<L", 0)
            + struct.pack("<L", 65535)
            + struct.pack("<L", 283)  # LINKTYPE_IEEE802_15_4_TAP
        )

    def write_packet(self, packet: t.CapturedPacket) -> None:
        """Write a packet with its header and TLV metadata."""
        timestamp_sec = int(packet.timestamp.timestamp())
        timestamp_usec = int(packet.timestamp.microsecond)

        sub_tlvs = b""

        # RSSI
        sub_tlvs += (
            t.uint16_t(1).serialize()
            + t.uint16_t(4).serialize()
            + t.Single(packet.rssi).serialize()
        )

        # LQI
        sub_tlvs += (
            t.uint16_t(10).serialize()
            + t.uint16_t(1).serialize()
            + t.uint8_t(packet.lqi).serialize()
            + b"\x00\x00\x00"
        )

        # Channel Assignment
        sub_tlvs += (
            t.uint16_t(3).serialize()
            + t.uint16_t(3).serialize()
            + t.uint16_t(packet.channel).serialize()
            + t.uint8_t(0).serialize()  # page 0
            + b"\x00"
        )

        # FCS type
        sub_tlvs += (
            t.uint16_t(0).serialize()
            + t.uint16_t(1).serialize()
            + t.uint8_t(1).serialize()  # FCS type 1
            + b"\x00\x00\x00"
        )

        tlvs = b""

        # TAP header: version:u8, reserved: u8, length: u16
        tlvs += struct.pack("<BBH", 0, 0, 4 + len(sub_tlvs))
        assert len(sub_tlvs) % 4 == 0

        data = tlvs + sub_tlvs + packet.data + packet.compute_fcs()

        self.file.write(
            struct.pack("<L", timestamp_sec)
            + struct.pack("<L", timestamp_usec)
            + struct.pack("<L", len(data))
            + struct.pack("<L", len(data))
            + data
        )
