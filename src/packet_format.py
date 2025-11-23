# src/packet_format
import struct
import uuid
from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketHeader:
    """
    Represents the header of our custom packet format.
    """

    version: int  # Protocol version (1 byte) - allows future upgrades
    file_id: bytes  # UUID (16 bytes) - uniquely identifies the file transfer
    sequence_num: int  # (4 bytes) - orders packets for reassembly
    total_packets: int  # (4 bytes) - helps receiver know when transfer is complete
    timestamp: int  # (8 bytes) - prevents replay attacks
    payload_size: int  # (4 bytes) - size of actual data in this packet
    original_chunk_size: int  # Size of the plaintext chunk (e.g., 1024)
    crc_checksum: int  # (4 bytes) - error detection
    hmac_signature: bytes  # (32 bytes) - authentication and integrity

    # Format string for struct.pack/unpack
    # '>' means big-endian (network byte order)
    # B=unsigned char, 16s=16-char string, I=unsigned int, Q=unsigned long long
    FORMAT = ">B16sIIQIII32s"
    HEADER_SIZE = struct.calcsize(FORMAT)

    def pack(self) -> bytes:
        """Converts header to binary format for network transmission"""
        return struct.pack(
            self.FORMAT,
            self.version,
            self.file_id,
            self.sequence_num,
            self.total_packets,
            self.timestamp,
            self.payload_size,
            self.original_chunk_size,
            self.crc_checksum,
            self.hmac_signature,
        )

    def pack_without_hmac(self) -> bytes:
        """Pack header excluding HMAC (for computing HMAC over header + payload)."""
        return struct.pack(
            ">B16sIIQIII",  # Exclude 32s for hmac
            self.version,
            self.file_id,
            self.sequence_num,
            self.total_packets,
            self.timestamp,
            self.payload_size,
            self.original_chunk_size,
            self.crc_checksum,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "PacketHeader":
        """Reconstructs header from binary data"""
        unpacked = struct.unpack(cls.FORMAT, data[: cls.HEADER_SIZE])
        return cls(*unpacked)


class Packet:
    """Complete packet with header and payload"""

    def __init__(self, header: PacketHeader, payload: bytes):
        self.header = header
        self.payload = payload

    def to_bytes(self) -> bytes:
        """Serializes entire packet for transmission"""
        return self.header.pack() + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "Packet":
        """Deserializes packet from received data"""
        header = PacketHeader.unpack(data)
        payload = data[
            PacketHeader.HEADER_SIZE : PacketHeader.HEADER_SIZE + header.payload_size
        ]
        return cls(header, payload)
