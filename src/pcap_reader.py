"""
pcap_reader.py - Read and write PCAP files.
Mirrors pcap_reader.h / pcap_reader.cpp from the original C++ project.
No external libraries — pure stdlib.
"""

from __future__ import annotations
from typing import Iterator, Optional
import struct

from .types import PcapGlobalHeader, PcapPacketHeader, RawPacket

PCAP_MAGIC_LE = 0xA1B2C3D4   # little-endian timestamps (µs)
PCAP_MAGIC_BE = 0xD4C3B2A1   # big-endian timestamps (µs)
PCAP_MAGIC_NS_LE = 0xA1B23C4D  # nanosecond resolution


class PcapReader:
    """Iterate over packets in a .pcap file."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = None
        self.global_header: Optional[PcapGlobalHeader] = None
        self._byte_swap = False

    def open(self) -> "PcapReader":
        self._fh = open(self.path, "rb")
        hdr_bytes = self._fh.read(PcapGlobalHeader.SIZE)
        if len(hdr_bytes) < PcapGlobalHeader.SIZE:
            raise ValueError(f"File too small to be a PCAP: {self.path}")

        # Detect byte order
        magic = struct.unpack_from("<I", hdr_bytes)[0]
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            self._byte_swap = False
        elif magic == PCAP_MAGIC_BE:
            self._byte_swap = True
        else:
            raise ValueError(f"Not a PCAP file (bad magic: 0x{magic:08X}): {self.path}")

        fmt = "<IHHiIII" if not self._byte_swap else ">IHHiIII"
        fields = struct.unpack(fmt, hdr_bytes)
        self.global_header = PcapGlobalHeader(*fields)
        return self

    def __enter__(self) -> "PcapReader":
        return self.open()

    def __exit__(self, *_) -> None:
        self.close()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def packets(self) -> Iterator[RawPacket]:
        """Yield RawPacket objects one by one."""
        fmt_hdr = "<IIII" if not self._byte_swap else ">IIII"
        while True:
            hdr_bytes = self._fh.read(PcapPacketHeader.SIZE)
            if not hdr_bytes:
                break
            if len(hdr_bytes) < PcapPacketHeader.SIZE:
                break
            fields = struct.unpack(fmt_hdr, hdr_bytes)
            pkt_hdr = PcapPacketHeader(*fields)
            data = self._fh.read(pkt_hdr.incl_len)
            if len(data) < pkt_hdr.incl_len:
                break
            yield RawPacket(header=pkt_hdr, data=data)


class PcapWriter:
    """Write packets to a .pcap file."""

    def __init__(self, path: str,
                 snaplen: int = 65535,
                 network: int = 1) -> None:
        self.path = path
        self._snaplen = snaplen
        self._network = network
        self._fh = None

    def open(self) -> "PcapWriter":
        self._fh = open(self.path, "wb")
        gh = PcapGlobalHeader(
            magic_number=PCAP_MAGIC_LE,
            version_major=2, version_minor=4,
            thiszone=0, sigfigs=0,
            snaplen=self._snaplen,
            network=self._network
        )
        self._fh.write(gh.to_bytes())
        return self

    def __enter__(self) -> "PcapWriter":
        return self.open()

    def __exit__(self, *_) -> None:
        self.close()

    def write_packet(self, raw: RawPacket) -> None:
        self._fh.write(raw.header.to_bytes())
        self._fh.write(raw.data)

    def write_raw(self, ts_sec: int, ts_usec: int, data: bytes) -> None:
        hdr = PcapPacketHeader(ts_sec, ts_usec, len(data), len(data))
        self._fh.write(hdr.to_bytes())
        self._fh.write(data)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
