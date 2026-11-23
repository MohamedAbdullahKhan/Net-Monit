"""Native Linux packet capture (AF_PACKET): no libpcap/tcpdump needed, loopback packets are seen once, promiscuous mode optional.
Also contains a tiny pcap writer used for PCAP export on every platform."""
import socket
import struct
import threading
import time

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
LINK_ETHERNET, LINK_RAW = 1, 101


class PcapWriter:
    """Minimal libpcap file writer (microsecond timestamps)."""

    def __init__(self, path, linktype=LINK_ETHERNET, snaplen=65535):
        self.f = open(path, "wb"); self.snaplen = snaplen
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)); self.lock = threading.Lock()

    def write(self, data, ts=None, wirelen=None):
        ts = ts or time.time(); sec = int(ts); usec = int((ts - sec) * 1e6); cap = data[:self.snaplen]
        with self.lock:
            self.f.write(struct.pack("<IIII", sec, usec, len(cap), wirelen or len(data)) + cap)

    def close(self):
        with self.lock:
            try: self.f.close()
            except Exception: pass


class RawLinuxSniffer(threading.Thread):
    def __init__(self, iface, on_frame, promisc=True):
        super().__init__(daemon=True, name="traffic-af_packet")
        self.iface, self.on_frame, self.promisc = iface, on_frame, promisc
        self.running = False; self.exception = None; self._stop_evt = threading.Event(); self.sock = None; self.linktype = LINK_ETHERNET

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.sock.bind((self.iface, 0)); self.sock.settimeout(0.5)
            try: self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            except OSError: pass
            if self.promisc and self.iface != "lo":
                try:
                    idx = socket.if_nametoindex(self.iface)
                    self.sock.setsockopt(263, 1, struct.pack("iHH8s", idx, 1, 0, b""))      # SOL_PACKET, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC
                except OSError: pass
        except PermissionError:
            raise
        except OSError as e:
            self.exception = e; raise
        self.running = True
        super().start()

    def run(self):
        loop = self.iface == "lo"
        while not self._stop_evt.is_set():
            try:
                data, sa = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if sa[2] == PACKET_OUTGOING and loop:      # on loopback every packet is delivered twice (out + in): count it once
                continue
            hatype = sa[3]
            self.linktype = LINK_RAW if hatype in (65534, 768, 769) else LINK_ETHERNET
            try: self.on_frame(data, self.linktype, time.time())
            except Exception: pass
        self.running = False

    def stop(self):
        self._stop_evt.set()
        try: self.sock.close()
        except Exception: pass
        self.running = False
