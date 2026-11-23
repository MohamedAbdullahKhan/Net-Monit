"""Packet capture on Windows WITHOUT Npcap: raw IP sockets in 'receive all' mode (SIO_RCVALL). Needs Administrator / Local System only.

What you get: every IPv4 packet that passes the network card address (incoming and outgoing), starting at the IP header, so no
Ethernet MAC addresses or VLAN tags (the link type is RAW). IPv6 is captured when Windows allows it. Install Npcap if you want MAC/VLAN
or native BPF filters; Net-monit then uses it automatically."""
import socket
import threading
import time

SIO_RCVALL = getattr(socket, "SIO_RCVALL", 0x98000001)
RCVALL_ON, RCVALL_OFF = getattr(socket, "RCVALL_ON", 1), getattr(socket, "RCVALL_OFF", 0)
LINK_RAW = 101


def npcap_installed():
    """True when Npcap/WinPcap's wpcap.dll is present (then scapy can capture natively)."""
    import os
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return any(os.path.isfile(os.path.join(root, "System32", *p)) for p in (("Npcap", "wpcap.dll"), ("wpcap.dll",)))


class RawWindowsSniffer:
    """One raw socket per local address of the chosen card, one reader thread each."""

    def __init__(self, addresses, on_frame, socket_factory=None):
        self.addresses, self.on_frame = list(addresses), on_frame
        self.make = socket_factory or self._real_socket
        self.socks, self.threads, self.errors = [], [], []
        self._stop = threading.Event(); self.running = False; self.exception = None; self.linktype = LINK_RAW

    @staticmethod
    def _real_socket(addr, v6):
        if v6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_IPV6); s.bind((addr, 0))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP); s.bind((addr, 0)); s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(SIO_RCVALL, RCVALL_ON)
        return s

    def start(self):
        for a in self.addresses:
            v6 = ":" in a
            if a.startswith("127.") or a == "::1" or a.startswith("fe80:") or a.startswith("169.254."):
                continue                                                      # loopback / link-local cannot be captured this way
            try:
                s = self.make(a, v6); s.settimeout(0.5)
            except PermissionError:
                raise PermissionError("Windows refused a raw capture socket: run Net-monit as Administrator (the Windows service already does)")
            except OSError as e:
                self.errors.append(f"{a}: {e}")
                if not v6:                                                    # IPv4 is the one we need; IPv6 may simply be unsupported
                    self.exception = e
                continue
            self.socks.append(s)
        if not self.socks:
            raise OSError("Could not open a raw capture socket on this network card. " + "; ".join(self.errors) +
                          " (Security software can block raw sockets; installing Npcap is the alternative.)")
        self.running = True
        for s in self.socks:
            t = threading.Thread(target=self._loop, args=(s,), daemon=True, name="traffic-rawwin"); t.start(); self.threads.append(t)

    def _loop(self, s):
        while not self._stop.is_set():
            try:
                data = s.recvfrom(65535)[0]
            except socket.timeout:
                continue
            except OSError:
                break
            if data:
                try: self.on_frame(data, LINK_RAW, time.time())
                except Exception: pass

    def stop(self):
        self._stop.set(); self.running = False
        for s in self.socks:
            try: s.ioctl(SIO_RCVALL, RCVALL_OFF)
            except Exception: pass
            try: s.close()
            except Exception: pass
