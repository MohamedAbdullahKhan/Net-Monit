"""IP blacklist: one IP address or CIDR range per line; '#' or ';' start a comment (full-line or after the entry). Invalid lines are
ignored. Lookup cost is O(number of distinct prefix lengths)."""
import ipaddress


class IpBlacklist:
    def __init__(self):
        self._sets = {4: {}, 6: {}}          # version -> {prefixlen: set(int network address)}
        self.ips = 0
        self.cidrs = 0
        self.path = ""
        self.lines = 0                       # non-empty, non-comment lines seen

    @property
    def count(self):
        return self.ips + self.cidrs

    @property
    def invalid(self):
        """The file had content but not one valid entry (Sniffnet marks such a list as invalid)."""
        return self.lines > 0 and self.count == 0

    def info(self):
        parts = []
        if self.ips: parts.append(f"IPs: {self.ips}")
        if self.cidrs: parts.append(f"CIDRs: {self.cidrs}")
        return ", ".join(parts)

    @classmethod
    def from_file(cls, path):
        b = cls(); b.path = path
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                for mark in ("#", ";"):
                    line = line.split(mark, 1)[0]
                line = line.strip()
                if not line: continue
                b.lines += 1
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    continue
                b._sets[net.version].setdefault(net.prefixlen, set()).add(int(net.network_address))
                if "/" in line: b.cidrs += 1
                else: b.ips += 1
        return b

    def contains(self, addr):
        a = ipaddress.ip_address(addr) if not hasattr(addr, "version") else addr
        bits = 32 if a.version == 4 else 128
        n = int(a)
        for plen, s in self._sets[a.version].items():
            if (n >> (bits - plen) << (bits - plen)) in s:
                return True
        return False
