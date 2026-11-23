# =============================================================================
# Net-monit V12.4 -- Speed Test Checker
# Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com
# =============================================================================
"""
speedtest_check.py
Measures WAN download / upload speed, latency and jitter.

Engines (config.yaml -> speedtest.engine, default "builtin" since V10.9; "auto" tries the speedtest-cli library first):

  1. speedtest-cli -- the third-party library that has always been a dependency
     of this project. Skipped when engine is "builtin". Guarded by a hard time
     limit so it can never hang a test. It has no live-speed hook, so while it
     runs the page can show the phase but not a live Mbps figure.
  2. Built-in multi-connection HTTP test (this file), against a TARGET:
       a. custom targets from config.yaml (speedtest.targets -- LibreSpeed-
          compatible servers, tried in the order listed), then
       b. Cloudflare (speed.cloudflare.com).

What the built-in test measures is the path from THIS machine to the target --
not "the ISP's line speed" in the abstract. That is also true of speedtest.net
(it measures the path to an Ookla server, usually one inside your ISP), which
is why the target matters and why every result records which one was used.
See CLAUDE.md lesson #8 for why the Ookla CLI is deliberately NOT used here.

V10.7 rewrite of the built-in engine (why, in short):
  * V10.6 drained the rest of every in-flight chunk (r.read()) after the
    deadline. On slow and medium links that dragged a "5 s" test out to 24 s
    and divided the bytes by the inflated time: 22 % of the real speed was
    reported on a 12 Mbps link, 50 % on 30 Mbps. Now: the main thread ends the
    phase at the deadline and closes every socket (shutdown() wakes a blocked
    read), then computes the rate from a window that stops AT the deadline.
  * Upload only counted a chunk once the WHOLE 2 MB POST completed, so on a slow
    link the byte counter moved in huge lumps. Bytes are now counted as they
    are handed to the socket.
  * Latency was measured to 1.1.1.1 while the download came from
    speed.cloudflare.com -- different anycast prefixes that an ISP can route to
    different data centres. Latency is now measured to the host that carries
    the test, and the Cloudflare data centre (colo) is reported.
  * A direction that fails is reported as None, not as a "successful" 0.0 Mbps.
"""
import logging, time, socket, ssl, urllib.request, urllib.parse, http.client
import threading, os, json, random, statistics, sys

log = logging.getLogger("monitor.checkers.speedtest")

# V10.6: Python 3.12 removed the legacy ssl.wrap_socket() function. The
# speedtest-cli library (2.1.3, latest on PyPI at time of writing) still
# calls it as a fallback when its own self._context.wrap_socket(...) path
# raises AttributeError (speedtest.py, HTTPSConnection.connect(), around
# line 486) -- on 3.12 that fallback call itself then raises AttributeError
# ("module 'ssl' has no attribute 'wrap_socket'"), uncaught, which is why
# _try_speedtest_cli() below was silently failing every time. This restores
# a working wrap_socket() using the modern SSLContext API, only if it's
# actually missing (Python <3.12 is unaffected and never sees this).
# Verified against a real local TLS server, not just imported without error.
if not hasattr(ssl, "wrap_socket"):
    def _wrap_socket_compat(sock, keyfile=None, certfile=None, server_side=False,
                             cert_reqs=ssl.CERT_NONE, ssl_version=None,
                             ca_certs=None, do_handshake_on_connect=True,
                             suppress_ragged_eofs=True, ciphers=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
        if certfile:
            context.load_cert_chain(certfile, keyfile)
        if ca_certs:
            context.load_verify_locations(ca_certs)
        if cert_reqs == ssl.CERT_NONE:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context.verify_mode = cert_reqs
        if ciphers:
            context.set_ciphers(ciphers)
        return context.wrap_socket(sock, server_side=server_side,
                                    do_handshake_on_connect=do_handshake_on_connect,
                                    suppress_ragged_eofs=suppress_ragged_eofs)
    ssl.wrap_socket = _wrap_socket_compat

_UA            = "netmonit/11.3"
_DL_SECONDS    = 10.0          # download phase length
_UL_SECONDS    = 8.0           # upload phase length
_DL_STREAMS    = 8             # parallel TCP connections, download
_UL_STREAMS    = 6             # parallel TCP connections, upload
_DL_CHUNK      = 25_000_000    # bytes requested per download request (same size the browser test already uses)
_UL_CHUNK      = 262_144       # STARTING bytes per upload request (adapts 64 KB..16 MB so each request lasts ~1 s)
_SOCK_TIMEOUT  = 6.0           # a stalled socket read/write gives up after this
_LAST_RATE_LIMITED_AT = 0.0   # time.time() of the last 429/503 from a test target (for the "wait" hint)
_CLI_TIMEOUT   = 100.0         # speedtest-cli may never hold a test longer than this


# ─────────────────────────────────────────────────────────────────────────────
#  Targets
# ─────────────────────────────────────────────────────────────────────────────
class _Target:
    """A place to run the built-in test against."""
    def __init__(self, name, scheme, host, port, kind, base="/", down_path="garbage.php",
                 up_path="empty.php", ping_path="empty.php", verify_tls=True):
        self.name, self.scheme, self.host, self.port, self.kind = name, scheme, host, port, kind
        self.base, self.down_path, self.up_path, self.ping_path = base, down_path, up_path, ping_path
        self.verify_tls = verify_tls

    def down_request(self, nbytes):
        if self.kind == "cloudflare":
            return "GET", f"/__down?bytes={int(nbytes)}"
        mib = max(1, int(round(nbytes / 1048576.0)))            # LibreSpeed takes MiB
        return "GET", f"{self.base}{self.down_path}?cors=true&ckSize={mib}&r={random.random()}"

    def up_request(self):
        if self.kind == "cloudflare":
            return "POST", "/__up"
        return "POST", f"{self.base}{self.up_path}?r={random.random()}"

    def ping_request(self):
        if self.kind == "cloudflare":
            return "GET", "/__down?bytes=0"
        return "GET", f"{self.base}{self.ping_path}?r={random.random()}"


def _cloudflare_target():
    return _Target("Cloudflare", "https", "speed.cloudflare.com", 443, "cloudflare")


def _new_connection(target, timeout):
    """One place that creates connections (tests redirect this at a local server)."""
    if target.scheme == "https":
        ctx = ssl.create_default_context()
        try:                                  # V12.4 patch 01: Python 3.13+ turns VERIFY_X509_STRICT on; firewalls / proxies that inspect
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT   # HTTPS present certificates that fail it, so every stream died and no download ran
        except (AttributeError, ValueError):
            pass
        if not target.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(target.host, target.port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(target.host, target.port, timeout=timeout)


def _interrupt(conn):
    """
    Wake a worker that is blocked in recv()/send() on this connection. shutdown() does that;
    close() alone does not. This is the ONLY thing another thread may do to a connection:
    closing it from outside races with http.client's own close-at-EOF (AttributeError
    inside the worker), so the worker that owns the connection closes it itself.
    """
    sock = getattr(conn, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass


def _hard_close(conn):
    """Full close -- call only from the thread that owns the connection."""
    _interrupt(conn)
    try:
        conn.close()
    except Exception:
        pass


def _speedtest_config():
    try:
        from monitor import config_manager
        cfg = config_manager.get_config() or {}
        st = cfg.get("speedtest")
        return st if isinstance(st, dict) else {}
    except Exception as e:
        log.debug("speedtest config unavailable: %s", e)
        return {}


def _configured_targets(cfg):
    """speedtest.targets in config.yaml -> [_Target]; a bad entry is logged and skipped, never fatal."""
    out = []
    for i, t in enumerate(cfg.get("targets") or []):
        try:
            u = urllib.parse.urlparse(str(t.get("url", "")).strip())
            if u.scheme not in ("http", "https") or not u.hostname:
                raise ValueError("url must look like https://host/path/")
            port = u.port or (443 if u.scheme == "https" else 80)
            base = u.path if u.path.endswith("/") else (u.path + "/")
            out.append(_Target(str(t.get("name") or u.hostname), u.scheme, u.hostname, port, "librespeed",
                               base=base,
                               down_path=str(t.get("download_path") or "garbage.php"),
                               up_path=str(t.get("upload_path") or "empty.php"),
                               ping_path=str(t.get("ping_path") or "empty.php"),
                               verify_tls=bool(t.get("verify_tls", True))))
        except Exception as e:
            log.warning("speedtest.targets[%d] ignored: %s", i, e)
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  One measurement phase (download OR upload)
# ─────────────────────────────────────────────────────────────────────────────
class _HttpStatus(Exception):
    """A non-success HTTP answer. Keeps the status and Retry-After so 429/503 can be handled politely."""
    def __init__(self, msg, status=0, retry_after=None):
        super().__init__(msg)
        self.status, self.retry_after = status, retry_after

    @classmethod
    def from_response(cls, r):
        ra = None
        try:
            ra = float(r.getheader("Retry-After") or "")
        except (TypeError, ValueError):
            pass
        return cls(f"HTTP {r.status}", r.status, ra)


class _Phase:
    def __init__(self, kind, target, duration, chunk_bytes, timeout):
        self.kind, self.target, self.duration = kind, target, duration
        self.chunk, self.timeout = chunk_bytes, timeout
        self.lock = threading.Lock()
        self.total = 0
        self.stop = threading.Event()
        self.conns = []
        self.connections = 0
        self.errors = 0
        self.last_error = ""
        self.t0 = 0.0
        self.deadline = 0.0
        self.events = []               # upload: per-stream lists of (t_done, bytes) -- see _completion_mbps
        self.last_t = None             # perf_counter() of the most recent byte counted
        self.allowed = 10 ** 6         # streams still allowed to run (cut in half when the target says 429/503)
        self.rate_limited = 0          # how many 429/503 answers the target gave in this phase
        self._last_cut = 0.0

    def backoff(self, idx, retry_after):
        """The target answered 429/503. Returns seconds to wait before retrying, or None if this stream
        should retire (the phase continues with fewer streams, hammering a limiter only makes it stricter)."""
        with self.lock:
            self.rate_limited += 1
            now = time.perf_counter()
            if now - self._last_cut >= 1.0:           # halve at most once a second, not once per stream
                self.allowed = max(1, min(self.allowed, self.connections or 1) // 2)
                self._last_cut = now
            if idx >= self.allowed:
                return None
            n = min(self.rate_limited, 4)
        return min(3.0, retry_after if retry_after else 0.4 * (2 ** n))

    def add(self, n):
        with self.lock:
            self.total += n
            self.last_t = time.perf_counter()

    def snapshot(self):
        with self.lock:
            return self.total

    def register(self, conn):
        with self.lock:
            self.conns.append(conn)
            self.connections += 1

    def unregister(self, conn):
        with self.lock:
            try:
                self.conns.remove(conn)
            except ValueError:
                pass

    def error(self, exc):
        with self.lock:
            self.errors += 1
            self.last_error = f"{type(exc).__name__}: {exc}"[:200]

    def running(self):
        return (not self.stop.is_set()) and time.perf_counter() < self.deadline

    def close_all(self):
        with self.lock:
            conns = list(self.conns)
        for c in conns:
            _interrupt(c)


def _download_worker(ph, idx=0):
    conn, bad_in_a_row = None, 0
    try:
        while ph.running():
            try:
                if conn is None:
                    conn = _new_connection(ph.target, ph.timeout)
                    ph.register(conn)
                method, path = ph.target.down_request(ph.chunk)
                conn.request(method, path, headers={"User-Agent": _UA})
                r = conn.getresponse()
                if r.status != 200:
                    raise _HttpStatus.from_response(r)
                while not ph.stop.is_set() and time.perf_counter() < ph.deadline:
                    data = r.read(65536)
                    if not data:
                        break                      # chunk finished: loop and reuse the SAME connection
                    ph.add(len(data))
                bad_in_a_row = 0
                if not ph.running():
                    break
            except Exception as e:                 # OSError / HTTPException / _HttpStatus / a close race at the deadline
                if ph.stop.is_set():
                    break
                ph.error(e)
                if isinstance(e, _HttpStatus) and e.status in (429, 503):
                    if conn is not None:
                        ph.unregister(conn)
                        _hard_close(conn)
                        conn = None
                    wait = ph.backoff(idx, e.retry_after)
                    if wait is None:
                        break                      # this stream retires; the others carry on
                    if ph.stop.wait(wait):
                        break
                    continue
                bad_in_a_row += 1
                if conn is not None:
                    ph.unregister(conn)
                    _hard_close(conn)
                    conn = None
                if bad_in_a_row >= 4:
                    break
                time.sleep(0.15)
    finally:
        if conn is not None:
            ph.unregister(conn)
            _hard_close(conn)


def _upload_worker(ph, idx=0):
    """
    Upload bytes count only when the SERVER HAS ANSWERED a whole request -- i.e. it has really
    received them. Counting "bytes handed to the socket" instead would be wrong: the kernel
    swallows megabytes into send buffers instantly, which on a slow uplink inflates the
    result by tens of percent (this is why real speed tests count at the receiving end).
    Each completion is recorded as (time, bytes) for _completion_mbps(). Request size adapts
    so a request takes roughly half a second on whatever link this is: 64 KB on a crawl,
    16 MB on a fast line.
    """
    piece = os.urandom(65536)
    chunk = max(65536, int(ph.chunk))
    events = ph.events[idx]
    conn, bad_in_a_row = None, 0
    try:
        while ph.running():
            try:
                if conn is None:
                    conn = _new_connection(ph.target, ph.timeout)
                    ph.register(conn)
                method, path = ph.target.up_request()
                t_req = time.perf_counter()
                conn.putrequest(method, path)
                conn.putheader("Content-Type", "application/octet-stream")
                conn.putheader("Content-Length", str(chunk))
                conn.putheader("User-Agent", _UA)
                conn.endheaders()
                sent = 0
                while sent < chunk and not ph.stop.is_set() and time.perf_counter() < ph.deadline:
                    n = min(len(piece), chunk - sent)
                    conn.send(piece if n == len(piece) else piece[:n])
                    sent += n
                if sent < chunk:
                    break                          # cut short by the deadline: we are done
                r = conn.getresponse()
                r.read()
                if r.status >= 400:
                    raise _HttpStatus.from_response(r)
                t_done = time.perf_counter()
                ph.add(chunk)                      # acknowledged by the server: now it counts
                events.append((t_done - ph.t0, chunk))
                took = t_done - t_req
                if took < 0.3:
                    chunk = min(chunk * 2, 16_000_000)
                elif took > 0.9:
                    chunk = max(chunk // 2, 65536)
                bad_in_a_row = 0
            except Exception as e:
                if ph.stop.is_set():
                    break
                ph.error(e)
                if isinstance(e, _HttpStatus) and e.status in (429, 503):
                    if conn is not None:
                        ph.unregister(conn)
                        _hard_close(conn)
                        conn = None
                    wait = ph.backoff(idx, e.retry_after)
                    if wait is None:
                        break                      # this stream retires; the others carry on
                    if ph.stop.wait(wait):
                        break
                    continue
                bad_in_a_row += 1
                if conn is not None:
                    ph.unregister(conn)
                    _hard_close(conn)
                    conn = None
                if bad_in_a_row >= 4:
                    break
                time.sleep(0.15)
    finally:
        if conn is not None:
            ph.unregister(conn)
            _hard_close(conn)


def _sampler(ph, samples, progress_cb, phase_name):
    """
    Every ~0.1 s record (t, bytes). Every ~0.2 s report a live rate for the gauge: the average
    over a short sliding window (1 s download / 1.5 s upload), then lightly smoothed -- steady
    enough to look right on a needle, quick enough to follow a real change.
    """
    window = 1.5 if ph.kind == "upload" else 1.0
    ema, last_emit, lo = None, 0.0, 0
    while not ph.stop.wait(0.1):
        t = time.perf_counter() - ph.t0
        b = ph.snapshot()
        samples.append((t, b))
        while lo < len(samples) - 1 and samples[lo + 1][0] <= t - window:
            lo += 1
        if t >= 0.5 and t - last_emit >= 0.2:
            t_old, b_old = samples[lo]
            span = t - t_old
            if span >= 0.3:
                inst = (b - b_old) * 8 / (span * 1_000_000)
                ema = inst if ema is None else ema + 0.5 * (inst - ema)
                last_emit = t
                if progress_cb is not None:
                    try:
                        progress_cb(phase_name, round(ema, 2), round(t, 1))
                    except Exception:
                        pass


def _bytes_at(points, t):
    """Bytes delivered at time t, linearly interpolated from (time, bytes) points."""
    prev = None
    for pt in points:
        if pt[0] >= t:
            if prev is None:
                return pt[1]
            (t0, b0), (t1, b1) = prev, pt
            return b0 if t1 <= t0 else b0 + (b1 - b0) * ((t - t0) / (t1 - t0))
        prev = pt
    return prev[1] if prev else None


def _window_mbps(samples, t_end, b_end, duration):
    """Average rate over [warm-up, deadline]. The window ENDS at the deadline -- never later."""
    if b_end <= 0:
        return None
    warm = min(2.0, duration * 0.25)                 # skip TCP slow-start ramp
    points = sorted(list(samples) + [(t_end, b_end)])
    b_warm = _bytes_at(points, warm)
    dt = t_end - warm
    if b_warm is None or dt <= 0.2:
        return None
    return max(0.0, (b_end - b_warm) * 8 / (dt * 1_000_000))


def _completion_mbps(events_by_stream, warm, t_end):
    """
    Upload rate from completion events. For each stream, bytes of the requests that COMPLETED
    between its first and last completion in the window, divided by the time between those two
    completions -- the two ends of the interval are real events, so a request that was half-way
    done when the window opened (or is half-way done at the deadline) cannot distort the answer.
    The per-stream rates are summed. None if too few streams produced two completions.
    """
    total, used = 0.0, 0
    for ev in events_by_stream:
        inwin = [(t, n) for (t, n) in ev if warm <= t <= t_end]
        if len(inwin) >= 2 and inwin[-1][0] - inwin[0][0] > 0.05:
            span = inwin[-1][0] - inwin[0][0]
            total += sum(n for _, n in inwin[1:]) * 8 / (span * 1_000_000)
            used += 1
    if used == 0 or used < max(1, len(events_by_stream) // 2):
        return None
    return total


def _run_phase(kind, target, duration, streams, chunk_bytes, timeout, progress_cb=None, phase_name=None):
    """
    Run one download or upload phase. Returns
      {"mbps": float|None, "connections": int, "errors": int, "last_error": str, "elapsed": float}
    Always returns within ~duration + 2 s, whatever the link or server does.
    """
    phase_name = phase_name or kind
    if progress_cb is not None:                      # tell the page this phase has begun (0 Mbps) so the dial switches at once
        try:
            progress_cb(phase_name, 0.0, 0.0)
        except Exception:
            pass
    ph = _Phase(kind, target, duration, chunk_bytes, timeout)
    worker = _download_worker if kind == "download" else _upload_worker
    samples = []
    ph.t0 = time.perf_counter()
    ph.deadline = ph.t0 + duration
    ph.events = [[] for _ in range(streams)]
    ph.allowed = streams
    threads = [threading.Thread(target=worker, args=(ph, i), daemon=True) for i in range(streams)]
    sampler = threading.Thread(target=_sampler, args=(ph, samples, progress_cb, phase_name), daemon=True)
    sampler.start()
    for th in threads:
        th.start()

    while True:                                      # wait for the deadline (or for every worker to give up)
        now = time.perf_counter()
        if now >= ph.deadline or not any(th.is_alive() for th in threads):
            break
        time.sleep(min(0.05, ph.deadline - now))

    t_end = time.perf_counter() - ph.t0
    b_end = ph.snapshot()                            # freeze the numbers BEFORE tearing anything down
    ph.stop.set()
    ph.close_all()
    join_by = time.perf_counter() + 2.0
    for th in threads:
        th.join(max(0.0, join_by - time.perf_counter()))
    sampler.join(1.0)

    # Every connection gave up before the deadline? Then measure up to the last byte that actually
    # arrived -- dividing by the dead time after the connections dropped would silently deflate it --
    # and flag the phase as early so the caller can say so.
    early = t_end < duration - 0.5
    t_calc = t_end
    if early and ph.last_t is not None:
        t_calc = min(t_end, max(0.0, ph.last_t - ph.t0))
    mbps = None
    if kind == "upload":
        mbps = _completion_mbps(ph.events, min(2.0, duration * 0.25), t_calc)
    if mbps is None:                                 # download, or an upload too slow for completion events
        mbps = _window_mbps(samples, t_calc, b_end, duration)
    if progress_cb is not None and mbps is not None:
        try:
            progress_cb(phase_name, round(mbps, 2), round(t_end, 1))
        except Exception:
            pass
    return {"mbps": None if mbps is None else round(mbps, 2), "connections": ph.connections,
            "errors": ph.errors, "last_error": ph.last_error, "elapsed": round(t_end, 1), "early": early,
            "rate_limited": ph.rate_limited}


# ─────────────────────────────────────────────────────────────────────────────
#  Latency / jitter / target identity -- measured against the SAME host as the test
# ─────────────────────────────────────────────────────────────────────────────
def _jitter_ms(samples: list) -> float:
    """Mean absolute difference between consecutive latency samples (RFC-3550 style approximation)."""
    if len(samples) < 2:
        return 0.0
    diffs = [abs(samples[i] - samples[i - 1]) for i in range(1, len(samples))]
    return round(sum(diffs) / len(diffs), 1)


def _measure_latency(target, samples=8, timeout=4.0):
    """
    (median HTTP round-trip in ms, jitter in ms, meta) to the host that carries the test, or
    (None, 0.0, {}). `meta` is whatever cf-meta-* headers Cloudflare put on the answer -- colo (data
    centre), city, country, ip, asn -- read from the probe we send anyway.
    """
    rtts, meta, conn = [], {}, None
    try:
        conn = _new_connection(target, timeout)
        for i in range(samples + 1):
            method, path = target.ping_request()
            t0 = time.perf_counter()
            conn.request(method, path, headers={"User-Agent": _UA})
            r = conn.getresponse()
            r.read()
            if i == 0:
                meta = {k[8:].lower(): v for k, v in r.getheaders() if k.lower().startswith("cf-meta-")}
            if i > 0:                                # the first request pays TCP+TLS set-up; it is not the RTT
                rtts.append((time.perf_counter() - t0) * 1000.0)
    except Exception as e:
        log.debug("latency probe to %s failed: %s", target.host, e)
    finally:
        if conn is not None:
            _hard_close(conn)
    if not rtts:
        return None, 0.0, {}
    return round(statistics.median(rtts), 1), _jitter_ms(rtts), meta


def _cloudflare_trace(target, timeout=4.0):
    """Best effort: which Cloudflare data centre (colo) we actually reach, and our IP as it sees it."""
    conn = None
    try:
        conn = _new_connection(target, timeout)
        conn.request("GET", "/cdn-cgi/trace", headers={"User-Agent": _UA})
        txt = conn.getresponse().read(4096).decode("utf-8", "replace")
        return dict(line.split("=", 1) for line in txt.splitlines() if "=" in line)
    except Exception as e:
        log.debug("cloudflare trace failed: %s", e)
        return {}
    finally:
        if conn is not None:
            _hard_close(conn)


def _latency_ms(host="1.1.1.1", port=443, samples=5):
    """TCP connect latency in ms (average) + raw samples. Used for speedtest-cli jitter."""
    times = []
    for _ in range(samples):
        try:
            t0 = time.perf_counter()
            s = socket.create_connection((host, port), timeout=3)
            s.close()
            times.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
    if not times:
        return None, []
    return round(sum(times) / len(times), 1), times


def _public_ip_and_isp(timeout=5):
    """Public-facing IP and ISP/organisation name (ipapi.co, with a plain-IP fallback)."""
    try:
        req = urllib.request.Request("https://ipapi.co/json/", headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            info = json.loads(r.read().decode("utf-8", errors="replace"))
        ip = info.get("ip", "")
        isp = info.get("org") or info.get("asn") or ""
        if ip:
            return ip, (isp or "Unknown ISP")
    except Exception as e:
        log.debug("ipapi.co lookup failed: %s", e)
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ip = r.read().decode("utf-8", errors="replace").strip()
        return ip, "Unknown ISP"
    except Exception as e:
        log.debug("ipify fallback failed: %s", e)
        return "", "Unknown ISP"


# ─────────────────────────────────────────────────────────────────────────────
#  Engine 1: speedtest-cli (third-party; unchanged behaviour, now time-limited)
# ─────────────────────────────────────────────────────────────────────────────
def _std_streams_usable():
    """speedtest-cli touches sys.stdout.fileno() while importing. A Windows service (pythonw.exe) has no
    console, so the stream is None or fileno() fails. Do NOT patch sys.stdout/stderr globally (V10.7 owner
    patch broke service startup); just report whether the third-party engine can run here."""
    for name in ("stdin", "stdout", "stderr"):
        st = getattr(sys, name, None)
        if st is None:
            return False
        try:
            if st.fileno() < 0:
                return False
        except Exception:
            return False
    return True


def _try_speedtest_cli(progress_cb=None, timeout=_CLI_TIMEOUT):
    if not _std_streams_usable():
        log.info("speedtest-cli skipped: no usable console streams (running as a service); using the built-in test")
        return None
    try:
        import speedtest as st_lib
    except ImportError:
        return None
    except Exception as e:                     # e.g. fileno() errors inside the library at import time
        log.warning("speedtest-cli could not be imported (%s); using the built-in test", e)
        return None

    def _say(phase):
        if progress_cb is not None:
            try:
                progress_cb(phase, None, 0.0)
            except Exception:
                pass

    holder = {"result": None, "error": None, "st": None}

    def _run():
        try:
            st = st_lib.Speedtest(secure=True)
            holder["st"] = st
            _say("ping")
            st.get_best_server()
            _say("download")
            dl = round(st.download() / 1_000_000, 2)
            _say("upload")
            ul = round(st.upload() / 1_000_000, 2)
            srv = st.results.server
            label = (str(srv.get("sponsor", "")) + " " + str(srv.get("name", ""))).strip()
            holder["result"] = (dl, ul, round(st.results.ping, 1), label, str(srv.get("host", "")))
        except Exception as e:
            holder["error"] = e

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(timeout)
    # ... rest of function remains unchanged
    if th.is_alive():
        try:
            holder["st"]._shutdown_event.set()        # ask its worker threads to stop
        except Exception:
            pass
        log.warning("speedtest-cli did not finish within %.0f s; using the built-in test instead", timeout)
        return None
    if holder["error"] is not None:
        # WARNING (not debug): this line is the only trail showing why the third-party engine was skipped
        log.warning("speedtest-cli unavailable, falling back to the built-in test: %s", holder["error"])
        return None
    return holder["result"]


# ─────────────────────────────────────────────────────────────────────────────
#  Engine 2: built-in HTTP test
# ─────────────────────────────────────────────────────────────────────────────
def _test_target(target, progress_cb, info_cb):
    """Run a full test against one target. Returns a result dict, or None if the target is unusable."""
    def _info(**kw):
        if info_cb is not None:
            try:
                info_cb(kw)
            except Exception:
                pass

    if progress_cb is not None:
        try:
            progress_cb("ping", None, 0.0)
        except Exception:
            pass
    _info(engine="Built-in test", target=target.name)
    lat, jitter, meta = _measure_latency(target)
    if lat is None:
        log.warning("speed test target %s (%s) did not answer; skipping it", target.name, target.host)
        return None
    colo, city, trace_ip = meta.get("colo", ""), meta.get("city", ""), meta.get("ip", "")
    if target.kind == "cloudflare" and not colo:
        trace = _cloudflare_trace(target)                # older/other edge: fall back to /cdn-cgi/trace
        colo, trace_ip = trace.get("colo", ""), trace_ip or trace.get("ip", "")
    where = (colo + (f" · {city}" if city and colo else "")) if target.kind == "cloudflare" else ""
    label = target.name + (f" ({where})" if where else "")
    _info(engine="Built-in test", target=label, rtt_ms=lat)

    dl = _run_phase("download", target, _DL_SECONDS, _DL_STREAMS, _DL_CHUNK, _SOCK_TIMEOUT, progress_cb, "download")
    ul = _run_phase("upload", target, _UL_SECONDS, _UL_STREAMS, _UL_CHUNK, _SOCK_TIMEOUT, progress_cb, "upload")
    global _LAST_RATE_LIMITED_AT
    if dl.get("rate_limited") or ul.get("rate_limited"):
        _LAST_RATE_LIMITED_AT = time.time()
    if dl["mbps"] is None and ul["mbps"] is None:
        log.warning("speed test target %s: no data moved (download: %s | upload: %s)",
                    target.name, dl["last_error"] or "no bytes", ul["last_error"] or "no bytes")
        return None
    warn = []
    for label_, ph_ in (("Download", dl), ("Upload", ul)):
        if ph_.get("rate_limited"):
            _LAST_RATE_LIMITED_AT = time.time()
            warn.append(f"{label_}: {target.name} rate-limited this network ({ph_['rate_limited']} x HTTP 429/503); Net-monit slowed down and used fewer connections, so this figure can read low. Wait 5-10 minutes between tests")
        elif ph_["mbps"] is None:
            warn.append(f"{label_} could not be measured" + (f" ({ph_['last_error']})" if ph_["last_error"] else ""))
        elif ph_["early"]:
            warn.append(f"{label_} ended early after {ph_['elapsed']} s — the connections were dropped, so treat this figure as a minimum")
        elif ph_["errors"] >= 3:
            warn.append(f"{label_} had {ph_['errors']} connection errors during the test")
    return {"download_mbps": dl["mbps"], "upload_mbps": ul["mbps"], "latency_ms": lat, "jitter_ms": jitter,
            "server": label, "method_used": "cloudflare" if target.kind == "cloudflare" else "librespeed",
            "streams_dl": dl["connections"], "streams_ul": ul["connections"],
            "colo": colo, "trace_ip": trace_ip, "host": target.host,
            "warning": "; ".join(warn)}


def _cloudflare_note(res):
    return (f"Measured to Cloudflare{' ' + res['colo'] if res.get('colo') else ''} (round trip {res['latency_ms']} ms) — "
            "the route from this network to Cloudflare, not to an on-net ISP server. "
            "speedtest.net measures to a server inside your ISP, so on some ISPs it reads higher. "
            "To test against a nearby server instead, see speedtest.targets in config.yaml (Setup Guide).")


def check(device: dict, progress_cb=None, info_cb=None) -> dict:
    """
    Run the speed test. Returns:
      reachable, download_mbps, upload_mbps (float, or None if that direction failed),
      latency_ms, jitter_ms, isp, public_ip, server, method_used, elapsed_sec,
      note (what was measured, and against what), warning (something only partly worked),
      streams_dl / streams_ul / colo (built-in test only)
    progress_cb(phase, mbps_or_None, elapsed) -- phase: ping | download | upload
    info_cb({...}) -- engine / target / rtt_ms as they become known
    """
    t0 = time.perf_counter()
    cfg = _speedtest_config()
    engine = str(os.environ.get("NETMON_SPEEDTEST_ENGINE") or cfg.get("engine") or "auto").strip().lower()   # V12.4: auto = nearby ISP server first, Cloudflare second
    if engine not in ("auto", "builtin"):
        log.warning("speedtest.engine %r not recognised (use auto or builtin); using builtin", engine)
        engine = "builtin"

    ip_isp = [None, None]
    def _lookup():
        ip_isp[0], ip_isp[1] = _public_ip_and_isp()
    ip_thread = threading.Thread(target=_lookup, daemon=True)
    ip_thread.start()

    def _finish(res):
        ip_thread.join(timeout=6)
        res.setdefault("reachable", True)
        res["isp"] = ip_isp[1] or "Unknown ISP"
        res["public_ip"] = ip_isp[0] or res.pop("trace_ip", "") or ""
        res.pop("trace_ip", None)
        res["elapsed_sec"] = round(time.perf_counter() - t0, 1)
        return res

    # 1 ── speedtest-cli (skipped when engine = builtin)
    if engine == "auto":
        if info_cb is not None:
            try: info_cb({"engine": "speedtest-cli", "target": ""})
            except Exception: pass
        cli = _try_speedtest_cli(progress_cb)
        if cli:
            dl, ul, lat, label, host = cli
            jitter = 0.0
            try:
                h, _, p = host.partition(":")
                if h:
                    _, raw = _latency_ms(h, int(p) if p.isdigit() else 80, samples=6)
                    jitter = _jitter_ms(raw)
            except Exception:
                pass
            return _finish({"download_mbps": dl, "upload_mbps": ul, "latency_ms": lat, "jitter_ms": jitter,
                            "server": label or "Speedtest.net", "method_used": "speedtest-cli",
                            "note": f"Measured with speedtest-cli against {label or 'a Speedtest.net server'}.",
                            "warning": ""})

    # 2 ── built-in test: configured targets first (in the order listed), then Cloudflare
    targets = _configured_targets(cfg) + [_cloudflare_target()]
    cli_tried = (engine == "auto")
    for target in targets:
        res = _test_target(target, progress_cb, info_cb)
        if res is not None and res.get("download_mbps") is None and not cli_tried:
            # V12.4: the target answered (upload/ping worked) but gave no download -- Cloudflare rate-limiting (HTTP 429/503) is the usual reason.
            # Try the Speedtest.net engine instead of showing "--".
            cli_tried = True
            if info_cb is not None:
                try: info_cb({"engine": "speedtest-cli", "target": ""})
                except Exception: pass
            cli = _try_speedtest_cli(progress_cb)
            if cli:
                dl, ul, lat, label, host = cli
                return _finish({"download_mbps": dl, "upload_mbps": ul, "latency_ms": lat, "jitter_ms": 0.0, "server": label or "Speedtest.net",
                                "method_used": "speedtest-cli", "warning": "",
                                "note": f"Measured with speedtest-cli against {label or 'a Speedtest.net server'} (the Cloudflare test was rate-limited, so Net-monit switched engine)."})
        if res is not None:
            res["note"] = (_cloudflare_note(res) if target.kind == "cloudflare"
                           else f"Measured against {res['server']} ({res['host']}), round trip {res['latency_ms']} ms.")
            return _finish(res)

    limited_recently = (time.time() - _LAST_RATE_LIMITED_AT) < 120
    return _finish({"reachable": False,
                    "error": ("Speed test target is rate-limiting this network (HTTP 429). Wait 5-10 minutes and run ONE test; "
                              "repeated tests make the limit last longer"
                              if limited_recently else
                              "Speed test failed — no internet access or every test server was unreachable"),
                    "download_mbps": None, "upload_mbps": None, "latency_ms": None, "jitter_ms": 0.0,
                    "server": "", "method_used": "", "note": "", "warning": ""})


# ─────────────────────────────────────────────────────────────────────────────
#  Kept for continuity (older tests / docs call these names)
# ─────────────────────────────────────────────────────────────────────────────
def _cloudflare_download_mbps(target_duration=_DL_SECONDS, chunk_bytes=_DL_CHUNK, timeout=_SOCK_TIMEOUT,
                               progress_cb=None, streams=_DL_STREAMS):
    cb = None if progress_cb is None else (lambda ph, mbps, el: mbps is not None and progress_cb(mbps, el))
    return _run_phase("download", _cloudflare_target(), target_duration, streams, chunk_bytes, timeout, cb)["mbps"]


def _cloudflare_upload_mbps(target_duration=_UL_SECONDS, chunk_bytes=_UL_CHUNK, timeout=_SOCK_TIMEOUT,
                             progress_cb=None, streams=_UL_STREAMS):
    cb = None if progress_cb is None else (lambda ph, mbps, el: mbps is not None and progress_cb(mbps, el))
    return _run_phase("upload", _cloudflare_target(), target_duration, streams, chunk_bytes, timeout, cb)["mbps"]
