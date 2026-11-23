"""Net-monit V12.4 -- Speed-test diagnostic. Run with the SAME Python that runs Net-monit (Diagnose-SpeedTest.bat does this).
Shows, step by step, where the WAN download test fails: DNS, TCP 443, TLS (strict and relaxed), a 1 MB download, then the real test."""
import os, sys, ssl, socket, time, json, subprocess, http.client, urllib.request
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
H = "speed.cloudflare.com"
def step(n, t): print(f"\n[{n}] {t}")
def ok(m): print("    OK   " + m)
def bad(m): print("    FAIL " + m)
print("Net-monit speed-test diagnostic")
print("Python      :", sys.version.split()[0], "|", sys.executable)
print("OpenSSL     :", ssl.OPENSSL_VERSION)
print("Strict TLS  :", "ON by default in this Python (3.13+)" if hasattr(ssl, "VERIFY_X509_STRICT") and (ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT) else "off")
print("Proxy env   :", {k: v for k, v in os.environ.items() if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")} or "none")
if os.name == "nt":
    try: print("WinHTTP     :", " ".join(subprocess.run(["netsh", "winhttp", "show", "proxy"], capture_output=True, text=True).stdout.split()))
    except Exception: pass
step(1, "DNS " + H)
try: ip = socket.gethostbyname(H); ok(ip)
except Exception as e: bad(str(e)); print("    -> DNS cannot resolve it. Check DNS server / firewall DNS filtering."); sys.exit(1)
step(2, "TCP 443")
try: socket.create_connection((ip, 443), 6).close(); ok("connected")
except Exception as e: bad(str(e)); print("    -> Outbound 443 to Cloudflare is blocked for this program/account."); sys.exit(1)
def tls(strict):
    ctx = ssl.create_default_context()
    if not strict: ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    c = http.client.HTTPSConnection(H, 443, timeout=8, context=ctx); c.request("GET", "/__down?bytes=1000000", headers={"User-Agent": "netmonit-diag"}); r = c.getresponse(); n = 0
    while True:
        d = r.read(65536)
        if not d: break
        n += len(d)
    return r.status, n
res = {}
for strict in (True, False):
    step(3 if strict else 4, "TLS + 1 MB download, certificate checks " + ("STRICT (Python default)" if strict else "relaxed (what Net-monit V12.4 patch 01 uses)"))
    try: st, n = tls(strict); res[strict] = (st == 200 and n > 900000); (ok if res[strict] else bad)(f"HTTP {st}, {n} bytes")
    except Exception as e: res[strict] = False; bad(f"{type(e).__name__}: {e}")
if not res[True] and res[False]: print("    -> Strict TLS was the cause: a firewall/proxy re-signs HTTPS with a certificate Python 3.13+ rejects. Patch 01 fixes it.")
if not res[True] and not res[False]: print("    -> TLS fails even relaxed: look at the message above (certificate chain of your inspecting firewall must be in the Windows certificate store, or Cloudflare is blocked).")
step(5, "Net-monit's own speed test (about 25 seconds)")
try:
    from monitor.checkers.speedtest_check import check
    t0 = time.time(); r = check({}, progress_cb=lambda ph, mbps, el: print(f"    {ph:9s} {mbps if mbps is not None else '...'} Mbit/s", end="\r"))
    print(); print("    result:", json.dumps({k: r.get(k) for k in ("download_mbps", "upload_mbps", "latency_ms", "server", "method_used", "warning", "error")}) if r else "None (all targets failed: see logs\\service.log)")
except Exception as e: bad(f"{type(e).__name__}: {e}")
print("\nIf everything above is OK but the web page still shows no download, the Windows SERVICE environment differs from your user account")
print("(proxy settings are per user). Send the full text of this window plus the last 40 lines of logs\\service.log.")
