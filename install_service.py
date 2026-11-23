# =============================================================================
# Net-monit V12.4 -- Windows Service Manager
# Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com
# Contact: abuabdullah.be@outlook.com
# Dashboard: http://localhost:5050  (default port — can be overridden)
# =============================================================================
"""
install_service.py  --  Net-monit V12.4

Port and service name are read from environment variables so the setup
wizard can pass user-chosen values without modifying this file:
    NETMON_PORT      default 5050
    NETMON_SVC_NAME  default Net_Monit_V124

Usage (run as Administrator from the install directory):
    python install_service.py install
    python install_service.py start
    python install_service.py stop
    python install_service.py restart
    python install_service.py remove
    python install_service.py status
    python install_service.py debug
"""
import os, sys, time, threading, logging, subprocess

# V10.8: a Windows service runs under pythonw.exe -> sys.stdin/stdout/stderr are None. Give them real,
# fileno()-capable null files here, ONCE, before any library is imported. (Libraries such as
# speedtest-cli, click and werkzeug assume real streams.) Never do this inside a checker module.
for _n, _mode in (("stdin", "r"), ("stdout", "w"), ("stderr", "w")):
    if getattr(sys, _n, None) is None:
        try:
            setattr(sys, _n, open(os.devnull, _mode, encoding="utf-8"))
        except Exception:
            pass

APP_VERSION  = "12.4"
# --- Read from env so wizard can override without changing this file ---
APP_PORT     = int(os.environ.get("NETMON_PORT",     5050))
SVC_NAME     = os.environ.get("NETMON_SVC_NAME",     "Net_Monit_V124")
SVC_DISPLAY  = os.environ.get("NETMON_SVC_DISPLAY",  f"Net-monit V{APP_VERSION} Network Monitor")
# -----------------------------------------------------------------------
SVC_DESC     = f"Net-monit V{APP_VERSION} dashboard at http://localhost:{APP_PORT}"
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
LOG_FILE     = os.path.join(BASE_DIR, "logs", "service.log")

os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("netmonit.service")

try:
    import win32serviceutil, win32service, win32event, servicemanager, pywintypes
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


# ── Bootstrap ─────────────────────────────────────────────────────────────
def _bootstrap():
    """Start app in daemon thread. Returns the thread."""
    if BASE_DIR not in sys.path:
        sys.path.insert(0, BASE_DIR)
    os.chdir(BASE_DIR)

    from monitor import database as db
    from monitor import config_manager
    from monitor import scheduler as sched
    from monitor import auth
    from monitor.license import license_manager
    from app import app as flask_app

    db.init_db()
    auth.seed_default_admin_if_empty()
    license_manager.refresh()
    cfg = config_manager.load_config()

    # Use config.yaml port if set, else fall back to APP_PORT
    port = cfg.get("server", {}).get("port", APP_PORT)

    sched.start_scheduler(cfg)
    try:
        import app as _appmod
        _appmod.traffic_startup()                      # V12: the service does not call initialize(), so start the Traffic Analyzer here
    except Exception:
        log.exception("Traffic Analyzer startup failed (the rest of Net-monit keeps running)")

    # V12: a port that Windows reserves (Hyper-V/WSL/Docker excluded ranges) or that another program holds used to stop the service.
    from monitor import portcheck
    chosen, why = portcheck.pick_port(port)
    if why:
        log.warning("%s", why)
    port = chosen
    portcheck.remember(BASE_DIR, port)
    try:
        import app as _appmod2
        _appmod2.APP_PORT = port
    except Exception:
        pass

    ssl_ctx  = None
    ssl_cert = os.environ.get("NETMON_SSL_CERT", "")
    ssl_key  = os.environ.get("NETMON_SSL_KEY",  "")
    if ssl_cert and ssl_key and os.path.isfile(ssl_cert):
        import ssl as _ssl
        ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(ssl_cert, ssl_key)

    def _serve():
        try:
            flask_app.run(host="0.0.0.0", port=port, debug=False,
                          use_reloader=False, ssl_context=ssl_ctx)
        except BaseException:
            log.exception("Flask server crashed (port %s) -- the dashboard is NOT running", port)
            raise

    t = threading.Thread(target=_serve, daemon=True, name="flask")
    t.start()
    log.info("Net-monit V%s | http://localhost:%s | license=%s | devices=%d",
             APP_VERSION, port, license_manager.state,
             len(cfg.get("devices", [])))
    return t


# ── Service class ─────────────────────────────────────────────────────────
if HAS_WIN32:
    class NetMonitService(win32serviceutil.ServiceFramework):
        # These are read at class-definition time from env vars
        _svc_name_         = SVC_NAME
        _svc_display_name_ = SVC_DISPLAY
        _svc_description_  = SVC_DESC
        _svc_reg_class_    = \
            f"{os.path.splitext(os.path.basename(__file__))[0]}.NetMonitService"

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            log.info("Stop signal received")

        def SvcDoRun(self):
            # Report RUNNING immediately — prevents SCM Error 1053 timeout
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            log.info("SvcDoRun | svc=%s port=%s", SVC_NAME, APP_PORT)
            try:
                flask_thread = _bootstrap()
                while True:
                    rc = win32event.WaitForSingleObject(self._stop_event, 5000)
                    if rc == win32event.WAIT_OBJECT_0:
                        break
                    if not flask_thread.is_alive():
                        log.error("Flask thread ended unexpectedly; stopping so the Windows recovery action restarts the service")
                        raise RuntimeError("web server thread died")
            except Exception as exc:
                log.exception("Service error")
                servicemanager.LogErrorMsg(f"{SVC_NAME}: {exc}")
                raise
            log.info("Service stopped")


# ── Python executable resolution ─────────────────────────────────────────
def _get_python_exe():
    """Return pythonw.exe — prefers venv, then system python."""
    venv_w = os.path.join(BASE_DIR, "venv", "Scripts", "pythonw.exe")
    venv_p = os.path.join(BASE_DIR, "venv", "Scripts", "python.exe")
    if os.path.isfile(venv_w): return venv_w
    if os.path.isfile(venv_p): return venv_p
    exe = sys.executable
    w   = exe.replace("python.exe", "pythonw.exe")
    return w if os.path.isfile(w) else exe


# ── sc.exe registration ───────────────────────────────────────────────────
def _register_via_sc(python_exe, port, svc_name, svc_display):
    """Register service via sc.exe with explicit pythonw.exe + PYTHONPATH env."""
    this_script = os.path.abspath(__file__)
    svc_cmd     = f'"{python_exe}" "{this_script}"'
    svc_desc    = f"Net-monit V{APP_VERSION} dashboard at http://localhost:{port}"

    # Create
    r = subprocess.run(
        ["sc.exe", "create", svc_name,
         f"binpath={svc_cmd}",
         "start=delayed-auto",
         f"DisplayName={svc_display}"],
        capture_output=True, text=True,
    )
    if r.returncode not in (0, 1073):  # 1073 = already exists
        raise RuntimeError(f"sc create failed ({r.returncode}): {r.stdout} {r.stderr}")

    subprocess.run(["sc.exe", "config",      svc_name, "start=delayed-auto"], capture_output=True)
    subprocess.run(["sc.exe", "description", svc_name, svc_desc],            capture_output=True)
    subprocess.run(["sc.exe", "failure",     svc_name, "reset=", "86400",
                    "actions=", "restart/5000/restart/10000/restart/30000"],  capture_output=True)

    # Write PYTHONPATH + port into service registry Environment
    try:
        import winreg
        venv_site = os.path.join(BASE_DIR, "venv", "Lib", "site-packages")
        py_path   = [BASE_DIR]
        if os.path.isdir(venv_site):
            py_path.append(venv_site)

        reg_path = f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}"
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, reg_path, 0,
            winreg.KEY_SET_VALUE | winreg.KEY_READ,
        )
        winreg.SetValueEx(key, "Environment", 0, winreg.REG_MULTI_SZ, [
            f"PYTHONPATH={os.pathsep.join(py_path)}",
            f"NETMON_PORT={port}",
            f"NETMON_SVC_NAME={svc_name}",
            f"NETMON_SVC_DISPLAY={svc_display}",
        ])
        winreg.SetValueEx(key, "DelayedAutoStart", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        log.info("Registry env set: port=%s svc=%s python_path=%s", port, svc_name, py_path)
    except Exception as e:
        log.warning("Could not write registry env: %s", e)


def _remove_via_sc(svc_name):
    subprocess.run(["sc.exe", "stop",   svc_name], capture_output=True)
    time.sleep(2)
    r = subprocess.run(["sc.exe", "delete", svc_name], capture_output=True, text=True)
    return r.returncode == 0


def _start_and_wait(svc_name, timeout=35):
    subprocess.run(["sc.exe", "start", svc_name], capture_output=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(2)
        r = subprocess.run(["sc.exe", "query", svc_name], capture_output=True, text=True)
        if "RUNNING"  in r.stdout: return True
        if "FAILED"   in r.stdout: return False
    return False


def _status(svc_name):
    r = subprocess.run(["sc.exe", "query", svc_name], capture_output=True, text=True)
    print(r.stdout if r.returncode == 0 else f"Service '{svc_name}' not found.")
    print(f"Install : {BASE_DIR}")
    print(f"Port    : {APP_PORT}  (env NETMON_PORT)")
    print(f"SvcName : {SVC_NAME}  (env NETMON_SVC_NAME)")
    print(f"Log     : {LOG_FILE}")


def _debug():
    log.info("DEBUG mode | http://localhost:%s", APP_PORT)
    t = _bootstrap()
    try:
        while t.is_alive(): time.sleep(1)
    except KeyboardInterrupt:
        log.info("Stopped")


# ── Main ─────────────────────────────────────────────────────────────────
def main():
    if BASE_DIR not in sys.path:
        sys.path.insert(0, BASE_DIR)
    os.chdir(BASE_DIR)

    cmd = sys.argv[1].lower().strip() if len(sys.argv) > 1 else ""

    if cmd == "debug":
        _debug(); return

    if cmd == "status":
        _status(SVC_NAME); return

    if not HAS_WIN32:
        print("pywin32 not installed.\n  pip install pywin32")
        sys.exit(1)

    if cmd == "install":
        python_exe = _get_python_exe()
        print(f"[install] Python      : {python_exe}")
        print(f"[install] Script      : {os.path.abspath(__file__)}")
        print(f"[install] Service     : {SVC_NAME}")
        print(f"[install] DisplayName : {SVC_DISPLAY}")
        print(f"[install] Port        : {APP_PORT}")

        # Clean old registration
        subprocess.run(["sc.exe", "stop",   SVC_NAME], capture_output=True)
        time.sleep(2)
        subprocess.run(["sc.exe", "delete", SVC_NAME], capture_output=True)
        time.sleep(1)

        try:
            _register_via_sc(python_exe, APP_PORT, SVC_NAME, SVC_DISPLAY)
            print(f"[install] Service registered (Automatic Delayed Start)")
        except Exception as e:
            print(f"[install] ERROR registering: {e}")
            sys.exit(1)

        print("[install] Starting service...")
        ok = _start_and_wait(SVC_NAME, timeout=35)
        if ok:
            print(f"[install] Service RUNNING | http://localhost:{APP_PORT}")
            print(f"[install] First-run admin token: see data\\FIRST-RUN-ADMIN-TOKEN.txt")
            print(f"[install]   (email: admin@email.com -- token is unique to this install)")
        else:
            print(f"[install] WARNING: Service did not reach RUNNING in 35s")
            print(f"[install] Run:  python install_service.py debug")
            print(f"[install] Log:  {LOG_FILE}")
            try:
                lines = open(LOG_FILE).readlines()
                for l in lines[-8:]:
                    if l.strip(): print(f"         {l.rstrip()}")
            except Exception: pass

    elif cmd == "start":
        ok = _start_and_wait(SVC_NAME, 35)
        print("RUNNING" if ok else "Failed — check logs")

    elif cmd == "stop":
        r = subprocess.run(["sc.exe", "stop", SVC_NAME], capture_output=True, text=True)
        print(r.stdout or r.stderr)

    elif cmd == "restart":
        subprocess.run(["sc.exe", "stop", SVC_NAME], capture_output=True)
        time.sleep(3)
        ok = _start_and_wait(SVC_NAME, 35)
        print("RUNNING" if ok else "Failed")

    elif cmd == "remove":
        ok = _remove_via_sc(SVC_NAME)
        print("Removed." if ok else "Remove failed")

    elif len(sys.argv) == 1:
        # SCM dispatcher
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(NetMonitService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as exc:
            log.error("Dispatcher error: %s", exc)
            raise
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
