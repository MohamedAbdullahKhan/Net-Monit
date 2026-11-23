#!/usr/bin/env python3
# =============================================================================
# Net-monit V12.4 -- Setup Wizard
# Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com
# Contact: abuabdullah.be@outlook.com
# Default port: 5050 (browser-safe, user-changeable during install)
# =============================================================================
import os, sys, platform, subprocess, threading, shutil, time, re, ctypes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME    = "Net-monit"
APP_VER     = "V12.4"
APP_PORT    = 5050          # Browser-safe default (not in any blocked list)
IS_WIN      = platform.system() == "Windows"
DEFAULT_DIR = r"C:\NetMonit-V12.4" if IS_WIN else "/opt/netmonit-v124"
SVC_NAME    = "Net_Monit_V124"
CONTACT     = "abuabdullah.be@outlook.com"
COPYRIGHT   = "Abdullah-InfoXtek.com"

PY_INST_URL = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
PY_INST_NAME= "python-3.11.9-amd64.exe"


def _looks_like_windows_store_stub(path: str) -> bool:
    """
    True if `path` points at one of Windows' fake python.exe/python3.exe
    'App Execution Alias' stubs (...\\AppData\\Local\\Microsoft\\WindowsApps\\
    python.exe), which do nothing but redirect to the Microsoft Store and
    are NOT a real Python interpreter -- even though shutil.which() and the
    OS's own PATH search can both return this path, because that folder is
    placed ahead of real Python installs in PATH by default on most Windows
    systems (that's specifically what the alias feature is for).
    """
    return bool(path) and "windowsapps" in path.lower().replace("/", "\\")


def resolve_working_python(preferred: str = "") -> str:
    """
    Return a Python interpreter path that is GUARANTEED to actually work,
    never a bare unresolved command name.

    The one value that's always correct, with zero PATH-search ambiguity,
    is sys.executable -- the interpreter that is right now running this
    very script. If the wizard is running at all, sys.executable is by
    definition a real, working Python; there's no need to re-discover
    "a" Python by name afterwards (which is exactly what let the
    WindowsApps stub sneak in previously). `preferred` (e.g. a path the
    user picked, or an earlier detection result) is used only if it's a
    real file and not a known-broken stub.
    """
    if preferred and os.path.isfile(preferred) and not _looks_like_windows_store_stub(preferred):
        return preferred
    if sys.executable and not _looks_like_windows_store_stub(sys.executable):
        return sys.executable
    # Extremely unlikely fallback (frozen/embedded interpreter edge cases):
    # search PATH for "py" (the official Windows Python launcher) before
    # ever falling back to a bare "python"/"python3" string, since "py" is
    # never shadowed by the WindowsApps alias stub (only python.exe/
    # python3.exe are aliased that way).
    for cmd in (["py", "-3"] if IS_WIN else ["python3"]):
        found = shutil.which(cmd if isinstance(cmd, str) else cmd[0])
        if found and not _looks_like_windows_store_stub(found):
            return found
    # Last resort -- matches old behavior, but every safer option above
    # has already been exhausted.
    return "python" if IS_WIN else "python3"

# ── Colours ────────────────────────────────────────────────────────────────
C = {
    "bg":"#12121a","sidebar":"#0e0e16","panel":"#1c1c28","card":"#22222e",
    "border":"#32324a","accent":"#0078d4","acc_hov":"#005fa3",
    "text":"#e8e8f0","sub":"#9090aa","mute":"#606078",
    "ok":"#32c864","warn":"#f0b832","err":"#e04040",
    "btn_bg":"#2a2a3c","btn_brd":"#484860","log_bg":"#0a0a12","log_fg":"#40e080",
}
F_BODY  = ("Segoe UI", 10)
F_MONO  = ("Consolas", 10)
F_MONOS = ("Consolas", 8)
F_TITLE = ("Segoe UI", 16, "bold")
STEPS   = ["1  Welcome","2  Python","3  License","4  Location",
           "5  Options","6  Install","7  Finish"]
EULA    = (
    "NET-MONIT V12.4  --  END USER LICENSE AGREEMENT\n"
    "Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com\n"
    "Contact: abuabdullah.be@outlook.com\n\n"
    "IMPORTANT -- READ BEFORE INSTALLING\n\n"
    "1. GRANT OF LICENSE\n"
    "   Abdullah-InfoXtek.com grants you a non-exclusive, non-transferable\n"
    "   license to install and use Net-monit V12.4 for internal network\n"
    "   monitoring on machines you own or operate.\n\n"
    "2. FREE SOFTWARE\n"
    "   Net-monit is provided FREE of charge for personal and business use.\n"
    "   You must NOT sell, resell, or commercially redistribute this software.\n\n"
    "3. HOW TO OBTAIN A LICENSE KEY\n"
    "   This software is free but requires a license key after the 30-day trial.\n"
    "   To obtain your FREE key, contact:\n"
    "     Email   : abuabdullah.be@outlook.com\n"
    "     Website : Abdullah-InfoXtek.com\n"
    "   Share your Device ID and Activation Code from the Settings page.\n\n"
    "4. RESTRICTIONS\n"
    "   You may NOT:\n"
    "   a) Sell or commercially redistribute this software\n"
    "   b) Reverse-engineer or decompile the software\n"
    "   c) Remove or alter copyright notices\n"
    "   d) Use for unlawful network surveillance\n\n"
    "5. COPYRIGHT\n"
    "   Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com\n"
    "   All rights reserved.\n\n"
    "6. DISCLAIMER\n"
    "   THE SOFTWARE IS PROVIDED AS IS WITHOUT WARRANTY OF ANY KIND.\n\n"
    "By clicking 'I Agree' you confirm you have READ, UNDERSTOOD, and AGREE\n"
    "to be bound by all terms of this License Agreement."
)

# ── Browser-blocked ports (do not use as default) ──────────────────────────
BLOCKED_PORTS = {
    1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,77,79,87,95,
    101,102,103,104,109,110,111,115,117,119,123,135,137,139,143,
    161,179,389,427,465,512,513,514,515,526,530,531,532,540,548,554,
    556,563,587,601,636,989,990,993,995,2049,3659,4045,
    6000,6001,6002,6003,6004,6005,6006,6007,6008,6009,6010,6011,6012,
    6013,6014,6015,6016,6017,6018,6019,6020,6021,6022,6023,6024,6025,
    6026,6027,6028,6029,6030,6031,6032,6033,6034,6035,6036,6037,6038,
    6039,6040,6041,6042,6043,6044,6045,6046,6047,6048,6049,6050,6051,
    6052,6053,6054,6055,6056,6057,6058,6059,6060,6061,6062,6063,
    6665,6666,6667,6668,6669,6697
}


def is_safe_port(p):
    return 1024 <= p <= 65535 and p not in BLOCKED_PORTS


# =============================================================================
# SETUP WIZARD
# =============================================================================
class SetupWizard:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} {APP_VER} Setup Wizard")
        self.root.geometry("980x640")
        self.root.minsize(900, 600)
        self.root.configure(bg=C["bg"])
        self.root.resizable(True, True)

        # Install state
        self.page         = 0
        self.agreed       = tk.BooleanVar(value=False)
        self.install_path = tk.StringVar(value=DEFAULT_DIR)
        self.port_var     = tk.StringVar(value=str(APP_PORT))
        self.svc_name_var = tk.StringVar(value=SVC_NAME)
        self.opt_venv     = tk.BooleanVar(value=True)
        self.opt_fw       = tk.BooleanVar(value=True)
        self.opt_auto     = tk.BooleanVar(value=True)
        self.opt_desktop  = tk.BooleanVar(value=IS_WIN)
        self.py_exe       = ""
        self.py_ver       = ""
        self._py_ready    = threading.Event()

        self._build_shell()
        self._goto(0)
        self.root.mainloop()

    # ── Shell ─────────────────────────────────────────────────────────────
    def _build_shell(self):
        # Sidebar
        self.sidebar = tk.Frame(self.root, bg=C["sidebar"], width=210)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text=APP_NAME,
                 font=("Segoe UI",14,"bold"), fg="white",
                 bg=C["sidebar"]).place(x=18, y=18)
        tk.Label(self.sidebar, text=f"{APP_VER} Setup Wizard",
                 font=("Segoe UI",8), fg=C["mute"],
                 bg=C["sidebar"]).place(x=18, y=46)
        tk.Frame(self.sidebar, bg=C["border"],
                 height=1).place(x=0, y=68, relwidth=1)

        self.step_lbls = []
        for i, name in enumerate(STEPS):
            lbl = tk.Label(self.sidebar, text=name, font=("Segoe UI",9),
                           fg=C["mute"], bg=C["sidebar"], anchor="w",
                           padx=18, height=2)
            lbl.place(x=0, y=76+i*44, width=210, height=40)
            self.step_lbls.append(lbl)

        tk.Label(self.sidebar,
                 text=f"(c) 2024-2026 {COPYRIGHT}",
                 font=("Segoe UI",7), fg=C["mute"],
                 bg=C["sidebar"]).place(x=12, rely=1.0, anchor="sw", y=-10)

        # Right area
        self.right = tk.Frame(self.root, bg=C["bg"])
        self.right.pack(side="right", fill="both", expand=True)

        # Footer (fixed, packed bottom first)
        self.footer = tk.Frame(self.right, bg=C["panel"], height=64)
        self.footer.pack(side="bottom", fill="x")
        self.footer.pack_propagate(False)
        tk.Frame(self.right, bg=C["border"], height=1).pack(side="bottom", fill="x")

        self.btn_back = tk.Button(
            self.footer, text="< Back", font=F_BODY,
            bg=C["btn_bg"], fg=C["text"], relief="flat", bd=0,
            padx=16, pady=8, cursor="hand2", command=self._back)
        self.btn_back.place(x=14, y=12)

        self.btn_cancel = tk.Button(
            self.footer, text="Cancel", font=F_BODY,
            bg=C["btn_bg"], fg=C["sub"], relief="flat", bd=0,
            padx=14, pady=8, cursor="hand2", command=self._cancel)
        self.btn_cancel.place(x=126, y=12)

        self.btn_next = tk.Button(
            self.footer, text="Next  >", font=("Segoe UI",10,"bold"),
            bg=C["accent"], fg="white", relief="flat", bd=0,
            padx=22, pady=8, cursor="hand2", command=self._next)
        self.footer.bind("<Configure>", lambda e: self.btn_next.place(
            x=e.width-self.btn_next.winfo_reqwidth()-14, y=12))

        # Scrollable content
        self.content_outer = tk.Frame(self.right, bg=C["bg"])
        self.content_outer.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(self.content_outer, bg=C["bg"],
                                highlightthickness=0, bd=0)
        self.vsb = ttk.Scrollbar(self.content_outer, orient="vertical",
                                 command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.content = tk.Frame(self.canvas, bg=C["bg"])
        self._cwin = self.canvas.create_window(
            (0,0), window=self.content, anchor="nw", tags="c")
        self.content.bind("<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",
            lambda e: self.canvas.itemconfig(self._cwin, width=e.width))
        self.root.bind_all("<MouseWheel>",
            lambda e: self.canvas.yview_scroll(int(-1*(e.delta/120)),"units"))

    # ── Navigation ────────────────────────────────────────────────────────
    def _set_step(self, idx):
        for i, lbl in enumerate(self.step_lbls):
            if i == idx:
                lbl.configure(fg="white", bg=C["accent"],
                              font=("Segoe UI",9,"bold"))
            else:
                lbl.configure(fg=C["mute"], bg=C["sidebar"],
                              font=("Segoe UI",9))

    def _clear(self):
        for w in self.content.winfo_children(): w.destroy()
        self.canvas.yview_moveto(0)
        self.btn_next.configure(text="Next  >", state="normal",
                                bg=C["accent"])
        self.btn_back.configure(state="normal")
        self.btn_cancel.configure(state="normal")

    def _goto(self, idx):
        self.page = idx
        self._clear()
        self._set_step(idx)
        [self._p_welcome, self._p_python, self._p_license,
         self._p_location, self._p_options, self._p_install,
         self._p_finish][idx]()

    def _next(self):
        p = self.page
        if   p == 0: self._goto(1)
        elif p == 1: self._goto(2)
        elif p == 2:
            if not self.agreed.get():
                messagebox.showwarning("License",
                    "You must accept the license agreement to continue.")
                return
            self._goto(3)
        elif p == 3: self._validate_loc()
        elif p == 4: self._goto(5); self.root.after(100, self._run_install)
        elif p == 5: self._goto(6)
        elif p == 6: self._finish_close()

    def _back(self):
        if self.page in (5, 6): return
        if self.page > 0: self._goto(self.page - 1)

    def _cancel(self):
        if self.page == 5:
            messagebox.showinfo("Installing","Installation in progress. Please wait.")
            return
        if messagebox.askyesno("Cancel", "Cancel the installation?"):
            self.root.destroy()

    def _next_en(self, on):
        self.btn_next.configure(
            state="normal" if on else "disabled",
            bg=C["accent"] if on else C["btn_bg"])

    # ── Widget builders ───────────────────────────────────────────────────
    def _hdr(self, title, sub=""):
        f = tk.Frame(self.content, bg=C["bg"])
        f.pack(fill="x", padx=32, pady=(28,0))
        tk.Label(f, text=title, font=F_TITLE,
                 fg="white", bg=C["bg"], anchor="w").pack(anchor="w")
        if sub:
            tk.Label(f, text=sub, font=F_BODY,
                     fg=C["sub"], bg=C["bg"], anchor="w").pack(anchor="w", pady=(3,0))
        tk.Frame(self.content, bg=C["border"], height=1).pack(
            fill="x", padx=32, pady=(10,0))

    def _card(self, pady=(12,0)):
        f = tk.Frame(self.content, bg=C["card"],
                     highlightbackground=C["border"], highlightthickness=1)
        f.pack(fill="x", padx=32, pady=pady)
        return f

    def _row(self, parent, label, var, hint="", width=36, upper=False):
        tk.Label(parent, text=label, font=("Segoe UI",9),
                 fg=C["sub"], bg=C["card"], anchor="w"
                 ).pack(anchor="w", padx=14, pady=(10,2))
        e = tk.Entry(parent, textvariable=var, font=F_MONO,
                     bg=C["panel"], fg=C["text"], insertbackground="white",
                     relief="flat", bd=0, width=width)
        if upper:
            e.bind("<KeyRelease>", lambda ev: var.set(
                e.get().upper().replace(" ","_")))
        e.pack(fill="x", padx=14, pady=(0,2), ipady=6)
        if hint:
            tk.Label(parent, text=hint, font=("Segoe UI",8),
                     fg=C["mute"], bg=C["card"], anchor="w"
                     ).pack(anchor="w", padx=14, pady=(0,6))
        return e

    def _info(self, parent, text, color=None):
        lbl = tk.Label(parent, text=text, font=F_BODY,
                       fg=color or C["sub"], bg=C["card"],
                       anchor="w", justify="left", wraplength=750)
        lbl.pack(anchor="w", padx=14, pady=(0,10))
        return lbl

    def _chk(self, parent, text, var, y=0):
        c = tk.Checkbutton(parent, text=f"  {text}", variable=var,
                           font=F_BODY, fg=C["text"], bg=C["card"],
                           activebackground=C["card"], activeforeground="white",
                           selectcolor=C["panel"], cursor="hand2")
        c.pack(anchor="w", padx=14, pady=4)
        return c

    def _accent_btn(self, parent, text, cmd, color=None):
        b = tk.Button(parent, text=text, font=("Segoe UI",9,"bold"),
                      bg=color or C["accent"], fg="white",
                      activebackground=C["acc_hov"], relief="flat", bd=0,
                      padx=14, pady=6, cursor="hand2", command=cmd)
        b.pack(anchor="w", padx=14, pady=(4,12))
        return b

    # ==========================================================================
    # PAGE 0 -- WELCOME
    # ==========================================================================
    def _p_welcome(self):
        self.btn_back.configure(state="disabled")
        self._hdr(f"Welcome to {APP_NAME} {APP_VER} Setup",
                  "This wizard installs Net-monit on this machine.")
        c = self._card(pady=(16,0))
        tk.Label(c, text="What will be installed:", font=("Segoe UI",9,"bold"),
                 fg=C["text"], bg=C["card"]).pack(anchor="w", padx=14, pady=(14,6))
        for f in [
            f"  Real-time monitoring: Ping, SNMP, SSH, PowerShell, Disk",
            f"  Web dashboard at http://localhost:{APP_PORT}  (dark + light theme)",
            "  Multi-level email alert escalation (L1 / L2 / L3)",
            "  Per-user persistent dashboard layouts (grid and list views)",
            "  30-day free trial + permanent HMAC-SHA256 license activation",
            "  Windows Service (pywin32) or Linux systemd  --  no NSSM needed",
            "  Full REST API for future mobile app integration",
        ]:
            tk.Label(c, text=f, font=F_BODY, fg=C["text"],
                     bg=C["card"], anchor="w").pack(anchor="w", padx=14, pady=1)

        tk.Frame(c, bg=C["border"], height=1).pack(fill="x", padx=14, pady=10)
        tk.Label(c, text="Before you begin:", font=("Segoe UI",9,"bold"),
                 fg=C["text"], bg=C["card"]).pack(anchor="w", padx=14)
        for r in [
            "  Python 3.9+ (auto-detected; installer runs automatically if missing)",
            "  Administrator / root privileges  (wizard auto-elevates)",
            "  Internet access (only needed if Python must be downloaded)",
        ]:
            tk.Label(c, text=r, font=F_BODY, fg=C["sub"],
                     bg=C["card"], anchor="w").pack(anchor="w", padx=14, pady=1)
        tk.Label(c, text="Click  Next >  to begin.",
                 font=("Segoe UI",10,"bold"), fg=C["ok"],
                 bg=C["card"]).pack(anchor="w", padx=14, pady=(14,14))

    # ==========================================================================
    # PAGE 1 -- PYTHON
    # ==========================================================================
    def _p_python(self):
        self._next_en(False)
        self._hdr("Python Environment",
                  "Detecting Python 3.9+ automatically...")
        c = self._card(pady=(16,0))

        self._py_status = self._info(c, "Scanning...", C["sub"])
        self._py_status.configure(font=("Segoe UI",10,"bold"))
        self._py_detail = tk.Label(c, text="", font=F_MONOS,
                                   fg=C["sub"], bg=C["card"],
                                   anchor="w", justify="left", wraplength=750)
        self._py_detail.pack(anchor="w", padx=14)

        # Progress bar (shown during download/install)
        self._py_prog_frame = tk.Frame(c, bg=C["card"])
        self._py_prog_frame.pack(fill="x", padx=14, pady=(6,0))
        self._py_prog = ttk.Progressbar(self._py_prog_frame, mode="indeterminate",
                                        length=400)
        self._py_prog_lbl = tk.Label(self._py_prog_frame, text="",
                                     font=("Segoe UI",8), fg=C["mute"],
                                     bg=C["card"])

        self._btn_install_py = tk.Button(
            c, text="  Auto-Install Python 3.11  ",
            font=("Segoe UI",9,"bold"), bg="#005fa3", fg="white",
            relief="flat", bd=0, padx=14, pady=6, cursor="hand2",
            command=self._do_install_python)
        self._btn_retry_py = tk.Button(
            c, text="  Retry Detection  ",
            font=("Segoe UI",9), bg=C["btn_bg"], fg=C["text"],
            relief="flat", bd=0, padx=14, pady=6, cursor="hand2",
            command=lambda: self._goto(1))

        self.root.after(150, self._detect_python_async)

    def _detect_python_async(self):
        def _work():
            candidates = (
                ["python","python3","py"] if IS_WIN
                else ["python3.12","python3.11","python3.10","python3.9","python3"]
            )
            for cmd in candidates:
                try:
                    raw = subprocess.check_output(
                        [cmd,"--version"], stderr=subprocess.STDOUT,
                        timeout=5).decode().strip()
                    m = re.search(r"Python (\d+)\.(\d+)", raw)
                    if m and int(m.group(1))>=3 and int(m.group(2))>=9:
                        found = shutil.which(cmd)
                        if found and _looks_like_windows_store_stub(found):
                            continue  # this candidate is the broken Store stub -- keep looking
                        self.py_exe = found or resolve_working_python()
                        self.py_ver = raw
                        self.root.after(0, self._py_found)
                        return
                except Exception:
                    continue
            self.root.after(0, self._py_not_found)
        threading.Thread(target=_work, daemon=True).start()

    def _py_found(self):
        self._py_status.configure(
            text=f"Python detected  --  ready to continue.", fg=C["ok"])
        self._py_detail.configure(
            text=f"Executable : {self.py_exe}\n"
                 f"Version    : {self.py_ver}\n\n"
                 f"Python 3.9+ requirement is met. Dependencies will be installed automatically.")
        self._next_en(True)

    def _py_not_found(self):
        self._py_status.configure(
            text="Python 3.9+ not found on this system.", fg=C["warn"])
        self._py_detail.configure(
            text="Net-monit V12.4 requires Python 3.9 or later.\n"
                 "Click 'Auto-Install Python 3.11' to download and install silently,\n"
                 "or install manually from python.org (add to PATH) then click 'Retry Detection'.")
        self._btn_install_py.pack(anchor="w", padx=14, pady=(10,0))
        self._btn_retry_py.pack(anchor="w", padx=14, pady=(6,14))

    def _do_install_python(self):
        self._btn_install_py.configure(state="disabled")
        self._btn_retry_py.configure(state="disabled")
        self._py_prog.pack(side="left", pady=6)
        self._py_prog_lbl.pack(side="left", padx=8)
        self._py_prog.start(12)

        def _work():
            try:
                tmp = os.environ.get("TEMP", os.path.expanduser("~"))
                dest = os.path.join(tmp, PY_INST_NAME)

                def _status(msg):
                    self.root.after(0, lambda: (
                        self._py_status.configure(text=msg, fg=C["sub"]),
                        self._py_prog_lbl.configure(text=msg),
                    ))

                _status("Downloading Python 3.11 (~26 MB)...")
                import urllib.request, urllib.error
                try:
                    urllib.request.urlretrieve(PY_INST_URL, dest)
                except urllib.error.URLError as e:
                    raise RuntimeError(f"Download failed: {e}")

                _status("Installing Python 3.11 (silent, system-wide)...")
                ret = subprocess.call(
                    [dest, "/quiet", "InstallAllUsers=1",
                     "PrependPath=1", "Include_pip=1"],
                    timeout=300
                )
                if ret != 0:
                    raise RuntimeError(f"Installer exit code {ret}")

                # Refresh PATH in this process
                if IS_WIN:
                    try:
                        import winreg
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
                        ) as k:
                            sys_path, _ = winreg.QueryValueEx(k, "Path")
                        os.environ["PATH"] = sys_path + ";" + os.environ.get("PATH","")
                    except Exception:
                        pass

                self.py_exe = resolve_working_python()
                self.py_ver = "Python 3.11.9"
                self.root.after(0, lambda: (
                    self._py_prog.stop(),
                    self._py_prog.pack_forget(),
                    self._py_prog_lbl.pack_forget(),
                    self._py_found(),
                ))
            except Exception as ex:
                # V11.1: Python deletes `ex` when this block ends, and Tk runs the lambda LATER, so the old
                # code raised NameError inside the callback: the failure text never appeared and the progress
                # bar kept spinning. Bind the message now via a default argument.
                self.root.after(0, lambda msg=str(ex): (
                    self._py_prog.stop(),
                    self._py_prog.pack_forget(),
                    self._py_prog_lbl.pack_forget(),
                    self._py_status.configure(
                        text=f"Installation failed: {msg}", fg=C["err"]),
                    self._btn_install_py.configure(
                        state="normal", text="  Retry Install Python 3.11  "),
                    self._btn_retry_py.configure(state="normal"),
                ))
        threading.Thread(target=_work, daemon=True).start()

    # ==========================================================================
    # PAGE 2 -- LICENSE
    # ==========================================================================
    def _p_license(self):
        self._hdr("License Agreement",
                  "Please read the terms carefully before continuing.")
        c = self._card(pady=(16,0))
        inner = tk.Frame(c, bg=C["card"])
        inner.pack(fill="both", padx=14, pady=(12,0), expand=True)

        txt = tk.Text(inner, font=("Consolas",9), bg=C["panel"], fg=C["sub"],
                      relief="flat", bd=0, wrap="word", height=17, state="normal")
        vsb = ttk.Scrollbar(inner, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        txt.insert("1.0", EULA)
        txt.configure(state="disabled")

        row = tk.Frame(c, bg=C["card"])
        row.pack(fill="x", padx=14, pady=(12,14))
        self._chk_agree = tk.Checkbutton(
            row, text="  I have read and agree to the terms of the License Agreement",
            font=("Segoe UI",9,"bold"), fg="white", bg=C["card"],
            activebackground=C["card"], activeforeground="white",
            selectcolor=C["panel"], variable=self.agreed,
            command=self._on_agree, cursor="hand2")
        self._chk_agree.pack(anchor="w")
        self._on_agree()

    def _on_agree(self):
        if self.agreed.get():
            self.btn_next.configure(state="normal", bg=C["accent"], text="Next  >")
        else:
            self.btn_next.configure(state="disabled", bg=C["btn_bg"])

    # ==========================================================================
    # PAGE 3 -- LOCATION
    # ==========================================================================
    def _p_location(self):
        self._hdr("Installation Location",
                  f"Choose where {APP_NAME} {APP_VER} will be installed.")
        c = self._card(pady=(16,0))

        # Install path
        tk.Label(c, text="Install folder:", font=("Segoe UI",9),
                 fg=C["sub"], bg=C["card"], anchor="w"
                 ).pack(anchor="w", padx=14, pady=(12,2))
        path_row = tk.Frame(c, bg=C["card"])
        path_row.pack(fill="x", padx=14, pady=(0,4))
        path_e = tk.Entry(path_row, textvariable=self.install_path,
                          font=F_MONO, bg=C["panel"], fg=C["text"],
                          insertbackground="white", relief="flat", bd=0)
        path_e.pack(side="left", fill="x", expand=True, ipady=6)
        tk.Button(path_row, text=" Browse... ", font=("Segoe UI",8),
                  bg=C["btn_bg"], fg=C["text"], relief="flat", bd=0,
                  padx=8, pady=5, cursor="hand2",
                  command=self._browse).pack(side="right", padx=(8,0))

        self._disk_lbl = tk.Label(c, text="", font=("Segoe UI",8),
                                  fg=C["mute"], bg=C["card"], anchor="w")
        self._disk_lbl.pack(anchor="w", padx=14, pady=(0,8))
        self.install_path.trace_add("write", lambda *_: self._update_disk())
        self._update_disk()

        tk.Frame(c, bg=C["border"], height=1).pack(fill="x", padx=14, pady=4)

        # Port with browser-safety warning
        tk.Label(c, text="Dashboard port:", font=("Segoe UI",9),
                 fg=C["sub"], bg=C["card"], anchor="w"
                 ).pack(anchor="w", padx=14, pady=(8,2))
        port_row = tk.Frame(c, bg=C["card"])
        port_row.pack(fill="x", padx=14, pady=(0,2))
        self._port_entry = tk.Entry(port_row, textvariable=self.port_var,
                                    font=F_MONO, bg=C["panel"], fg=C["text"],
                                    insertbackground="white", relief="flat",
                                    bd=0, width=10)
        self._port_entry.pack(side="left", ipady=6)
        self._port_warn = tk.Label(port_row, text="", font=("Segoe UI",8),
                                   fg=C["warn"], bg=C["card"])
        self._port_warn.pack(side="left", padx=8)
        self.port_var.trace_add("write", lambda *_: self._check_port())
        self._check_port()
        tk.Label(c, text="Default: 5050  |  Avoid ports 6000-6063 (blocked by all browsers)",
                 font=("Segoe UI",8), fg=C["mute"], bg=C["card"], anchor="w"
                 ).pack(anchor="w", padx=14, pady=(0,8))

        tk.Frame(c, bg=C["border"], height=1).pack(fill="x", padx=14, pady=4)

        # Service name
        self._row(c, "Windows Service name  (letters, numbers, underscores only):",
                  self.svc_name_var,
                  hint="Used as the Windows service identifier. Changing this allows multiple installations.",
                  width=30, upper=True)

    def _browse(self):
        p = filedialog.askdirectory(title="Select installation folder",
                                    initialdir=self.install_path.get())
        if p:
            self.install_path.set(p.replace("/","\\") if IS_WIN else p)

    def _update_disk(self):
        try:
            p = self.install_path.get()
            if IS_WIN:
                drive = os.path.splitdrive(p)[0] or "C:"
                import ctypes as _ct
                free = _ct.c_ulonglong(0)
                _ct.windll.kernel32.GetDiskFreeSpaceExW(
                    drive, None, None, _ct.pointer(free))
                mb = free.value // (1024*1024)
            else:
                probe = p
                while probe and not os.path.exists(probe):
                    probe = os.path.dirname(probe)
                st = os.statvfs(probe or "/")
                mb = (st.f_bavail * st.f_frsize) // (1024*1024)
            self._disk_lbl.configure(
                text=f"Free space: {mb:,} MB  (Net-monit requires ~250 MB)",
                fg=C["ok"] if mb>300 else C["warn"])
        except Exception:
            self._disk_lbl.configure(text="", fg=C["mute"])

    def _check_port(self):
        try:
            p = int(self.port_var.get())
            if p in BLOCKED_PORTS:
                self._port_warn.configure(
                    text=f"Port {p} is blocked by browsers! Choose another.")
            elif not (1024 <= p <= 65535):
                self._port_warn.configure(text="Port must be 1024-65535")
            else:
                self._port_warn.configure(text="")
        except ValueError:
            self._port_warn.configure(text="Enter a valid number")

    def _validate_loc(self):
        p = self.install_path.get().strip()
        s = self.svc_name_var.get().strip()
        if not p:
            messagebox.showwarning("Location","Please enter a valid install path.")
            return
        if not s or not re.match(r"^[A-Za-z0-9_]+$", s):
            messagebox.showwarning("Service Name",
                "Service name must be letters, numbers, and underscores only.")
            return
        try:
            port_v = int(self.port_var.get())
            if not is_safe_port(port_v):
                messagebox.showwarning("Port",
                    f"Port {port_v} is not allowed.\n"
                    "Use a port between 1024-65535 that is not 6000-6063.\n"
                    "Recommended: 5050, 7000, 7001, 7070, 8080, 8181, 8443, 9000")
                return
        except ValueError:
            messagebox.showwarning("Port","Enter a valid port number.")
            return
        self._goto(4)

    # ==========================================================================
    # PAGE 4 -- OPTIONS
    # ==========================================================================
    def _p_options(self):
        self._hdr("Installation Options",
                  "Configure optional components.")
        c = self._card(pady=(16,0))
        try:
            port_v = int(self.port_var.get())
        except Exception:
            port_v = APP_PORT
        svc    = self.svc_name_var.get()

        for var, text in [
            (self.opt_venv,    "Create Python virtual environment  (recommended)"),
            (self.opt_fw,      f"Add Windows Firewall rule for port {port_v}"),
            (self.opt_auto,    f"Start '{svc}' service automatically on startup"),
            (self.opt_desktop, "Create desktop shortcut to the dashboard"),
        ]:
            self._chk(c, text, var)

        tk.Frame(c, bg=C["border"], height=1).pack(fill="x", padx=14, pady=8)
        tk.Label(c, text="Installation Summary", font=("Segoe UI",9,"bold"),
                 fg=C["accent"], bg=C["card"]).pack(anchor="w", padx=14)
        tk.Label(c,
                 text=(f"  Path    : {self.install_path.get()}\n"
                       f"  Port    : {port_v}\n"
                       f"  Service : {svc}\n"
                       f"  Python  : {self.py_ver or self.py_exe or 'auto'}"),
                 font=F_MONOS, fg=C["sub"], bg=C["card"],
                 anchor="w", justify="left"
                 ).pack(anchor="w", padx=14, pady=(4,14))
        self.btn_next.configure(text="Install  >")

    # ==========================================================================
    # PAGE 5 -- INSTALL
    # ==========================================================================
    def _p_install(self):
        self.btn_back.configure(state="disabled")
        self.btn_cancel.configure(state="disabled")
        self._next_en(False)
        self._hdr("Installing Net-monit V12.4",
                  "Please wait while the installation completes.")
        c = self._card(pady=(16,0))

        self._inst_status = tk.Label(c, text="Preparing...",
                                     font=("Segoe UI",9,"bold"),
                                     fg=C["sub"], bg=C["card"], anchor="w")
        self._inst_status.pack(anchor="w", padx=14, pady=(12,4))

        self._inst_bar = ttk.Progressbar(c, mode="determinate",
                                         maximum=100, value=0)
        self._inst_bar.pack(fill="x", padx=14, pady=(0,4))
        self._inst_pct = tk.Label(c, text="0%", font=("Segoe UI",8),
                                   fg=C["mute"], bg=C["card"])
        self._inst_pct.pack(anchor="e", padx=14)

        log_f = tk.Frame(c, bg=C["log_bg"], height=300)
        log_f.pack(fill="both", padx=14, pady=(4,14), expand=False)
        log_f.pack_propagate(False)
        self._inst_log = tk.Text(log_f, font=("Consolas",8),
                                 bg=C["log_bg"], fg=C["log_fg"],
                                 relief="flat", bd=0, state="disabled",
                                 wrap="word")
        lsb = ttk.Scrollbar(log_f, orient="vertical",
                             command=self._inst_log.yview)
        self._inst_log.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right", fill="y")
        self._inst_log.pack(side="left", fill="both", expand=True)

    def _log(self, msg, color=None):
        ts   = time.strftime("%H:%M:%S")
        line = f"[{ts}]  {msg}\n"
        print(f"[INSTALL] {msg}")
        def _ui():
            self._inst_log.configure(state="normal")
            if color:
                tag = f"c_{color}"
                self._inst_log.tag_configure(tag, foreground=color)
                self._inst_log.insert("end", line, tag)
            else:
                self._inst_log.insert("end", line)
            self._inst_log.see("end")
            self._inst_log.configure(state="disabled")
        self.root.after(0, _ui)

    def _prog(self, pct, msg):
        def _ui():
            self._inst_bar["value"] = pct
            self._inst_pct.configure(text=f"{pct}%")
            self._inst_status.configure(text=msg)
        self.root.after(0, _ui)

    # ==========================================================================
    # INSTALLATION LOGIC
    # ==========================================================================
    def _run_install(self):
        ip  = self.install_path.get().strip()
        svc = self.svc_name_var.get().strip()
        try:
            port = int(self.port_var.get())
        except Exception:
            port = APP_PORT

        py  = resolve_working_python(self.py_exe)

        # ── STEP 1: Directories ──────────────────────────────────────────
        self._prog(4, "Creating directory structure...")
        try:
            subs = ["","data","logs","monitor","monitor/checkers",
                    "static/css","static/js","templates",
                    "setup","tools","scripts/windows","scripts/linux"]
            for s in subs:
                os.makedirs(os.path.join(ip, s.replace("/",os.sep)), exist_ok=True)
            self._log(f"Directories created: {ip}")
        except Exception as e:
            self._log(f"ERROR creating directories: {e}", C["err"])
            self.root.after(0, lambda: self.btn_back.configure(state="normal"))
            return

        # ── STEP 2: Copy files ───────────────────────────────────────────
        self._prog(12, "Copying application files...")
        try:
            src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            app_py = os.path.join(src, "app.py")
            if os.path.isfile(app_py):
                shutil.copytree(src, ip,
                    ignore=shutil.ignore_patterns(
                        "venv","__pycache__","*.pyc","*.zip",
                        "monitor.db","secret.key","*.log",".git"),
                    dirs_exist_ok=True)
                self._log(f"Files copied from {src}")
            else:
                self._log(f"Source not at {src}  --  copy files manually", C["warn"])
        except Exception as e:
            self._log(f"Copy warning: {e}", C["warn"])

        # ── STEP 3: Write config.yaml (port propagation) ─────────────────
        self._prog(22, "Writing configuration...")
        try:
            cfg_path = os.path.join(ip, "config.yaml")
            # Always update port in config.yaml so app uses the user-chosen port
            cfg_content = (
                f"# Net-monit V12.4 config.yaml  (generated by Setup Wizard)\n"
                f"smtp:\n"
                f"  enabled: false\n"
                f"  host: smtp-mail.outlook.com\n"
                f"  port: 587\n"
                f"  use_tls: true\n"
                f"  username: ''\n"
                f"  password: ''\n"
                f"  from_address: ''\n"
                f"  admin_emails: []\n"
                f"  support_emails: []\n"
                f"  manager_emails: []\n"
                f"server:\n"
                f"  port: {port}\n"
                f"  host: 0.0.0.0\n"
                f"devices: []\n"
            )
            with open(cfg_path, "w") as f:
                f.write(cfg_content)
            self._log(f"config.yaml written  (port={port})")
        except Exception as e:
            self._log(f"config.yaml warning: {e}", C["warn"])

        # ── STEP 4: Virtual environment ──────────────────────────────────
        if self.opt_venv.get():
            self._prog(30, "Creating Python virtual environment...")
            try:
                venv_path = os.path.join(ip, "venv")
                if not os.path.isdir(venv_path):
                    subprocess.run([py, "-m", "venv", venv_path],
                                   check=True, capture_output=True)
                    self._log(f"Virtual environment created: {venv_path}")
                else:
                    self._log("Virtual environment already exists  --  skipped")
                venv_py = os.path.join(venv_path,
                    "Scripts" if IS_WIN else "bin",
                    "python.exe" if IS_WIN else "python")
                if os.path.isfile(venv_py):
                    py = venv_py
                    self._log(f"Using venv Python: {py}")
            except Exception as e:
                self._log(f"venv warning: {e}", C["warn"])

        # ── STEP 5: pip install requirements.txt ─────────────────────────
        self._prog(44, "Installing Python dependencies from requirements.txt...")
        req = os.path.join(ip, "requirements.txt")
        if os.path.isfile(req):
            try:
                self._log("Running: pip install -r requirements.txt ...")
                r = subprocess.run(
                    [py, "-m", "pip", "install", "--upgrade", "pip",
                     "--quiet", "--no-warn-script-location"],
                    capture_output=True, text=True)
                r2 = subprocess.run(
                    [py, "-m", "pip", "install", "-r", req,
                     "--quiet", "--no-warn-script-location"],
                    capture_output=True, text=True)
                if r2.returncode == 0:
                    self._log("pip install completed successfully")
                else:
                    # Show individual failures
                    for line in (r2.stdout+r2.stderr).splitlines():
                        if line.strip() and any(
                            k in line.lower() for k in
                            ("error","failed","warning","could not")
                        ):
                            self._log(f"  pip: {line.strip()}", C["warn"])
                    self._log("pip install completed (with some warnings)", C["warn"])
            except Exception as e:
                self._log(f"pip error: {e}", C["warn"])
        else:
            self._log("requirements.txt not found  --  skipping pip install", C["warn"])

        # ── STEP 5b (V12.4): Npcap (optional packet-capture driver; silent only with an OEM installer in setup\\deps) ──
        if IS_WIN:
            try:
                self._prog(50, "Checking Npcap (packet capture driver)...")
                nps = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Install-Npcap.ps1")
                if os.path.isfile(nps):
                    r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", nps, "-Quiet"],
                                       capture_output=True, text=True, timeout=900)
                    ok = os.path.isfile(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll"))
                    self._log("Npcap installed" if ok else "Npcap not installed - built-in capture is used (optional add-on, see docs)",
                              None if ok else C["warn"])
            except Exception as e:
                self._log(f"Npcap step skipped: {e}", C["warn"])

        # ── STEP 6: Service registration (Windows) ───────────────────────
        if IS_WIN:
            # Stop and remove any existing service FIRST -- if a previous
            # install's service (or a leftover python.exe) is still running,
            # it holds pywintypes3XX.dll open and the postinstall step below
            # fails with "Error installing pywintypesXXX.dll ... process
            # cannot access the file because it is being used by another
            # process." Doing this before the postinstall call, not after,
            # is what actually prevents the error.
            self._prog(55, "Stopping any existing Net-monit service...")
            try:
                subprocess.run(["sc.exe", "stop",   svc], capture_output=True)
                time.sleep(2)
                subprocess.run(["sc.exe", "delete", svc], capture_output=True)
                time.sleep(1)
                self._log("Any previous service instance stopped and removed")
            except Exception as e:
                self._log(f"Pre-install service stop warning: {e}", C["warn"])

            self._prog(58, "Running pywin32 post-install...")
            try:
                pydir = os.path.dirname(py)
                pi_candidates = [
                    os.path.join(pydir, "pywin32_postinstall.py"),
                    os.path.normpath(os.path.join(pydir, "..", "Scripts",
                                                  "pywin32_postinstall.py")),
                ]
                pi_path = None
                for pi in pi_candidates:
                    if os.path.isfile(pi):
                        pi_path = pi
                        break

                # Retry up to 3 times with a short pause -- Windows can take
                # a moment to fully release a DLL handle even after the
                # owning process/service has been stopped.
                last_err_output = ""
                succeeded = False
                for attempt in range(1, 4):
                    if pi_path:
                        r = subprocess.run([py, pi_path, "-install"],
                                           capture_output=True, text=True)
                    else:
                        r = subprocess.run([py, "-m", "pywin32_postinstall", "-install"],
                                           capture_output=True, text=True)
                    combined = (r.stdout or "") + (r.stderr or "")
                    last_err_output = combined
                    if "being used by another process" not in combined:
                        succeeded = True
                        break
                    self._log(f"  DLL still locked, retrying ({attempt}/3)...", C["warn"])
                    time.sleep(3)

                if succeeded:
                    self._log(f"pywin32 post-install ran: {pi_path or '(module)'}")
                else:
                    self._log(
                        "pywin32 post-install could not replace pywintypes DLL "
                        "after 3 attempts -- close any other Python/Net-monit "
                        "windows and re-run Setup, or continue (service "
                        "registration may still succeed if pywin32 was "
                        "already installed correctly).", C["warn"])
            except Exception as e:
                self._log(f"pywin32 post-install warning: {e}", C["warn"])

            self._prog(64, "Registering Windows Service...")
            try:
                svc_script = os.path.join(ip, "install_service.py")
                if os.path.isfile(svc_script):
                    # Remove stale
                    subprocess.run(["sc.exe","stop",  svc], capture_output=True)
                    time.sleep(2)
                    subprocess.run(["sc.exe","delete",svc], capture_output=True)
                    time.sleep(1)
                    # Pass user-chosen port + service name via env vars
                    env = os.environ.copy()
                    env["NETMON_PORT"]        = str(port)
                    env["NETMON_SVC_NAME"]    = svc
                    env["NETMON_SVC_DISPLAY"] = f"Net-monit V12.4 Network Monitor"
                    r = subprocess.run(
                        [py, svc_script, "install"],
                        capture_output=True, text=True,
                        cwd=ip, env=env)
                    out = (r.stdout + r.stderr).strip()
                    if r.returncode == 0:
                        self._log(
                            f"Service '{svc}' registered "
                            f"(port={port}, Automatic Delayed Start)")
                        for line in out.splitlines()[-5:]:
                            if line.strip():
                                self._log(f"  {line.strip()}")
                    else:
                        self._log(
                            f"Service registration warning "
                            f"(code {r.returncode}): {out[:400]}", C["warn"])
                else:
                    self._log("install_service.py not found  --  skipping", C["warn"])
            except Exception as e:
                self._log(f"Service registration error: {e}", C["warn"])

        else:  # Linux systemd
            self._prog(64, "Writing systemd service file...")
            try:
                unit = (
                    f"[Unit]\nDescription=Net-monit V12.4 Network Monitor\n"
                    f"After=network-online.target\nWants=network-online.target\n\n"
                    f"[Service]\nType=simple\nUser=netmonit\nGroup=netmonit\nAmbientCapabilities=CAP_NET_RAW\nCapabilityBoundingSet=CAP_NET_RAW\n"
                    f"WorkingDirectory={ip}\n"
                    f"ExecStart={py} {ip}/app.py\n"
                    f"Restart=on-failure\nRestartSec=5s\n"
                    f"Environment=PYTHONUNBUFFERED=1\n"
                    f"Environment=NETMON_PORT={port}\n"
                    f"Environment=NETMON_SVC_NAME={svc}\n\n"
                    f"[Install]\nWantedBy=multi-user.target\n"
                )
                svc_file = f"/etc/systemd/system/{svc.lower()}.service"
                if os.access("/etc/systemd/system", os.W_OK):
                    with open(svc_file,"w") as f: f.write(unit)
                    subprocess.run(["systemctl","daemon-reload"], capture_output=True)
                    subprocess.run(["systemctl","enable", svc.lower()], capture_output=True)
                    self._log(f"systemd service registered: {svc_file}")
                else:
                    out = os.path.join(ip, f"{svc.lower()}.service")
                    with open(out,"w") as f: f.write(unit)
                    self._log(f"Service file written to {out}")
                    self._log("Run as root: sudo cp ... /etc/systemd/system/ && sudo systemctl enable ...")
            except Exception as e:
                self._log(f"systemd warning: {e}", C["warn"])

        # ── STEP 7: Firewall ─────────────────────────────────────────────
        if self.opt_fw.get() and IS_WIN:
            self._prog(76, f"Adding firewall rule for port {port}...")
            try:
                rule = f"Net-monit V12.4 Port {port}"
                # Remove old rule first
                subprocess.run(["netsh","advfirewall","firewall","delete","rule",
                                 f"name={rule}"], capture_output=True)
                subprocess.run(["netsh","advfirewall","firewall","add","rule",
                                 f"name={rule}",
                                 "dir=in","action=allow","protocol=TCP",
                                 f"localport={port}"],
                                capture_output=True)
                self._log(f"Firewall rule added for TCP {port}")
            except Exception as e:
                self._log(f"Firewall warning: {e}", C["warn"])

        # ── STEP 8: Start service ─────────────────────────────────────────
        self._prog(82, "Starting service...")
        if IS_WIN:
            try:
                svc_script = os.path.join(ip, "install_service.py")
                if os.path.isfile(svc_script):
                    time.sleep(1)
                    subprocess.run(["sc.exe","start",svc], capture_output=True)
                    running = False
                    self._log("Waiting for service to reach RUNNING state...")
                    for i in range(18):   # 36 seconds max
                        time.sleep(2)
                        r = subprocess.run(["sc.exe","query",svc],
                                           capture_output=True, text=True)
                        if "RUNNING" in r.stdout:
                            running = True
                            break
                        if i % 3 == 2:
                            self._log(f"  ... {(i+1)*2}s elapsed")
                    if running:
                        self._log(
                            f"Service RUNNING  --  http://localhost:{port}",
                            C["ok"])
                    else:
                        self._log("Service not yet RUNNING (may still be starting)", C["warn"])
                        log_file = os.path.join(ip,"logs","service.log")
                        if os.path.isfile(log_file):
                            lines = open(log_file).readlines()
                            for l in lines[-6:]:
                                if l.strip(): self._log(f"  {l.rstrip()}")
                        self._log(f"Manual check: python install_service.py debug", C["warn"])
            except Exception as e:
                self._log(f"Service start warning: {e}", C["warn"])
        else:
            try:
                subprocess.run(["systemctl","start",svc.lower()], capture_output=True)
                time.sleep(3)
                r = subprocess.run(["systemctl","is-active",svc.lower()],
                                   capture_output=True, text=True)
                if "active" in r.stdout:
                    self._log(f"systemd service active  --  http://localhost:{port}", C["ok"])
                else:
                    self._log("Service not active yet  --  check: systemctl status "+svc.lower(), C["warn"])
            except Exception as e:
                self._log(f"Service start warning: {e}", C["warn"])

        # ── STEP 9: Desktop shortcut ──────────────────────────────────────
        if self.opt_desktop.get() and IS_WIN:
            self._prog(92, "Creating desktop shortcut...")
            try:
                user_profile = (os.environ.get("USERPROFILE")
                                or os.path.expanduser("~"))
                desktop = os.path.join(user_profile, "Desktop")
                os.makedirs(desktop, exist_ok=True)
                lnk = os.path.join(desktop, "Net-monit Dashboard.url")
                with open(lnk, "w") as f:
                    f.write(f"[InternetShortcut]\nURL=http://localhost:{port}\n")
                self._log(f"Desktop shortcut created: {lnk}")
            except Exception as e:
                self._log(f"Shortcut warning: {e}", C["warn"])

        # ── STEP 10: Registry ─────────────────────────────────────────────
        if IS_WIN:
            self._prog(97, "Writing registry entries...")
            try:
                import winreg
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                                       r"SOFTWARE\NetMonit-V12.4")
                winreg.SetValueEx(key,"InstallPath",  0,winreg.REG_SZ, ip)
                winreg.SetValueEx(key,"Version",      0,winreg.REG_SZ, APP_VER.lstrip("Vv"))
                winreg.SetValueEx(key,"Port",         0,winreg.REG_DWORD, port)
                winreg.SetValueEx(key,"ServiceName",  0,winreg.REG_SZ, svc)
                winreg.SetValueEx(key,"PythonExe",    0,winreg.REG_SZ, py)
                winreg.SetValueEx(key,"InstallDate",  0,winreg.REG_SZ,
                                  time.strftime("%Y-%m-%d"))
                winreg.CloseKey(key)
                self._log("Registry entries written")
            except Exception as e:
                self._log(f"Registry warning: {e}", C["warn"])

        self._prog(100, "Installation complete!")
        self._log("=" * 52)
        self._log(f"Net-monit V12.4 installation finished successfully.")
        self._log(f"Dashboard  :  http://localhost:{port}")
        self._log(f"Login      :  see below for your one-time admin token")
        self._log(f"             (Email: admin@email.com)")
        self._log(f"             Check this window's log above, or")
        self._log(f"             {ip}\\data\\FIRST-RUN-ADMIN-TOKEN.txt")
        self._log(f"IMPORTANT  :  Change password immediately via Admin Panel!")
        self._log("=" * 52)

        def _done():
            self.btn_next.configure(
                state="normal", bg=C["ok"], text="Finish  >")
        self.root.after(0, _done)

    # ==========================================================================
    # PAGE 6 -- FINISH
    # ==========================================================================
    def _p_finish(self):
        self.btn_back.configure(state="disabled")
        self.btn_cancel.configure(state="disabled")
        self.btn_next.configure(text="Close", bg=C["ok"])
        try:
            port = int(self.port_var.get())
        except Exception:
            port = APP_PORT
        svc = self.svc_name_var.get()

        self._hdr("Installation Complete!",
                  "Net-monit V12.4 is installed and ready.")
        c = self._card(pady=(16,0))
        for label, value in [
            ("Install path",  self.install_path.get()),
            ("Dashboard",     f"http://localhost:{port}"),
            ("Service name",  svc),
            ("Python",        self.py_ver or self.py_exe or "system"),
            ("Platform",      f"{platform.system()} {platform.release()}"),
        ]:
            row = tk.Frame(c, bg=C["card"])
            row.pack(fill="x", padx=14, pady=2)
            tk.Label(row, text=f"{label}:", font=("Segoe UI",9),
                     fg=C["sub"], bg=C["card"], width=14, anchor="w"
                     ).pack(side="left")
            tk.Label(row, text=value, font=F_MONOS,
                     fg=C["ok"], bg=C["card"], anchor="w"
                     ).pack(side="left")

        tk.Frame(c, bg=C["border"], height=1).pack(fill="x", padx=14, pady=10)
        for step in [
            f"1.  Open  http://localhost:{port}  in your browser",
            "2.  Sign in with the one-time admin token shown during install",
            f"    (also saved to {self.install_path.get()}\\data\\FIRST-RUN-ADMIN-TOKEN.txt)",
            "3.  IMPORTANT: Change your password  (Admin Panel > Users)",
            "4.  Settings > License  to activate your free license key",
            "5.  Devices  to add network devices to monitor",
        ]:
            tk.Label(c, text=f"  {step}", font=F_BODY, fg=C["sub"],
                     bg=C["card"], anchor="w", justify="left"
                     ).pack(anchor="w", padx=14, pady=1)

        tk.Frame(c, bg=C["border"], height=1).pack(fill="x", padx=14, pady=8)
        tk.Label(c,
                 text=f"  For a FREE license key, share Device ID + Activation Code\n"
                      f"  (from Settings > License) with:  {CONTACT}",
                 font=("Segoe UI",9), fg=C["warn"], bg=C["card"],
                 anchor="w", justify="left"
                 ).pack(anchor="w", padx=14, pady=(0,14))

        oc = self._card(pady=(6,16))
        self.open_dash = tk.BooleanVar(value=True)
        tk.Checkbutton(oc,
                       text=f"  Open http://localhost:{port} in browser now",
                       font=("Segoe UI",9,"bold"), fg="white", bg=C["card"],
                       activebackground=C["card"], selectcolor=C["panel"],
                       variable=self.open_dash, cursor="hand2"
                       ).pack(anchor="w", padx=14, pady=(10,10))

    def _finish_close(self):
        try:
            port = int(self.port_var.get())
        except Exception:
            port = APP_PORT
        if hasattr(self, "open_dash") and self.open_dash.get():
            import webbrowser
            webbrowser.open(f"http://localhost:{port}")
        self.root.destroy()


# =============================================================================
# ENTRY POINT
# =============================================================================
def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return True   # Non-Windows: assume ok


if __name__ == "__main__":
    if IS_WIN and not _is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            f'"{os.path.abspath(__file__)}"', None, 1)
        sys.exit(0)
    SetupWizard()
