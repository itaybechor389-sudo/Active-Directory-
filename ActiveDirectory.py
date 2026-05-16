#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                  AD-SENTINEL  v1.0                               ║
║          Active Directory Security Auditor                       ║
║   ─────────────────────────────────────────────────────────     ║
║   Course  : RTX2026 | Network Security                           ║
║   Author  : Itay Bechor                                          ║
║   Platform: Cyberium Academy — John Bryce / ThinkCyber           ║
╚══════════════════════════════════════════════════════════════════╝

Dependencies:
    pip install customtkinter ldap3

Optional (for full scan features):
    sudo apt install nmap rpcclient smbclient
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import subprocess
import socket
import json
import datetime
import os
import time
import ipaddress
from pathlib import Path

# ── Optional imports ─────────────────────────────────────────────
try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    from ldap3.core.exceptions import LDAPException
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════
# THEME  —  Dark / Cyan / Electric-Blue
# ═══════════════════════════════════════════════════════════════════
C = {
    "bg0":          "#060b17",   # deepest bg
    "bg1":          "#0b1220",   # secondary bg
    "bg2":          "#101929",   # card bg
    "bg3":          "#18253a",   # hover / alt row
    "border":       "#1c2d44",
    "border_acc":   "#00d4ff22",
    "cyan":         "#00d4ff",
    "blue":         "#0066ff",
    "purple":       "#7c3aed",
    "green":        "#00ff88",
    "red":          "#ff3366",
    "orange":       "#ff6b00",
    "yellow":       "#ffd166",
    "txt":          "#dde6f0",
    "txt2":         "#7a8fa8",
    "txt3":         "#3a5070",
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ═══════════════════════════════════════════════════════════════════
# ENVIRONMENT DEFAULTS  (pre-filled from your lab screenshots)
# ═══════════════════════════════════════════════════════════════════
KALI_IP       = "192.168.108.156"
DC_IP         = "192.168.108.10"
DOMAIN        = "lab.local"
SUBNET        = "192.168.108.0/24"
TOOL_VERSION  = "1.0"

# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════
def ts():
    return datetime.datetime.now().strftime("%H:%M:%S")

def now_full():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def port_open(ip, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except:
        return False


# ═══════════════════════════════════════════════════════════════════
# CUSTOM WIDGETS
# ═══════════════════════════════════════════════════════════════════

class MetricCard(ctk.CTkFrame):
    """Glowing stat card."""
    def __init__(self, parent, title, value="—", unit="", color=None, icon="◈", **kw):
        super().__init__(parent, **kw)
        color = color or C["cyan"]
        self.configure(fg_color=C["bg2"], corner_radius=14,
                       border_width=1, border_color=C["border"])

        bar = ctk.CTkFrame(self, fg_color=color, width=4, corner_radius=2)
        bar.pack(side="left", fill="y", padx=(10, 0), pady=10)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(side="left", padx=14, pady=12, fill="both", expand=True)

        ctk.CTkLabel(body, text=f"{icon}  {title}",
                     font=ctk.CTkFont("Consolas", 10),
                     text_color=C["txt2"]).pack(anchor="w")

        row = ctk.CTkFrame(body, fg_color="transparent")
        row.pack(anchor="w")
        self._val = ctk.CTkLabel(row, text=str(value),
                                  font=ctk.CTkFont("Consolas", 28, "bold"),
                                  text_color=color)
        self._val.pack(side="left")
        if unit:
            ctk.CTkLabel(row, text=f" {unit}",
                         font=ctk.CTkFont("Consolas", 11),
                         text_color=C["txt2"]).pack(side="left", pady=(8, 0))

    def set(self, v): self._val.configure(text=str(v))


class Dot(ctk.CTkFrame):
    """Status indicator dot."""
    _MAP = {
        "idle":     C["txt3"],
        "online":   C["green"],
        "offline":  C["red"],
        "scanning": C["yellow"],
        "error":    C["red"],
    }
    def __init__(self, parent, status="idle", **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self._dot = ctk.CTkLabel(self, text="●", font=ctk.CTkFont(size=13),
                                  text_color=self._MAP.get(status, C["txt3"]))
        self._dot.pack(side="left")
        self._lbl = ctk.CTkLabel(self, text=status.upper(),
                                  font=ctk.CTkFont("Consolas", 10),
                                  text_color=self._MAP.get(status, C["txt3"]))
        self._lbl.pack(side="left", padx=(4, 0))

    def update(self, status):
        col = self._MAP.get(status, C["txt3"])
        self._dot.configure(text_color=col)
        self._lbl.configure(text=status.upper(), text_color=col)


class LogBox(ctk.CTkTextbox):
    """Styled log console."""
    _COLORS = {"info": C["cyan"], "ok": C["green"],
                "err": C["red"],  "warn": C["yellow"], "hdr": C["purple"]}
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.configure(fg_color=C["bg0"], text_color=C["cyan"],
                       font=ctk.CTkFont("Consolas", 11),
                       border_width=1, border_color=C["border"], corner_radius=8)
        for tag, col in self._COLORS.items():
            self.tag_config(tag, foreground=col)

    def log(self, msg, level="info"):
        self.configure(state="normal")
        pfx = {"info":"[*]","ok":"[+]","err":"[-]","warn":"[!]","hdr":["#"]}
        line = f"[{ts()}] {pfx.get(level,'[*]')} {msg}\n"
        self.insert("end", line, level)
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")


class Grid(ctk.CTkFrame):
    """Premium ttk.Treeview table."""
    def __init__(self, parent, cols, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        sty = ttk.Style(); sty.theme_use("clam")
        sty.configure("G.Treeview",
            background=C["bg2"], foreground=C["txt"],
            fieldbackground=C["bg2"], borderwidth=0,
            rowheight=30, font=("Consolas", 10))
        sty.configure("G.Treeview.Heading",
            background=C["bg0"], foreground=C["cyan"],
            font=("Consolas", 10, "bold"), relief="flat")
        sty.map("G.Treeview",
            background=[("selected", C["blue"])],
            foreground=[("selected", "white")])

        vsb = ttk.Scrollbar(self, orient="vertical")
        hsb = ttk.Scrollbar(self, orient="horizontal")
        self.tv  = ttk.Treeview(self, columns=cols, show="headings",
                                 style="G.Treeview",
                                 yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.configure(command=self.tv.yview)
        hsb.configure(command=self.tv.xview)

        for c in cols:
            self.tv.heading(c, text=c.upper())
            self.tv.column(c, anchor="w", minwidth=60)

        self.tv.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.tv.tag_configure("alt",      background=C["bg3"])
        self.tv.tag_configure("online",   foreground=C["green"])
        self.tv.tag_configure("offline",  foreground=C["red"])
        self.tv.tag_configure("critical", foreground=C["red"])
        self.tv.tag_configure("high",     foreground=C["orange"])
        self.tv.tag_configure("medium",   foreground=C["yellow"])
        self.tv.tag_configure("low",      foreground=C["green"])

    def clear(self):
        [self.tv.delete(i) for i in self.tv.get_children()]

    def add(self, vals, tags=()):
        n   = len(self.tv.get_children())
        row = ("alt",) if n % 2 else ()
        self.tv.insert("", "end", values=vals, tags=row + tuple(tags))


def card(parent, **kw):
    """Helper – styled card frame."""
    f = ctk.CTkFrame(parent, fg_color=C["bg2"], corner_radius=12,
                     border_width=1, border_color=C["border"], **kw)
    return f

def card_title(parent, text):
    ctk.CTkLabel(parent, text=text,
                 font=ctk.CTkFont("Consolas", 13, "bold"),
                 text_color=C["cyan"]).pack(anchor="w", padx=20, pady=(16, 8))
    ctk.CTkFrame(parent, fg_color=C["border"], height=1).pack(fill="x", padx=20)

def primary_btn(parent, text, cmd, color=None, **kw):
    color = color or C["cyan"]
    return ctk.CTkButton(parent, text=text, command=cmd,
                         font=ctk.CTkFont("Consolas", 11, "bold"),
                         fg_color=color, hover_color=C["blue"],
                         text_color=C["bg0"], corner_radius=8, height=34, **kw)

def ghost_btn(parent, text, cmd, **kw):
    return ctk.CTkButton(parent, text=text, command=cmd,
                         font=ctk.CTkFont("Consolas", 11),
                         fg_color="transparent", hover_color=C["bg3"],
                         border_width=1, border_color=C["border"],
                         text_color=C["txt2"], corner_radius=8, height=34, **kw)


# ═══════════════════════════════════════════════════════════════════
# TAB 1 — DASHBOARD
# ═══════════════════════════════════════════════════════════════════
class DashboardTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._build()

    def _build(self):
        # ── header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 18))
        ctk.CTkLabel(hdr, text="◈  SECURITY DASHBOARD",
                     font=ctk.CTkFont("Consolas", 22, "bold"),
                     text_color=C["cyan"]).pack(side="left")
        ctk.CTkLabel(hdr,
                     text=f"Target: {DC_IP}  ·  Domain: {DOMAIN}  ·  Network: {SUBNET}",
                     font=ctk.CTkFont("Consolas", 11),
                     text_color=C["txt2"]).pack(side="right")

        # ── metric cards
        mf = ctk.CTkFrame(self, fg_color="transparent")
        mf.pack(fill="x", pady=(0, 14))
        for i in range(5):
            mf.grid_columnconfigure(i, weight=1)

        self.m_hosts   = MetricCard(mf, "LIVE HOSTS",  icon="⬡", color=C["cyan"])
        self.m_users   = MetricCard(mf, "AD USERS",    icon="◎", color=C["blue"])
        self.m_groups  = MetricCard(mf, "AD GROUPS",   icon="◈", color=C["purple"])
        self.m_finds   = MetricCard(mf, "FINDINGS",    icon="⚠", color=C["orange"])
        self.m_risk    = MetricCard(mf, "RISK SCORE",  icon="◉", color=C["red"], unit="/100")

        for i, w in enumerate([self.m_hosts, self.m_users, self.m_groups,
                                self.m_finds, self.m_risk]):
            w.grid(row=0, column=i, padx=5, sticky="ew")

        # ── middle row
        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.pack(fill="both", expand=True)
        mid.grid_columnconfigure(0, weight=2); mid.grid_columnconfigure(1, weight=1)
        mid.grid_rowconfigure(0, weight=1)

        # environment card
        env = card(mid); env.grid(row=0, column=0, padx=(0,8), sticky="nsew")
        card_title(env, "◈  ENVIRONMENT OVERVIEW")

        items = [
            ("Attacker IP",      KALI_IP,                C["green"]),
            ("Domain Controller", DC_IP,                 C["cyan"]),
            ("Domain Name",      DOMAIN,                 C["txt"]),
            ("Subnet",           SUBNET,                 C["txt"]),
            ("DC Roles",         "AD DS · DHCP · DNS",  C["purple"]),
            ("DC OS",            "Windows Server 2019",  C["txt"]),
            ("Course",           "RTX2026 | Cyberium Academy", C["txt2"]),
            ("Tool",             f"AD-Sentinel v{TOOL_VERSION}", C["cyan"]),
        ]
        for k, v, col in items:
            r = ctk.CTkFrame(env, fg_color="transparent"); r.pack(fill="x", padx=20, pady=4)
            ctk.CTkLabel(r, text=k + " :", width=180, anchor="w",
                         font=ctk.CTkFont("Consolas", 11),
                         text_color=C["txt2"]).pack(side="left")
            ctk.CTkLabel(r, text=v, anchor="w",
                         font=ctk.CTkFont("Consolas", 11, "bold"),
                         text_color=col).pack(side="left")

        # status card
        stc = card(mid); stc.grid(row=0, column=1, padx=(8,0), sticky="nsew")
        card_title(stc, "◉  SERVICE STATUS")

        self._dots = {}
        for name in ["DC Connectivity","LDAP (389)","DNS (53)",
                     "SMB (445)","RDP (3389)","WinRM (5985)"]:
            r = ctk.CTkFrame(stc, fg_color="transparent"); r.pack(fill="x", padx=20, pady=7)
            ctk.CTkLabel(r, text=name, width=130, anchor="w",
                         font=ctk.CTkFont("Consolas", 11),
                         text_color=C["txt2"]).pack(side="left")
            d = Dot(r); d.pack(side="right")
            self._dots[name] = d

        ctk.CTkFrame(stc, fg_color=C["border"], height=1).pack(fill="x", padx=20, pady=8)
        primary_btn(stc, "⬡  CHECK SERVICES", self._check).pack(padx=20, pady=(0,8), fill="x")
        ghost_btn  (stc, "◎  PING DC",        self._ping ).pack(padx=20, pady=(0,16), fill="x")

    def _check(self):
        threading.Thread(target=self._do_check, daemon=True).start()

    def _do_check(self):
        pairs = [
            ("DC Connectivity", DC_IP, 389),
            ("LDAP (389)",      DC_IP, 389),
            ("DNS (53)",        DC_IP, 53),
            ("SMB (445)",       DC_IP, 445),
            ("RDP (3389)",      DC_IP, 3389),
            ("WinRM (5985)",    DC_IP, 5985),
        ]
        for name, ip, port in pairs:
            ok = port_open(ip, port)
            st = "online" if ok else "offline"
            self.after(0, lambda n=name, s=st: self._dots[n].update(s))
            time.sleep(0.1)

    def _ping(self):
        def go():
            r = run_cmd(f"ping -c 4 {DC_IP}")
            self.after(0, lambda: messagebox.showinfo("Ping Result", r[:600]))
        threading.Thread(target=go, daemon=True).start()

    def update(self, hosts=None, users=None, groups=None, finds=None, risk=None):
        if hosts  is not None: self.m_hosts.set(hosts)
        if users  is not None: self.m_users.set(users)
        if groups is not None: self.m_groups.set(groups)
        if finds  is not None: self.m_finds.set(finds)
        if risk   is not None: self.m_risk.set(risk)


# ═══════════════════════════════════════════════════════════════════
# TAB 2 — NETWORK SCAN
# ═══════════════════════════════════════════════════════════════════
class NetworkTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app; self._running = False
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="⬡  NETWORK DISCOVERY",
                     font=ctk.CTkFont("Consolas", 22, "bold"),
                     text_color=C["cyan"]).pack(anchor="w", pady=(0, 14))

        # controls
        cc = card(self); cc.pack(fill="x", pady=(0, 10))
        inner = ctk.CTkFrame(cc, fg_color="transparent")
        inner.pack(padx=20, pady=14, fill="x")
        for i in range(5): inner.grid_columnconfigure(i, weight=1)

        def lbl(text, col):
            ctk.CTkLabel(inner, text=text, font=ctk.CTkFont("Consolas", 9),
                         text_color=C["txt2"]).grid(row=0, column=col, sticky="w")
        def ent(col, default, **kw):
            e = ctk.CTkEntry(inner, fg_color=C["bg0"], border_color=C["border"],
                              font=ctk.CTkFont("Consolas", 11), height=34, **kw)
            e.insert(0, default); e.grid(row=1, column=col, padx=(0,8), sticky="ew")
            return e

        lbl("SUBNET", 0);    self._subnet = ent(0, SUBNET)
        lbl("SCAN MODE", 1)
        self._mode = ctk.CTkComboBox(inner,
            values=["Host Discovery (ping)", "TCP SYN - Common Ports",
                    "Service Version (-sV)", "Full Aggressive (-A)"],
            fg_color=C["bg0"], border_color=C["border"],
            font=ctk.CTkFont("Consolas", 11), height=34)
        self._mode.set("Host Discovery (ping)")
        self._mode.grid(row=1, column=1, padx=(0,8), sticky="ew")
        lbl("PORT LIST", 2);  self._ports = ent(2, "22,53,80,135,389,445,3389,5985")

        self._btn = primary_btn(inner, "▶  START SCAN", self._start)
        self._btn.grid(row=1, column=3, padx=(0,8), sticky="ew")
        ghost_btn(inner, "✕  CLEAR", self._clear).grid(row=1, column=4, sticky="ew")

        # progress
        self._prog = ctk.CTkProgressBar(self, fg_color=C["bg2"],
                                         progress_color=C["cyan"], height=3)
        self._prog.set(0); self._prog.pack(fill="x", pady=(0, 8))

        # main area
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=3); body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        tc = card(body); tc.grid(row=0, column=0, padx=(0,8), sticky="nsew")
        card_title(tc, "◈  DISCOVERED HOSTS")
        self._tbl = Grid(tc, ["IP Address","Hostname","Status","Open Ports","Notes"])
        self._tbl.tv.column("IP Address", width=130)
        self._tbl.tv.column("Hostname",   width=170)
        self._tbl.tv.column("Status",     width=80)
        self._tbl.tv.column("Open Ports", width=220)
        self._tbl.tv.column("Notes",      width=120)
        self._tbl.pack(fill="both", expand=True, padx=14, pady=14)

        lc = card(body); lc.grid(row=0, column=1, padx=(8,0), sticky="nsew")
        card_title(lc, "◉  SCAN LOG")
        self._log = LogBox(lc, height=300)
        self._log.pack(fill="both", expand=True, padx=12, pady=12)

    def _start(self):
        if self._running: return
        self._running = True
        self._btn.configure(text="⟳  SCANNING…", state="disabled")
        self._prog.configure(mode="indeterminate"); self._prog.start()
        self._tbl.clear(); self._log.clear()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        subnet = self._subnet.get() or SUBNET
        mode   = self._mode.get()
        ports  = self._ports.get() or "22,80,135,389,445,3389"

        self.after(0, lambda: self._log.log(f"Scanning {subnet}", "hdr"))

        if "ping" in mode.lower():
            cmd = f"nmap -sn {subnet} -oG -"
        elif "SYN" in mode:
            cmd = f"nmap -sS -p {ports} {subnet} --open -oG -"
        elif "Version" in mode:
            cmd = f"nmap -sV -p {ports} {subnet} --open -oG -"
        else:
            cmd = f"nmap -A -p {ports} {subnet} --open -oG -"

        self.after(0, lambda: self._log.log(f"CMD: {cmd}", "info"))
        out = run_cmd(cmd, timeout=180)

        found = 0
        for line in out.splitlines():
            if not line.startswith("Host:"): continue
            parts = line.split("\t")
            ip = hn = ports_str = ""
            for p in parts:
                p = p.strip()
                if p.startswith("Host:"):
                    tok = p[5:].strip().split()
                    ip  = tok[0] if tok else ""
                    hn  = tok[1].strip("()") if len(tok)>1 else ""
                elif p.startswith("Ports:"):
                    pl = []
                    for pe in p[6:].split(","):
                        if "/open/" in pe:
                            pnum = pe.split("/")[0]
                            psvc = pe.split("/")[4] if len(pe.split("/"))>4 else ""
                            pl.append(f"{pnum}/{psvc}")
                    ports_str = " ".join(pl[:6])

            if ip:
                found += 1
                note = "DC" if ip == DC_IP else ("Kali" if ip == KALI_IP else "")
                tag  = "online"
                self.after(0, lambda i=ip, h=hn, o=ports_str, n=note, t=tag:
                           self._tbl.add([i, h or "—", "Up", o or "—", n], (t,)))
                self.after(0, lambda i=ip: self._log.log(f"Host up: {i}", "ok"))

        if found == 0:
            self.after(0, lambda: self._log.log("nmap returned nothing — trying ping sweep…", "warn"))
            self._ping_sweep(subnet)
        else:
            self.after(0, lambda: self._log.log(f"Done — {found} hosts", "ok"))

        self.after(0, lambda: self.app.dash.update(hosts=found or "?"))
        self.after(0, self._done)

    def _ping_sweep(self, subnet):
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            up  = 0
            for h in list(net.hosts())[:30]:
                ip = str(h)
                r  = run_cmd(f"ping -c 1 -W 1 {ip}", timeout=3)
                if "bytes from" in r or "1 received" in r:
                    up += 1
                    try: hn = socket.gethostbyaddr(ip)[0]
                    except: hn = "—"
                    self.after(0, lambda i=ip, hn=hn:
                               self._tbl.add([i, hn, "Up", "—", ""], ("online",)))
                    self.after(0, lambda i=ip: self._log.log(f"Alive: {i}", "ok"))
        except Exception as e:
            self.after(0, lambda: self._log.log(str(e), "err"))

    def _done(self):
        self._running = False
        self._btn.configure(text="▶  START SCAN", state="normal")
        self._prog.stop(); self._prog.configure(mode="determinate"); self._prog.set(1)

    def _clear(self):
        self._tbl.clear(); self._log.clear(); self._prog.set(0)


# ═══════════════════════════════════════════════════════════════════
# TAB 3 — AD ENUMERATION
# ═══════════════════════════════════════════════════════════════════
class ADTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app; self.conn = None
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="◎  ACTIVE DIRECTORY ENUMERATION",
                     font=ctk.CTkFont("Consolas", 22, "bold"),
                     text_color=C["cyan"]).pack(anchor="w", pady=(0, 14))

        # connection bar
        cc = card(self); cc.pack(fill="x", pady=(0, 10))
        inn = ctk.CTkFrame(cc, fg_color="transparent")
        inn.pack(padx=20, pady=14, fill="x")
        for i in range(6): inn.grid_columnconfigure(i, weight=1)

        self._ef = {}
        defs = [("DC IP", "DC_IP", DC_IP, False),
                ("DOMAIN", "DOM", DOMAIN, False),
                ("USERNAME", "USR", "Administrator", False),
                ("PASSWORD", "PWD", "", True)]

        for col, (lbl, key, dflt, hide) in enumerate(defs):
            ctk.CTkLabel(inn, text=lbl, font=ctk.CTkFont("Consolas", 9),
                         text_color=C["txt2"]).grid(row=0, column=col, sticky="w")
            e = ctk.CTkEntry(inn, fg_color=C["bg0"], border_color=C["border"],
                              font=ctk.CTkFont("Consolas", 11), height=34,
                              show="*" if hide else "")
            if dflt: e.insert(0, dflt)
            e.grid(row=1, column=col, padx=(0,8), sticky="ew")
            self._ef[key] = e

        primary_btn(inn, "⟳  CONNECT", self._connect).grid(row=1, column=4, padx=(0,8), sticky="ew")

        self._status = ctk.CTkLabel(inn, text="● DISCONNECTED",
                                     font=ctk.CTkFont("Consolas", 11),
                                     text_color=C["red"])
        self._status.grid(row=1, column=5)

        # sub-tabs
        self._st = ctk.CTkTabview(self,
            fg_color=C["bg2"],
            segmented_button_fg_color=C["bg1"],
            segmented_button_selected_color=C["blue"],
            segmented_button_selected_hover_color=C["cyan"],
            segmented_button_unselected_color=C["bg1"],
            segmented_button_unselected_hover_color=C["bg3"],
            text_color=C["txt"],
            border_width=1, border_color=C["border"], corner_radius=12)
        self._st.pack(fill="both", expand=True)

        self._panels = {}
        specs = [
            ("◎  Users",     "users",     ["Username","Full Name","Email","Enabled","Last Logon","Description"]),
            ("◈  Groups",    "groups",    ["Group Name","Members","Scope","Description"]),
            ("⬡  Computers","computers", ["Name","OS","Last Logon","DNS Host","Description"]),
            ("◉  OUs",       "ous",       ["OU Name","Distinguished Name"]),
            ("⚠  Admins",   "admins",    ["Username","Full Name","Group","Last Logon","Enabled"]),
        ]
        for tab_name, key, cols in specs:
            self._st.add(tab_name)
            self._panels[key] = self._make_panel(self._st.tab(tab_name), key, cols)

    def _make_panel(self, parent, key, cols):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="both", expand=True, padx=8, pady=8)
        f.grid_columnconfigure(0, weight=3); f.grid_columnconfigure(1, weight=1)
        f.grid_rowconfigure(1, weight=1)

        bt = ctk.CTkFrame(f, fg_color="transparent")
        bt.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0,8))

        cb = getattr(self, f"_enum_{key}")
        primary_btn(bt, f"▶  ENUMERATE {key.upper()}",
                    lambda k=key: threading.Thread(target=cb, daemon=True).start()
                    ).pack(side="left")

        tbl = Grid(f, cols)
        tbl.grid(row=1, column=0, padx=(0,8), sticky="nsew")

        lf = ctk.CTkFrame(f, fg_color=C["bg1"], corner_radius=8,
                           border_width=1, border_color=C["border"])
        lf.grid(row=1, column=1, sticky="nsew")
        log = LogBox(lf, height=200)
        log.pack(fill="both", expand=True, padx=8, pady=8)

        setattr(self, f"_tbl_{key}", tbl)
        setattr(self, f"_log_{key}", log)
        return {"tbl": tbl, "log": log}

    def _base_dn(self):
        domain = self._ef["DOM"].get() or DOMAIN
        return ",".join(f"DC={p}" for p in domain.split("."))

    def _connect(self):
        if not LDAP_AVAILABLE:
            messagebox.showerror("Missing library",
                "ldap3 not installed.\n\nRun:  pip install ldap3"); return
        threading.Thread(target=self._do_connect, daemon=True).start()

    def _do_connect(self):
        ip  = self._ef["DC_IP"].get() or DC_IP
        dom = self._ef["DOM"].get()   or DOMAIN
        usr = self._ef["USR"].get()
        pwd = self._ef["PWD"].get()
        self.after(0, lambda: self._status.configure(text="⟳ CONNECTING…", text_color=C["yellow"]))
        try:
            srv  = Server(ip, get_info=ALL)
            self.conn = Connection(srv, user=f"{dom}\\{usr}", password=pwd,
                                   authentication=NTLM, auto_bind=True)
            self.after(0, lambda: self._status.configure(text="● CONNECTED", text_color=C["green"]))
        except Exception as e:
            self.conn = None
            self.after(0, lambda: self._status.configure(text="● FAILED", text_color=C["red"]))
            self.after(0, lambda: messagebox.showerror("LDAP Error", str(e)))

    # ── enumerators ────────────────────────────────────────────────
    def _need_conn(self, key):
        log = getattr(self, f"_log_{key}")
        if not self.conn:
            self.after(0, lambda: log.log("Not connected — click CONNECT first", "err"))
            return False
        return True

    def _enum_users(self):
        key = "users"
        if not self._need_conn(key): return
        log = self._log_users; tbl = self._tbl_users
        self.after(0, lambda: log.log("Enumerating users…", "hdr"))
        self.after(0, tbl.clear)
        try:
            self.conn.search(self._base_dn(), "(objectClass=user)",
                attributes=["sAMAccountName","displayName","mail",
                            "userAccountControl","lastLogon","description"])
            n = 0
            for e in self.conn.entries:
                u = str(e.sAMAccountName) if e.sAMAccountName else ""
                if u.endswith("$"): continue
                fn  = str(e.displayName)       if e.displayName else ""
                em  = str(e.mail)              if e.mail        else ""
                try:
                    uac = int(str(e.userAccountControl)) if e.userAccountControl else 0
                except:
                    uac = 0
                en  = "Yes" if not (uac & 0x2) else "No"
                try:
                    ll = str(e.lastLogon.value)[:10] if e.lastLogon and e.lastLogon.value else "Never"
                except:
                    ll = "Never"
                d   = str(e.description)       if e.description else ""
                tag = () if en == "Yes" else ("offline",)
                self.after(0, lambda a=u,b=fn,c=em,d2=en,f=ll,g=d,t=tag:
                           tbl.add([a,b,c,d2,f,g], t))
                n += 1
            self.after(0, lambda: log.log(f"{n} user accounts found", "ok"))
            self.after(0, lambda: self.app.dash.update(users=n))
        except Exception as ex:
            self.after(0, lambda: log.log(str(ex), "err"))

    def _enum_groups(self):
        key = "groups"
        if not self._need_conn(key): return
        log = self._log_groups; tbl = self._tbl_groups
        self.after(0, lambda: log.log("Enumerating groups…", "hdr"))
        self.after(0, tbl.clear)
        try:
            self.conn.search(self._base_dn(), "(objectClass=group)",
                attributes=["cn","member","groupType","description"])
            SCOPE = {-2147483640:"Global Sec",-2147483646:"Global Sec",
                     -2147483644:"Domain Local",-2147483643:"Universal"}
            n = 0
            for e in self.conn.entries:
                nm  = str(e.cn)          if e.cn          else ""
                try:
                    mb = str(len(e.member.values)) if e.member else "0"
                except:
                    mb = "?"
                try:
                    gt = int(str(e.groupType)) if e.groupType else 0
                except:
                    gt = 0
                sc  = SCOPE.get(gt, "Security")
                d   = str(e.description) if e.description else ""
                self.after(0, lambda a=nm,b=mb,c=sc,d2=d: tbl.add([a,b,c,d2]))
                n += 1
            self.after(0, lambda: log.log(f"{n} groups found", "ok"))
            self.after(0, lambda: self.app.dash.update(groups=n))
        except Exception as ex:
            self.after(0, lambda: log.log(str(ex), "err"))

    def _enum_computers(self):
        key = "computers"
        if not self._need_conn(key): return
        log = self._log_computers; tbl = self._tbl_computers
        self.after(0, lambda: log.log("Enumerating computers…", "hdr"))
        self.after(0, tbl.clear)
        try:
            self.conn.search(self._base_dn(), "(objectClass=computer)",
                attributes=["cn","operatingSystem","lastLogon","dNSHostName","description"])
            n = 0
            for e in self.conn.entries:
                nm  = str(e.cn)              if e.cn             else ""
                os_ = str(e.operatingSystem) if e.operatingSystem else "Unknown"
                ll  = str(e.lastLogon)[:10]  if e.lastLogon      else "Never"
                dns = str(e.dNSHostName)     if e.dNSHostName    else ""
                d   = str(e.description)     if e.description    else ""
                self.after(0, lambda a=nm,b=os_,c=ll,d2=dns,f=d: tbl.add([a,b,c,d2,f]))
                n += 1
            self.after(0, lambda: log.log(f"{n} computers found", "ok"))
        except Exception as ex:
            self.after(0, lambda: log.log(str(ex), "err"))

    def _enum_ous(self):
        key = "ous"
        if not self._need_conn(key): return
        log = self._log_ous; tbl = self._tbl_ous
        self.after(0, lambda: log.log("Enumerating OUs…", "hdr"))
        self.after(0, tbl.clear)
        try:
            self.conn.search(self._base_dn(), "(objectClass=organizationalUnit)",
                attributes=["ou","distinguishedName"])
            n = 0
            for e in self.conn.entries:
                nm = str(e.ou)                if e.ou                 else ""
                dn = str(e.distinguishedName) if e.distinguishedName  else ""
                self.after(0, lambda a=nm,b=dn: tbl.add([a,b]))
                n += 1
            self.after(0, lambda: log.log(f"{n} OUs found", "ok"))
        except Exception as ex:
            self.after(0, lambda: log.log(str(ex), "err"))

    def _enum_admins(self):
        key = "admins"
        if not self._need_conn(key): return
        log = self._log_admins; tbl = self._tbl_admins
        self.after(0, lambda: log.log("Enumerating privileged accounts…", "hdr"))
        self.after(0, tbl.clear)
        bd = self._base_dn()
        groups = [
            ("Domain Admins",    f"CN=Domain Admins,CN=Users,{bd}"),
            ("Enterprise Admins",f"CN=Enterprise Admins,CN=Users,{bd}"),
            ("Administrators",   f"CN=Administrators,CN=Builtin,{bd}"),
        ]
        try:
            n = 0
            for gname, gdn in groups:
                self.conn.search(bd, f"(&(objectClass=user)(memberOf={gdn}))",
                    attributes=["sAMAccountName","displayName","lastLogon","userAccountControl"])
                for e in self.conn.entries:
                    u  = str(e.sAMAccountName) if e.sAMAccountName else ""
                    fn = str(e.displayName)    if e.displayName    else ""
                    try:
                        ll = str(e.lastLogon.value)[:10] if e.lastLogon and e.lastLogon.value else "Never"
                    except:
                        ll = "Never"
                    try:
                        uac = int(str(e.userAccountControl)) if e.userAccountControl else 0
                    except:
                        uac = 0
                    en = "Yes" if not (uac & 0x2) else "No"
                    self.after(0, lambda a=u,b=fn,c=gname,d2=ll,f=en:
                               tbl.add([a,b,c,d2,f], ("critical",)))
                    n += 1
            self.after(0, lambda: log.log(f"{n} privileged accounts found", "warn"))
        except Exception as ex:
            self.after(0, lambda: log.log(str(ex), "err"))


# ═══════════════════════════════════════════════════════════════════
# TAB 4 — SECURITY AUDIT
# ═══════════════════════════════════════════════════════════════════
class AuditTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app; self._findings = []
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="⚠  SECURITY AUDIT",
                     font=ctk.CTkFont("Consolas", 22, "bold"),
                     text_color=C["cyan"]).pack(anchor="w", pady=(0, 14))

        # module selector
        mc = card(self); mc.pack(fill="x", pady=(0, 10))
        inn = ctk.CTkFrame(mc, fg_color="transparent")
        inn.pack(padx=20, pady=14, fill="x")
        ctk.CTkLabel(inn, text="AUDIT MODULES",
                     font=ctk.CTkFont("Consolas", 9), text_color=C["txt2"]).pack(anchor="w", pady=(0,6))

        row = ctk.CTkFrame(inn, fg_color="transparent"); row.pack(fill="x")
        self._checks = {}
        modules = ["Null Sessions","SMB Signing","Password Policy",
                   "Open Ports","Kerberos Checks","Stale Accounts",
                   "Anonymous LDAP","Admin Exposure"]
        for m in modules:
            v = tk.BooleanVar(value=True)
            self._checks[m] = v
            ctk.CTkCheckBox(row, text=m, variable=v,
                             font=ctk.CTkFont("Consolas", 11),
                             fg_color=C["blue"], checkmark_color="white",
                             border_color=C["border"]).pack(side="left", padx=10)

        btn_row = ctk.CTkFrame(mc, fg_color="transparent")
        btn_row.pack(padx=20, pady=(0,14), fill="x")
        primary_btn(btn_row, "⚡  RUN ALL AUDITS", self._run, color=C["orange"]).pack(side="left", padx=(0,8))
        ghost_btn  (btn_row, "✕  CLEAR",           self._clear).pack(side="left")

        # body
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=3); body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        tc = card(body); tc.grid(row=0, column=0, padx=(0,8), sticky="nsew")
        card_title(tc, "◈  SECURITY FINDINGS")
        self._tbl = Grid(tc, ["Risk","Category","Finding","Recommendation"])
        self._tbl.tv.column("Risk", width=80)
        self._tbl.tv.column("Category", width=130)
        self._tbl.tv.column("Finding", width=280)
        self._tbl.tv.column("Recommendation", width=240)
        self._tbl.pack(fill="both", expand=True, padx=14, pady=14)

        sc = card(body); sc.grid(row=0, column=1, padx=(8,0), sticky="nsew")
        card_title(sc, "◉  RISK SUMMARY")

        self._rlbls = {}
        for risk, col in [("CRITICAL",C["red"]),("HIGH",C["orange"]),
                           ("MEDIUM",C["yellow"]),("LOW",C["green"]),("INFO",C["txt2"])]:
            r = ctk.CTkFrame(sc, fg_color="transparent"); r.pack(fill="x", padx=20, pady=7)
            ctk.CTkLabel(r, text="●", text_color=col,
                         font=ctk.CTkFont(size=13)).pack(side="left")
            ctk.CTkLabel(r, text=f"  {risk}", text_color=C["txt2"],
                         font=ctk.CTkFont("Consolas", 11)).pack(side="left")
            lbl = ctk.CTkLabel(r, text="0", text_color=col,
                                font=ctk.CTkFont("Consolas", 20, "bold"))
            lbl.pack(side="right"); self._rlbls[risk] = lbl

        ctk.CTkFrame(sc, fg_color=C["border"], height=1).pack(fill="x", padx=20, pady=6)
        ctk.CTkLabel(sc, text="RISK SCORE", font=ctk.CTkFont("Consolas", 9),
                     text_color=C["txt2"]).pack(padx=20, anchor="w")
        self._score_lbl = ctk.CTkLabel(sc, text="—",
            font=ctk.CTkFont("Consolas", 42, "bold"), text_color=C["red"])
        self._score_lbl.pack(padx=20, anchor="w")
        ctk.CTkLabel(sc, text="out of 100", font=ctk.CTkFont("Consolas", 10),
                     text_color=C["txt2"]).pack(padx=20, anchor="w")
        self._rbar = ctk.CTkProgressBar(sc, fg_color=C["bg0"],
                                         progress_color=C["red"], height=8, corner_radius=4)
        self._rbar.set(0); self._rbar.pack(padx=20, pady=8, fill="x")
        ctk.CTkFrame(sc, fg_color=C["border"], height=1).pack(fill="x", padx=20)
        self._alog = LogBox(sc, height=180)
        self._alog.pack(fill="both", expand=True, padx=10, pady=10)

    def _add(self, risk, cat, finding, rec):
        self._findings.append((risk, cat, finding, rec))
        tag = risk.lower()
        self.after(0, lambda: self._tbl.add([risk, cat, finding, rec], (tag,)))
        self._refresh_counts()

    def _refresh_counts(self):
        cnt = {k:0 for k in self._rlbls}
        for f in self._findings:
            if f[0] in cnt: cnt[f[0]] += 1
        for k, v in cnt.items():
            self.after(0, lambda k=k, v=v: self._rlbls[k].configure(text=str(v)))

    def _calc_score(self):
        W = {"CRITICAL":25,"HIGH":15,"MEDIUM":8,"LOW":3,"INFO":0}
        s = min(sum(W.get(f[0],0) for f in self._findings), 100)
        col = C["red"] if s>=70 else C["orange"] if s>=40 else C["yellow"] if s>=20 else C["green"]
        self.after(0, lambda: self._score_lbl.configure(text=str(s), text_color=col))
        self.after(0, lambda: self._rbar.set(s/100))
        self.after(0, lambda: self.app.dash.update(finds=len(self._findings), risk=s))

    def _run(self):
        self._clear()
        threading.Thread(target=self._do_run, daemon=True).start()

    def _do_run(self):
        self.after(0, lambda: self._alog.log("Starting security audit…", "hdr"))
        self._check_ports()
        if self._checks.get("Null Sessions",     tk.BooleanVar(value=False)).get():
            self._check_null()
        if self._checks.get("SMB Signing",       tk.BooleanVar(value=False)).get():
            self._check_smb()
        if self._checks.get("Password Policy",   tk.BooleanVar(value=False)).get():
            self._check_pwd()
        if self._checks.get("Anonymous LDAP",    tk.BooleanVar(value=False)).get():
            self._check_anon_ldap()
        self._calc_score()
        self.after(0, lambda: self._alog.log(f"Done — {len(self._findings)} findings", "ok"))

    def _check_ports(self):
        self.after(0, lambda: self._alog.log("Scanning DC ports…", "info"))
        PORT_MAP = {
            23:  ("CRITICAL","Telnet","Telnet service open","Disable Telnet — use SSH"),
            21:  ("HIGH","FTP","FTP service open (plaintext)","Use SFTP or FTPS"),
            5985:("MEDIUM","WinRM HTTP","WinRM HTTP exposed","Switch to HTTPS (5986)"),
            3389:("MEDIUM","RDP","RDP open to network","Restrict via firewall / VPN"),
            389: ("INFO","LDAP","LDAP port open (DC expected)","Prefer LDAPS (636)"),
            636: ("INFO","LDAPS","LDAPS port open — good","Continue using LDAPS"),
            445: ("INFO","SMB","SMB open (DC expected)","Ensure signing is required"),
        }
        for port, (risk, cat, finding, rec) in PORT_MAP.items():
            if port_open(DC_IP, port):
                self._add(risk, cat, f"Port {port}/tcp — {finding}", rec)
                self.after(0, lambda p=port: self._alog.log(f"Port {p} open", "warn"))

    def _check_null(self):
        self.after(0, lambda: self._alog.log("Testing null sessions…", "info"))
        r = run_cmd(f"rpcclient -U '' -N {DC_IP} -c 'enumdomusers' 2>&1", timeout=12)
        if "result was NT_STATUS_OK" in r or "user:[" in r:
            self._add("CRITICAL","Null Session",
                      "Anonymous null session allowed on IPC$",
                      "Set RestrictAnonymous=2 via GPO")
            self.after(0, lambda: self._alog.log("CRITICAL: Null session allowed!", "err"))
        else:
            self.after(0, lambda: self._alog.log("Null sessions blocked — OK", "ok"))

    def _check_smb(self):
        self.after(0, lambda: self._alog.log("Checking SMB signing…", "info"))
        r = run_cmd(f"nmap -p 445 --script smb-security-mode {DC_IP}", timeout=30).lower()
        if "message_signing: disabled" in r:
            self._add("HIGH","SMB Signing","SMB signing disabled — relay attacks possible",
                      "Enable via GPO: RequireSecuritySignature=1")
        elif "enabled but not required" in r:
            self._add("MEDIUM","SMB Signing","SMB signing not enforced",
                      "Enforce: EnableSecuritySignature=1 + RequireSecuritySignature=1")
        else:
            self.after(0, lambda: self._alog.log("SMB signing check complete", "ok"))

    def _check_pwd(self):
        self.after(0, lambda: self._alog.log("Checking password policy…", "info"))
        r = run_cmd(f"rpcclient -U '' -N {DC_IP} -c 'getdompwinfo' 2>&1", timeout=12)
        import re
        m = re.search(r'min_password_length: (\d+)', r)
        if m:
            length = int(m.group(1))
            if length == 0:
                self._add("CRITICAL","Password Policy","Min password length = 0","Set min length ≥ 12")
            elif length < 8:
                self._add("HIGH","Password Policy",f"Min password length too short ({length})","Increase to ≥ 12")
            elif length < 12:
                self._add("MEDIUM","Password Policy",f"Min password length = {length}","Consider ≥ 12")
        if "DOMAIN_PASSWORD_COMPLEX" not in r and "NT_STATUS_OK" in r:
            self._add("HIGH","Password Policy","Password complexity disabled",
                      "Enable complexity in Default Domain Policy")

    def _check_anon_ldap(self):
        self.after(0, lambda: self._alog.log("Testing anonymous LDAP bind…", "info"))
        if not LDAP_AVAILABLE:
            self.after(0, lambda: self._alog.log("ldap3 not installed — skipping", "warn"))
            return
        try:
            from ldap3 import Server as S2, Connection as C2, ANONYMOUS, ALL as ALL2
            srv  = S2(DC_IP, get_info=ALL2)
            conn = C2(srv, authentication=ANONYMOUS, auto_bind=True)
            if conn.bound:
                self._add("HIGH","Anonymous LDAP",
                          "Anonymous LDAP bind succeeded — data exposed",
                          "Disable anonymous LDAP: set dsHeuristics")
                self.after(0, lambda: self._alog.log("Anonymous LDAP bind succeeded!", "err"))
            conn.unbind()
        except:
            self.after(0, lambda: self._alog.log("Anonymous LDAP blocked — OK", "ok"))

    def _clear(self):
        self._findings.clear(); self._tbl.clear(); self._alog.clear()
        self._score_lbl.configure(text="—"); self._rbar.set(0)
        for l in self._rlbls.values(): l.configure(text="0")

    @property
    def findings(self): return self._findings


# ═══════════════════════════════════════════════════════════════════
# TAB 5 — REPORTS
# ═══════════════════════════════════════════════════════════════════
class ReportTab(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app; self._build()

    def _build(self):
        ctk.CTkLabel(self, text="◈  REPORT GENERATOR",
                     font=ctk.CTkFont("Consolas", 22, "bold"),
                     text_color=C["cyan"]).pack(anchor="w", pady=(0, 14))

        oc = card(self); oc.pack(fill="x", pady=(0, 10))
        inn = ctk.CTkFrame(oc, fg_color="transparent")
        inn.pack(padx=20, pady=14, fill="x")
        for i in range(4): inn.grid_columnconfigure(i, weight=1)

        def ent(col, label, default):
            ctk.CTkLabel(inn, text=label, font=ctk.CTkFont("Consolas", 9),
                         text_color=C["txt2"]).grid(row=0, column=col, sticky="w")
            e = ctk.CTkEntry(inn, fg_color=C["bg0"], border_color=C["border"],
                              font=ctk.CTkFont("Consolas", 11), height=34)
            if default: e.insert(0, default)
            e.grid(row=1, column=col, padx=(0,8), sticky="ew")
            return e

        self._title  = ent(0, "REPORT TITLE",  "AD Security Assessment — Lab RTX2026")
        self._author = ent(1, "AUTHOR",         "Itay Bechor")
        ctk.CTkLabel(inn, text="FORMAT", font=ctk.CTkFont("Consolas", 9),
                     text_color=C["txt2"]).grid(row=0, column=2, sticky="w")
        self._fmt = ctk.CTkComboBox(inn, values=["HTML Report","JSON Export","Text Summary"],
                                     fg_color=C["bg0"], border_color=C["border"],
                                     font=ctk.CTkFont("Consolas", 11), height=34)
        self._fmt.set("HTML Report")
        self._fmt.grid(row=1, column=2, padx=(0,8), sticky="ew")
        primary_btn(inn, "⬡  GENERATE", self._generate, color=C["purple"]).grid(
            row=1, column=3, sticky="ew")

        pc = card(self); pc.pack(fill="both", expand=True)
        card_title(pc, "◈  REPORT PREVIEW")
        self._prev = ctk.CTkTextbox(pc,
            fg_color=C["bg0"], text_color=C["txt"],
            font=ctk.CTkFont("Consolas", 11), border_width=0, corner_radius=8)
        self._prev.pack(fill="both", expand=True, padx=16, pady=16)
        self._refresh_preview()

    def _refresh_preview(self):
        t = f"""
╔══════════════════════════════════════════════════════════════════╗
║                 AD-SENTINEL REPORT PREVIEW                       ║
╚══════════════════════════════════════════════════════════════════╝

  Title    : AD Security Assessment — Lab RTX2026
  Author   : Itay Bechor
  Date     : {now_full()}
  Course   : RTX2026 | Network Security | Cyberium Academy

  Target DC   : {DC_IP} ({DOMAIN})
  Attacker    : {KALI_IP} (Kali Linux 3)
  Subnet      : {SUBNET}
  DC Roles    : AD DS · DHCP · DNS

──────────────────────────────────────────────────────────────────
  Run the Security Audit tab to populate findings.
  Click  ⬡ GENERATE  to export a full report file.
──────────────────────────────────────────────────────────────────
"""
        self._prev.configure(state="normal")
        self._prev.delete("1.0","end"); self._prev.insert("1.0", t)
        self._prev.configure(state="disabled")

    def _generate(self):
        fmt     = self._fmt.get()
        title   = self._title.get()
        author  = self._author.get()
        findings= self.app.audit.findings

        if "HTML" in fmt:   self._html(title, author, findings)
        elif "JSON" in fmt: self._json(title, author, findings)
        else:               self._text(title, author, findings)

    def _html(self, title, author, findings):
        rows = ""
        for risk, cat, finding, rec in findings:
            col = {"CRITICAL":C["red"],"HIGH":C["orange"],"MEDIUM":C["yellow"],
                   "LOW":C["green"],"INFO":C["txt2"]}.get(risk,"#888")
            rows += f"""<tr>
  <td><span style="background:{col}22;color:{col};border:1px solid {col}55;
      padding:2px 8px;border-radius:4px;font-size:10px">{risk}</span></td>
  <td>{cat}</td><td>{finding}</td><td>{rec}</td>
</tr>"""

        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>{title}</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{background:{C["bg0"]};color:{C["txt"]};font-family:Consolas,monospace;padding:40px}}
  h1{{font-size:24px;color:{C["cyan"]};letter-spacing:4px;border-bottom:2px solid {C["cyan"]};
      padding-bottom:16px;margin-bottom:24px}}
  .meta{{color:{C["txt2"]};font-size:12px;margin-bottom:32px;line-height:2}}
  .card{{background:{C["bg2"]};border-radius:12px;border:1px solid {C["border"]};
         padding:24px;margin-bottom:20px}}
  h2{{color:{C["cyan"]};font-size:12px;letter-spacing:2px;margin-bottom:16px}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:{C["bg0"]};color:{C["cyan"]};padding:10px;text-align:left;font-size:10px;letter-spacing:1px}}
  td{{padding:10px;border-bottom:1px solid {C["border"]};font-size:11px}}
  tr:hover{{background:{C["bg3"]}}}
  .footer{{text-align:center;color:{C["txt3"]};font-size:10px;margin-top:32px}}
</style></head><body>
<h1>◈ AD-SENTINEL  ·  SECURITY REPORT</h1>
<div class="meta">
  <b>Title:</b> {title}<br>
  <b>Author:</b> {author}<br>
  <b>Date:</b> {now_full()}<br>
  <b>Course:</b> RTX2026 | Network Security | Cyberium Academy
</div>
<div class="card">
  <h2>◎ ENVIRONMENT</h2>
  <table><tr><th>KEY</th><th>VALUE</th></tr>
  <tr><td>Domain Controller</td><td>{DC_IP}</td></tr>
  <tr><td>Domain</td><td>{DOMAIN}</td></tr>
  <tr><td>Attacker (Kali)</td><td>{KALI_IP}</td></tr>
  <tr><td>Subnet</td><td>{SUBNET}</td></tr>
  <tr><td>DC Roles</td><td>AD DS · DHCP · DNS</td></tr>
  </table>
</div>
<div class="card">
  <h2>⚠ SECURITY FINDINGS  ({len(findings)} total)</h2>
  <table><tr><th>RISK</th><th>CATEGORY</th><th>FINDING</th><th>RECOMMENDATION</th></tr>
  {rows or '<tr><td colspan="4" style="text-align:center;color:#3a5070">No findings — run Security Audit first</td></tr>'}
  </table>
</div>
<div class="footer">AD-Sentinel v{TOOL_VERSION} · Cyberium Academy · {now_full()}</div>
</body></html>"""

        fp = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("HTML","*.html")],
            initialfile=f"ad_sentinel_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        if fp:
            Path(fp).write_text(html, encoding="utf-8")
            messagebox.showinfo("Saved", f"HTML report saved:\n{fp}")

    def _json(self, title, author, findings):
        d = {
            "title": title, "author": author, "generated": now_full(),
            "environment": {"dc_ip":DC_IP,"domain":DOMAIN,"attacker":KALI_IP,"subnet":SUBNET},
            "findings": [{"risk":f[0],"category":f[1],"finding":f[2],"recommendation":f[3]}
                         for f in findings],
            "summary": {r: sum(1 for f in findings if f[0]==r)
                        for r in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
        }
        fp = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON","*.json")],
            initialfile=f"ad_sentinel_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if fp:
            Path(fp).write_text(json.dumps(d, indent=2), encoding="utf-8")
            messagebox.showinfo("Saved", f"JSON export saved:\n{fp}")

    def _text(self, title, author, findings):
        lines = ["="*70, f"  {title}", "="*70,
                 f"  Author : {author}", f"  Date   : {now_full()}",
                 f"  Target : {DC_IP} ({DOMAIN})", "="*70, ""]
        for risk, cat, finding, rec in findings:
            lines += [f"\n[{risk}] {cat}", f"  Finding : {finding}", f"  Fix     : {rec}"]
        lines += ["", "="*70]
        fp = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text","*.txt")],
            initialfile=f"ad_sentinel_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if fp:
            Path(fp).write_text("\n".join(lines), encoding="utf-8")
            messagebox.showinfo("Saved", f"Text report saved:\n{fp}")


# ═══════════════════════════════════════════════════════════════════
# MAIN APPLICATION WINDOW
# ═══════════════════════════════════════════════════════════════════
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"AD-SENTINEL v{TOOL_VERSION}  ◈  Active Directory Security Auditor")
        self.geometry("1440x900"); self.minsize(1200, 750)
        self.configure(fg_color=C["bg0"])
        self._build()

    def _build(self):
        # ── Top bar ───────────────────────────────────────────────
        tb = ctk.CTkFrame(self, fg_color=C["bg1"], height=54, corner_radius=0)
        tb.pack(fill="x"); tb.pack_propagate(False)

        lf = ctk.CTkFrame(tb, fg_color="transparent"); lf.pack(side="left", padx=22)
        ctk.CTkLabel(lf, text="◈", font=ctk.CTkFont("Consolas",22),
                     text_color=C["cyan"]).pack(side="left", pady=12)
        ctk.CTkLabel(lf, text="  AD-SENTINEL", font=ctk.CTkFont("Consolas",17,"bold"),
                     text_color=C["txt"]).pack(side="left", pady=12)
        ctk.CTkLabel(lf, text=f"  v{TOOL_VERSION}", font=ctk.CTkFont("Consolas",11),
                     text_color=C["txt3"]).pack(side="left", pady=12)

        ctk.CTkLabel(tb,
            text=f"◉ {KALI_IP}  →  {DC_IP}  ·  {DOMAIN}  ·  RTX2026 | Cyberium Academy",
            font=ctk.CTkFont("Consolas",10), text_color=C["txt2"]
        ).pack(side="right", padx=22, pady=12)

        ctk.CTkFrame(self, fg_color=C["border"], height=1).pack(fill="x")

        # ── Tab view ──────────────────────────────────────────────
        self._tv = ctk.CTkTabview(self,
            fg_color=C["bg0"],
            segmented_button_fg_color=C["bg1"],
            segmented_button_selected_color=C["blue"],
            segmented_button_selected_hover_color=C["cyan"],
            segmented_button_unselected_color=C["bg1"],
            segmented_button_unselected_hover_color=C["bg3"],
            text_color=C["txt"],
            border_width=0, corner_radius=0)
        self._tv.pack(fill="both", expand=True)

        TABS = [
            "  ◈  DASHBOARD  ",
            "  ⬡  NETWORK SCAN  ",
            "  ◎  AD ENUMERATION  ",
            "  ⚠  SECURITY AUDIT  ",
            "  ◉  REPORTS  ",
        ]
        for t in TABS: self._tv.add(t)

        self.dash  = DashboardTab(self._tv.tab(TABS[0]), self)
        self.dash.pack(fill="both", expand=True, padx=24, pady=20)

        self.net   = NetworkTab(self._tv.tab(TABS[1]), self)
        self.net.pack(fill="both", expand=True, padx=24, pady=20)

        self.ade   = ADTab(self._tv.tab(TABS[2]), self)
        self.ade.pack(fill="both", expand=True, padx=24, pady=20)

        self.audit = AuditTab(self._tv.tab(TABS[3]), self)
        self.audit.pack(fill="both", expand=True, padx=24, pady=20)

        self.rpt   = ReportTab(self._tv.tab(TABS[4]), self)
        self.rpt.pack(fill="both", expand=True, padx=24, pady=20)

        # ── Status bar ────────────────────────────────────────────
        sb = ctk.CTkFrame(self, fg_color=C["bg1"], height=26, corner_radius=0)
        sb.pack(fill="x", side="bottom"); sb.pack_propagate(False)
        ctk.CTkLabel(sb,
            text=f"  ◈ AD-Sentinel v{TOOL_VERSION}  ·  Target: {DC_IP}  ·  Subnet: {SUBNET}  ·  RTX2026",
            font=ctk.CTkFont("Consolas",10), text_color=C["txt3"]
        ).pack(side="left", pady=4)
        self._tlbl = ctk.CTkLabel(sb, text="", font=ctk.CTkFont("Consolas",10),
                                   text_color=C["txt3"])
        self._tlbl.pack(side="right", padx=16, pady=4)
        self._tick()

    def _tick(self):
        self._tlbl.configure(text=now_full() + "  ")
        self.after(1000, self._tick)


# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    App().mainloop()
