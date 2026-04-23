"""
SQL Injection Attack and Web Firewall Simulation
Cyber Range as a Service - Activity 2
Author: Poornachandra M | 24MSRDF0317 | 4th Sem MSc DFIS

Description:
    A GUI-based simulation of SQL Injection attacks against a mock
    web application, with an integrated Web Application Firewall (WAF)
    that detects, blocks, and logs malicious payloads in real time.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import re
import random
import time
import threading
import hashlib
from datetime import datetime


# ─────────────────────────────────────────────────
#  Mock In-Memory Database
# ─────────────────────────────────────────────────
MOCK_DB = {
    "users": [
        {"id": 1, "username": "admin",    "password": hashlib.md5(b"admin123").hexdigest(),  "role": "administrator", "email": "admin@cyberrange.local"},
        {"id": 2, "username": "alice",    "password": hashlib.md5(b"alice456").hexdigest(),   "role": "user",          "email": "alice@cyberrange.local"},
        {"id": 3, "username": "bob",      "password": hashlib.md5(b"bob789").hexdigest(),     "role": "user",          "email": "bob@cyberrange.local"},
        {"id": 4, "username": "manager",  "password": hashlib.md5(b"mgr2024").hexdigest(),    "role": "manager",       "email": "manager@cyberrange.local"},
    ],
    "products": [
        {"id": 1, "name": "Laptop",   "price": 999.99,  "stock": 50},
        {"id": 2, "name": "Mouse",    "price": 29.99,   "stock": 200},
        {"id": 3, "name": "Monitor",  "price": 349.99,  "stock": 30},
    ],
}


# ─────────────────────────────────────────────────
#  WAF Engine
# ─────────────────────────────────────────────────
WAF_RULES = [
    (r"'.*--",                               "Classic comment bypass"),
    (r"(\bor\b|\band\b)\s+\d+=\d+",         "Boolean-based SQLi"),
    (r"union\s+(all\s+)?select",             "UNION SELECT injection"),
    (r";\s*(drop|delete|insert|update)\b",   "Stacked query injection"),
    (r"sleep\s*\(\s*\d+\s*\)",              "Time-based blind SQLi"),
    (r"benchmark\s*\(",                      "Benchmark time attack"),
    (r"information_schema",                  "Schema enumeration"),
    (r"0x[0-9a-f]{2,}",                     "Hex encoding bypass"),
    (r"char\s*\(\s*\d+",                     "CHAR() encoding bypass"),
    (r"\/\*.*\*\/",                          "Inline comment obfuscation"),
    (r"load_file\s*\(",                      "File read attempt"),
    (r"into\s+(out|dump)file",               "File write attempt"),
    (r"exec\s*\(",                           "EXEC injection"),
    (r"xp_cmdshell",                         "Command shell injection"),
    (r"waitfor\s+delay",                     "MSSQL time delay"),
    (r"'?\s*or\s+'1'\s*=\s*'1",             "Tautology bypass"),
]

WAF_COMPILED = [(re.compile(p, re.IGNORECASE), desc) for p, desc in WAF_RULES]


def waf_inspect(payload: str):
    """Return (blocked: bool, reason: str)."""
    for pattern, desc in WAF_COMPILED:
        if pattern.search(payload):
            return True, desc
    return False, "CLEAN"


# ─────────────────────────────────────────────────
#  Vulnerable Query Simulator
# ─────────────────────────────────────────────────
def simulate_vulnerable_query(username_input: str):
    """
    Simulate how a vulnerable app would construct a raw SQL query
    and return (query_string, result_rows).
    This NEVER executes real SQL – it only models the behaviour.
    """
    raw_query = f"SELECT * FROM users WHERE username = '{username_input}'"

    lower = username_input.lower().strip()

    # Tautology: OR 1=1 style
    if re.search(r"'\s*(or|and)\s+[\d'\"=\s]+--", lower) or "1'='1" in lower or "or '1'='1" in lower:
        return raw_query, list(MOCK_DB["users"])   # returns ALL rows

    # UNION injection – simulate data leakage
    if "union" in lower and "select" in lower:
        leaked = [{"id": "UNION", "username": "LEAKED_DATA", "password": "ALL_HASHES",
                   "role": "N/A", "email": "data@stolen"}]
        return raw_query, leaked

    # Comment-based bypass  ' --
    if "' --" in lower or "'--" in lower:
        return raw_query, list(MOCK_DB["users"])

    # Normal lookup
    matches = [u for u in MOCK_DB["users"] if u["username"] == username_input]
    return raw_query, matches


# ─────────────────────────────────────────────────
#  KNOWN SQLI PAYLOADS FOR THE DEMO PANEL
# ─────────────────────────────────────────────────
SAMPLE_PAYLOADS = [
    ("Tautology (auth bypass)",   "admin' OR '1'='1' --"),
    ("UNION dump all users",      "' UNION SELECT * FROM users --"),
    ("Stacked DROP TABLE",        "admin'; DROP TABLE users; --"),
    ("Time-based blind",          "admin' AND SLEEP(5) --"),
    ("Boolean blind",             "admin' AND 1=1 --"),
    ("Schema enum",               "' UNION SELECT table_name FROM information_schema.tables --"),
    ("Hex encoding bypass",       "0x61646d696e"),
    ("CHAR() bypass",             "' OR CHAR(49)=CHAR(49) --"),
    ("Inline comment",            "ad/**/min"),
    ("Legitimate login",          "alice"),
]


# ─────────────────────────────────────────────────
#  Main Application Window
# ─────────────────────────────────────────────────
class CyberRangeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Range as a Service — SQL Injection & Web Firewall Simulation")
        self.geometry("1200x800")
        self.resizable(True, True)
        self.configure(bg="#0d1117")

        self.waf_enabled = tk.BooleanVar(value=True)
        self.attack_count = 0
        self.blocked_count = 0
        self.allowed_count = 0

        self._build_ui()

    # ── UI Construction ──────────────────────────
    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg="#161b22", pady=8)
        header.pack(fill=tk.X)
        tk.Label(header, text="⚔  CYBER RANGE — SQL Injection Attack & Web Firewall Simulation",
                 font=("Courier New", 14, "bold"), fg="#58a6ff", bg="#161b22").pack(side=tk.LEFT, padx=16)
        tk.Label(header, text="Poornachandra M  |  24MSRDF0317  |  4th Sem MSc DFIS",
                 font=("Courier New", 9), fg="#8b949e", bg="#161b22").pack(side=tk.RIGHT, padx=16)

        # WAF toggle bar
        toggle_bar = tk.Frame(self, bg="#0d1117", pady=6)
        toggle_bar.pack(fill=tk.X, padx=16)
        tk.Checkbutton(toggle_bar, text=" 🔒  Web Application Firewall (WAF) ENABLED",
                       variable=self.waf_enabled, command=self._refresh_waf_label,
                       font=("Courier New", 11, "bold"),
                       fg="#3fb950", bg="#0d1117",
                       selectcolor="#0d1117",
                       activebackground="#0d1117").pack(side=tk.LEFT)
        self.waf_label = tk.Label(toggle_bar, text="WAF: ACTIVE",
                                  font=("Courier New", 11, "bold"), fg="#3fb950", bg="#0d1117")
        self.waf_label.pack(side=tk.LEFT, padx=20)

        # Stat counters
        self.stat_frame = tk.Frame(self, bg="#0d1117")
        self.stat_frame.pack(fill=tk.X, padx=16, pady=2)
        self.lbl_total   = self._stat_label("Requests: 0",   "#58a6ff")
        self.lbl_blocked = self._stat_label("Blocked: 0",    "#f85149")
        self.lbl_allowed = self._stat_label("Allowed: 0",    "#3fb950")

        # Main paned layout
        paned = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg="#0d1117", sashwidth=5)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        left  = self._build_left_panel(paned)
        right = self._build_right_panel(paned)
        paned.add(left,  minsize=380)
        paned.add(right, minsize=380)

    def _stat_label(self, text, color):
        lbl = tk.Label(self.stat_frame, text=text, font=("Courier New", 10, "bold"),
                       fg=color, bg="#0d1117", padx=14)
        lbl.pack(side=tk.LEFT)
        return lbl

    def _build_left_panel(self, parent):
        frame = tk.Frame(parent, bg="#0d1117")

        # Input section
        inp_frame = tk.LabelFrame(frame, text=" 🖥  Simulated Login Form (Vulnerable Endpoint) ",
                                  font=("Courier New", 10, "bold"),
                                  fg="#e6edf3", bg="#161b22", padx=10, pady=10)
        inp_frame.pack(fill=tk.X, padx=4, pady=4)

        tk.Label(inp_frame, text="Username Input:", font=("Courier New", 10),
                 fg="#8b949e", bg="#161b22").pack(anchor=tk.W)
        self.entry_user = tk.Entry(inp_frame, font=("Courier New", 11),
                                   bg="#21262d", fg="#e6edf3",
                                   insertbackground="#58a6ff", relief=tk.FLAT,
                                   highlightthickness=1, highlightcolor="#58a6ff",
                                   width=48)
        self.entry_user.pack(fill=tk.X, pady=4)
        self.entry_user.insert(0, "Enter username or payload…")
        self.entry_user.bind("<FocusIn>",  lambda e: self._clear_placeholder())
        self.entry_user.bind("<Return>",   lambda e: self._execute_attack())

        btn_row = tk.Frame(inp_frame, bg="#161b22")
        btn_row.pack(fill=tk.X, pady=4)
        tk.Button(btn_row, text="▶  Send Request", command=self._execute_attack,
                  font=("Courier New", 10, "bold"),
                  bg="#238636", fg="white", relief=tk.FLAT,
                  padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_row, text="⟳  Reset Logs", command=self._reset_logs,
                  font=("Courier New", 10),
                  bg="#21262d", fg="#8b949e", relief=tk.FLAT,
                  padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT)

        # Sample payloads
        pl_frame = tk.LabelFrame(frame, text=" 🎯  Sample Attack Payloads ",
                                  font=("Courier New", 10, "bold"),
                                  fg="#e6edf3", bg="#161b22", padx=8, pady=6)
        pl_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        tk.Label(pl_frame, text="Click any payload to auto-load it:",
                 font=("Courier New", 9), fg="#8b949e", bg="#161b22").pack(anchor=tk.W)

        for label, payload in SAMPLE_PAYLOADS:
            row = tk.Frame(pl_frame, bg="#161b22")
            row.pack(fill=tk.X, pady=1)
            color = "#f85149" if payload != "alice" else "#3fb950"
            tk.Button(row, text=f"  {label:<30}", font=("Courier New", 9),
                      bg="#21262d", fg=color, relief=tk.FLAT,
                      anchor=tk.W, padx=4, pady=2, cursor="hand2",
                      command=lambda p=payload: self._load_payload(p)).pack(fill=tk.X)

        # WAF rules display
        rule_frame = tk.LabelFrame(frame, text=" 🛡  Active WAF Rules ",
                                    font=("Courier New", 10, "bold"),
                                    fg="#e6edf3", bg="#161b22", padx=8, pady=6)
        rule_frame.pack(fill=tk.X, padx=4, pady=4)

        rules_txt = scrolledtext.ScrolledText(rule_frame, height=7, font=("Courier New", 8),
                                              bg="#0d1117", fg="#8b949e", relief=tk.FLAT)
        rules_txt.pack(fill=tk.X)
        for i, (_, desc) in enumerate(WAF_RULES, 1):
            rules_txt.insert(tk.END, f"  Rule {i:02d}: {desc}\n")
        rules_txt.configure(state=tk.DISABLED)

        return frame

    def _build_right_panel(self, parent):
        frame = tk.Frame(parent, bg="#0d1117")

        nb = ttk.Notebook(frame)
        nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background="#0d1117", borderwidth=0)
        style.configure("TNotebook.Tab", background="#161b22", foreground="#8b949e",
                        font=("Courier New", 9, "bold"), padding=[10, 4])
        style.map("TNotebook.Tab", background=[("selected", "#21262d")],
                  foreground=[("selected", "#e6edf3")])

        # Tab 1 – WAF Log
        waf_tab = tk.Frame(nb, bg="#0d1117")
        nb.add(waf_tab, text="  WAF Log  ")
        self.waf_log = self._make_log(waf_tab)

        # Tab 2 – Query Simulation
        q_tab = tk.Frame(nb, bg="#0d1117")
        nb.add(q_tab, text="  Query Simulation  ")
        self.query_log = self._make_log(q_tab)

        # Tab 3 – DB Response
        db_tab = tk.Frame(nb, bg="#0d1117")
        nb.add(db_tab, text="  DB Response  ")
        self.db_log = self._make_log(db_tab)

        # Tab 4 – Attack Analytics
        self.analytics_tab = tk.Frame(nb, bg="#0d1117")
        nb.add(self.analytics_tab, text="  Analytics  ")
        self._build_analytics()

        return frame

    def _make_log(self, parent):
        txt = scrolledtext.ScrolledText(parent, font=("Courier New", 9),
                                        bg="#0d1117", fg="#e6edf3",
                                        insertbackground="#58a6ff", relief=tk.FLAT)
        txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        txt.tag_config("blocked", foreground="#f85149")
        txt.tag_config("allowed", foreground="#3fb950")
        txt.tag_config("warn",    foreground="#e3b341")
        txt.tag_config("info",    foreground="#58a6ff")
        txt.tag_config("dim",     foreground="#484f58")
        return txt

    def _build_analytics(self):
        self.bar_canvas = tk.Canvas(self.analytics_tab, bg="#0d1117",
                                    highlightthickness=0, height=260)
        self.bar_canvas.pack(fill=tk.X, padx=10, pady=10)

        self.analytics_list = scrolledtext.ScrolledText(self.analytics_tab,
                                                         font=("Courier New", 9),
                                                         bg="#0d1117", fg="#8b949e",
                                                         relief=tk.FLAT, height=14)
        self.analytics_list.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.attack_history = []  # list of (payload, blocked, reason)

    def _draw_bar_chart(self):
        c = self.bar_canvas
        c.delete("all")
        W, H = 700, 240
        total = max(self.attack_count, 1)
        bars = [
            ("Blocked",   self.blocked_count, "#f85149"),
            ("Allowed",   self.allowed_count, "#3fb950"),
        ]
        bar_w, gap = 100, 80
        x = 80
        c.create_text(W // 2, 14, text="Request Summary",
                      fill="#58a6ff", font=("Courier New", 10, "bold"))
        for label, val, color in bars:
            pct = val / total
            bh  = int(pct * 160)
            y1  = 190 - bh
            c.create_rectangle(x, y1, x + bar_w, 190, fill=color, outline="")
            c.create_text(x + bar_w // 2, y1 - 10, text=str(val),
                          fill=color, font=("Courier New", 10, "bold"))
            c.create_text(x + bar_w // 2, 206, text=label,
                          fill="#8b949e", font=("Courier New", 9))
            c.create_text(x + bar_w // 2, 220, text=f"{pct*100:.0f}%",
                          fill=color, font=("Courier New", 8))
            x += bar_w + gap

    # ── Actions ──────────────────────────────────
    def _clear_placeholder(self):
        if self.entry_user.get() == "Enter username or payload…":
            self.entry_user.delete(0, tk.END)

    def _load_payload(self, payload):
        self.entry_user.delete(0, tk.END)
        self.entry_user.insert(0, payload)

    def _refresh_waf_label(self):
        if self.waf_enabled.get():
            self.waf_label.config(text="WAF: ACTIVE", fg="#3fb950")
        else:
            self.waf_label.config(text="WAF: DISABLED ⚠", fg="#f85149")

    def _reset_logs(self):
        for log in (self.waf_log, self.query_log, self.db_log, self.analytics_list):
            log.configure(state=tk.NORMAL)
            log.delete(1.0, tk.END)
            log.configure(state=tk.DISABLED)
        self.attack_count = self.blocked_count = self.allowed_count = 0
        self.attack_history.clear()
        self._update_stats()
        self._draw_bar_chart()

    def _update_stats(self):
        self.lbl_total.config(  text=f"Requests: {self.attack_count}")
        self.lbl_blocked.config(text=f"Blocked: {self.blocked_count}")
        self.lbl_allowed.config(text=f"Allowed: {self.allowed_count}")

    def _append(self, widget, text, tag=None):
        widget.configure(state=tk.NORMAL)
        if tag:
            widget.insert(tk.END, text, tag)
        else:
            widget.insert(tk.END, text)
        widget.see(tk.END)
        widget.configure(state=tk.DISABLED)

    def _execute_attack(self):
        payload = self.entry_user.get().strip()
        if not payload or payload == "Enter username or payload…":
            messagebox.showwarning("Empty Input", "Please enter a username or payload.")
            return

        threading.Thread(target=self._process_request, args=(payload,), daemon=True).start()

    def _process_request(self, payload):
        ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        waf_on = self.waf_enabled.get()

        self.attack_count += 1

        sep = "─" * 60 + "\n"

        # ── WAF Inspection ──
        blocked, reason = waf_inspect(payload)

        self._append(self.waf_log, sep, "dim")
        self._append(self.waf_log, f"[{ts}] INPUT : {payload}\n", "info")
        self._append(self.waf_log, f"         WAF  : {'ON' if waf_on else 'OFF'}\n", "dim")

        if waf_on and blocked:
            self.blocked_count += 1
            self._append(self.waf_log, f"         STATUS: ✘ BLOCKED\n", "blocked")
            self._append(self.waf_log, f"         RULE  : {reason}\n", "blocked")

            # Query log – show what WOULD have been sent
            self._append(self.query_log, sep, "dim")
            self._append(self.query_log, f"[{ts}] REQUEST BLOCKED BEFORE REACHING DATABASE\n", "warn")
            raw_q = f"SELECT * FROM users WHERE username = '{payload}'"
            self._append(self.query_log, f"         Attempted Query:\n         {raw_q}\n", "dim")

            self._append(self.db_log, sep, "dim")
            self._append(self.db_log, f"[{ts}] ✘ Request blocked by WAF — database not reached.\n", "blocked")

            self.attack_history.append((payload[:40], True, reason))

        else:
            self.allowed_count += 1
            status = "⚠ ALLOWED (WAF disabled)" if not waf_on and blocked else "✔ ALLOWED (Clean)"
            color  = "warn" if not waf_on and blocked else "allowed"
            self._append(self.waf_log, f"         STATUS: {status}\n", color)

            # Query simulation
            raw_q, rows = simulate_vulnerable_query(payload)

            self._append(self.query_log, sep, "dim")
            self._append(self.query_log, f"[{ts}] QUERY SENT TO DB:\n", "info")
            self._append(self.query_log, f"         {raw_q}\n", "warn" if blocked else "allowed")

            # DB Response
            self._append(self.db_log, sep, "dim")
            if rows:
                self._append(self.db_log, f"[{ts}] ⚠  {len(rows)} row(s) returned!\n", "warn")
                for r in rows[:6]:
                    line = "  |  ".join(f"{k}={v}" for k, v in r.items())
                    self._append(self.db_log, f"         {line}\n",
                                 "blocked" if len(rows) > 1 else "allowed")
            else:
                self._append(self.db_log, f"[{ts}] No matching records.\n", "dim")

            self.attack_history.append((payload[:40], False, reason))

        # Update UI counters
        self._update_stats()
        self._draw_bar_chart()

        # Update analytics list
        self.analytics_list.configure(state=tk.NORMAL)
        self.analytics_list.delete(1.0, tk.END)
        for payload_s, blk, rsn in reversed(self.attack_history[-20:]):
            icon = "✘ BLOCKED" if blk else "✔ ALLOWED"
            clr  = "blocked" if blk else "allowed"
            self.analytics_list.insert(tk.END, f"  {icon}  {payload_s:<44}  {rsn}\n", clr)
        self.analytics_list.see(tk.END)
        self.analytics_list.configure(state=tk.DISABLED)


# ─────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    app = CyberRangeApp()
    app.mainloop()
