"""Setup wizard, uninstaller and status window (Tkinter, native Windows look)."""
import ctypes
import os
import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

from common import AGENT_VERSION, INSTALL_DIR, LOG_DIR, PRODUCT, PUBLISHER, log, resource

BLUE, NAVY, MUTED, OK, ERR, INFO_BG = "#2563EB", "#1E3A8A", "#5B6472", "#15803D", "#B91C1C", "#EEF4FF"


def _dpi_aware():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class Base:
    def __init__(self, title, w, h):
        _dpi_aware()
        try:  # own taskbar icon instead of python's
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("AssetAgent.Setup")
        except Exception:
            pass
        self.root = tk.Tk()
        self.s = max(1.0, self.root.winfo_fpixels("1i") / 96)
        self.root.title(title)
        try:
            self.root.iconbitmap(default=str(resource("icon.ico")))
        except Exception:
            pass
        self.root.resizable(False, False)
        W, H = self.px(w), self.px(h)
        x = (self.root.winfo_screenwidth() - W) // 2
        y = (self.root.winfo_screenheight() - H) // 3
        self.root.geometry(f"{W}x{H}+{x}+{y}")
        self.root.configure(bg="white")
        st = ttk.Style(self.root)
        if "vista" in st.theme_names():
            st.theme_use("vista")
        st.configure("TCheckbutton", background="white")
        st.configure("Info.TCheckbutton", background="white", foreground=MUTED)
        self.f_title = ("Segoe UI Semibold", 11)
        self.f_big = ("Segoe UI Light", 17)
        self.f_body = ("Segoe UI", 9)
        self.f_small = ("Segoe UI", 8)
        self.images = {}
        self.q = queue.Queue()
        self.root.after(100, self._pump)

    def px(self, v):
        return int(v * self.s)

    def logo(self, size):
        avail = [32, 48, 64, 96, 128, 256]
        want = self.px(size)
        pick = min(avail, key=lambda a: (a < want, abs(a - want)))
        if pick not in self.images:
            try:
                self.images[pick] = tk.PhotoImage(file=str(resource(f"logo-{pick}.png")))
            except Exception:
                self.images[pick] = None
        return self.images[pick]

    def _pump(self):
        try:
            while True:
                fn = self.q.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def ui(self, fn):
        """Schedule fn on the Tk thread (safe from worker threads)."""
        self.q.put(fn)

    def label(self, parent, text, font=None, fg="#111827", bg="white", wrap=None, **kw):
        return tk.Label(parent, text=text, font=font or self.f_body, fg=fg, bg=bg, justify="left", anchor="w",
                        wraplength=self.px(wrap) if wrap else 0, **kw)


# ============================================================================ setup wizard
class SetupWizard(Base):
    def __init__(self, prefill, upgrade_from=None):
        super().__init__(f"{PRODUCT} {AGENT_VERSION} Setup", 560, 400)
        self.prefill = prefill
        self.preconfigured = bool(prefill.get("server") and prefill.get("key") and prefill.get("embedded"))
        self.upgrade_from = upgrade_from
        self.server = tk.StringVar(value=prefill.get("server") or "")
        self.key = tk.StringVar(value=prefill.get("key") or "")
        self.insecure = tk.BooleanVar(value=bool(prefill.get("insecure")))
        self.open_portal = tk.BooleanVar(value=False)
        self.show_key = tk.BooleanVar(value=False)
        self.identity = None  # (values tuple, fingerprint)
        self.result = None
        self.error = None
        self.failed_step = None
        self.busy = False

        self.page_frame = tk.Frame(self.root, bg="white")
        self.page_frame.pack(fill="both", expand=True)
        bar = tk.Frame(self.root, bg="#F3F4F6")
        bar.pack(fill="x", side="bottom")
        ttk.Separator(self.root, orient="horizontal").pack(fill="x", side="bottom")
        self.lbl_brand = tk.Label(bar, text=PUBLISHER, font=self.f_small, fg="#9CA3AF", bg="#F3F4F6")
        self.lbl_brand.pack(side="left", padx=self.px(12))
        self.btn_cancel = ttk.Button(bar, text="Cancel", command=self.cancel)
        self.btn_cancel.pack(side="right", padx=(self.px(6), self.px(12)), pady=self.px(10))
        self.btn_next = ttk.Button(bar, text="Next >", command=self.next)
        self.btn_next.pack(side="right")
        self.btn_back = ttk.Button(bar, text="< Back", command=self.back)
        self.btn_back.pack(side="right", padx=(0, self.px(2)))
        self.root.protocol("WM_DELETE_WINDOW", self.cancel)
        self.pages = [self.page_welcome, self.page_connection, self.page_ready, self.page_progress, self.page_finish]
        self.index = 0
        self.show(0)

    # ---------- chrome ----------
    def clear(self):
        for w in self.page_frame.winfo_children():
            w.destroy()

    def side_layout(self):
        """Welcome/finish layout with a branded side panel."""
        self.clear()
        side = tk.Canvas(self.page_frame, width=self.px(164), highlightthickness=0, bg=NAVY)
        side.pack(side="left", fill="y")
        h = self.px(400)
        steps = 60
        for i in range(steps):
            t = i / steps
            col = "#%02x%02x%02x" % tuple(int(a + (b - a) * t) for a, b in zip((37, 99, 235), (23, 37, 84)))
            side.create_rectangle(0, h * i / steps, self.px(164), h * (i + 1) / steps + 1, fill=col, outline="")
        img = self.logo(96)
        if img:
            side.create_image(self.px(82), self.px(96), image=img)
        side.create_text(self.px(82), self.px(170), text="Asset Inventory", fill="white", font=("Segoe UI Semibold", 11))
        side.create_text(self.px(82), self.px(190), text="Agent", fill="#BFDBFE", font=("Segoe UI", 10))
        side.create_text(self.px(82), self.px(320), text=f"Version {AGENT_VERSION}", fill="#93C5FD", font=self.f_small)
        body = tk.Frame(self.page_frame, bg="white")
        body.pack(side="left", fill="both", expand=True, padx=self.px(22), pady=self.px(20))
        return body

    def header_layout(self, title, subtitle):
        self.clear()
        head = tk.Frame(self.page_frame, bg="white", height=self.px(62))
        head.pack(fill="x")
        head.pack_propagate(False)
        img = self.logo(40)
        if img:
            tk.Label(head, image=img, bg="white").pack(side="right", padx=self.px(14))
        tk.Label(head, text=title, font=("Segoe UI Semibold", 10), bg="white", anchor="w").pack(fill="x", padx=self.px(16), pady=(self.px(12), 0))
        tk.Label(head, text=subtitle, font=self.f_body, fg=MUTED, bg="white", anchor="w").pack(fill="x", padx=self.px(30))
        ttk.Separator(self.page_frame, orient="horizontal").pack(fill="x")
        body = tk.Frame(self.page_frame, bg="white")
        body.pack(fill="both", expand=True, padx=self.px(30), pady=self.px(14))
        return body

    def show(self, i):
        self.index = i
        self.pages[i]()

    def nav(self, back=True, next_text="Next >", next_ok=True, cancel=True):
        self.btn_back.configure(state="normal" if back else "disabled")
        self.btn_next.configure(text=next_text, state="normal" if next_ok else "disabled")
        self.btn_cancel.configure(state="normal" if cancel else "disabled")

    # ---------- pages ----------
    def page_welcome(self):
        b = self.side_layout()
        self.label(b, f"Welcome to the {PRODUCT} Setup Wizard", self.f_big, wrap=330).pack(fill="x")
        txt = ("This wizard installs the agent that keeps this computer's hardware and software inventory "
               "up to date in your organization's IT asset portal.\n\n"
               "The agent runs quietly as a Windows service. It does not collect personal files, e-mail or browsing data. "
               "All communication with the portal is end-to-end encrypted.")
        self.label(b, txt, wrap=330, fg="#374151").pack(fill="x", pady=(self.px(14), 0))
        if self.upgrade_from:
            self.label(b, f"Version {self.upgrade_from} is installed and will be upgraded. Its registration in the portal is kept.",
                       wrap=330, fg=BLUE).pack(fill="x", pady=(self.px(12), 0))
        self.label(b, "Click Next to continue, or Cancel to exit Setup.", wrap=330, fg=MUTED).pack(side="bottom", fill="x")
        self.nav(back=False)

    def page_connection(self):
        b = self.header_layout("Portal connection", "Where should this computer report its inventory?")
        if self.preconfigured:
            info = tk.Frame(b, bg=INFO_BG, highlightbackground="#BFDBFE", highlightthickness=1)
            info.pack(fill="x", pady=(0, self.px(10)))
            self.label(info, "✓  These settings were provided by your IT department. The portal's identity is pinned in this installer.",
                       bg=INFO_BG, fg=NAVY, wrap=440).pack(fill="x", padx=self.px(10), pady=self.px(6))
        state = "readonly" if self.preconfigured else "normal"
        self.label(b, "Portal address").pack(fill="x")
        e1 = ttk.Entry(b, textvariable=self.server, state=state)
        e1.pack(fill="x", pady=(self.px(2), self.px(2)))
        self.label(b, "Example: https://assets.company.local  or  http://192.168.1.10:8080", fg=MUTED, font=self.f_small).pack(fill="x")
        row = tk.Frame(b, bg="white")
        row.pack(fill="x", pady=(self.px(10), 0))
        self.label(row, "Enrollment key").pack(side="left")
        ttk.Checkbutton(row, text="Show", variable=self.show_key, style="Info.TCheckbutton",
                        command=lambda: self.key_entry.configure(show="" if self.show_key.get() else "•")).pack(side="right")
        self.key_entry = ttk.Entry(b, textvariable=self.key, show="•", state=state)
        self.key_entry.pack(fill="x", pady=(self.px(2), self.px(2)))
        self.label(b, "Shown on the portal under Agents & deploy.", fg=MUTED, font=self.f_small).pack(fill="x")
        ttk.Checkbutton(b, text="Accept a self-signed HTTPS certificate (data stays end-to-end encrypted)",
                        variable=self.insecure).pack(fill="x", pady=(self.px(10), 0))
        row2 = tk.Frame(b, bg="white")
        row2.pack(fill="x", pady=(self.px(10), 0))
        self.btn_test = ttk.Button(row2, text="Test connection", command=lambda: self.test_connection())
        self.btn_test.pack(side="left")
        self.lbl_test = self.label(row2, "", wrap=330)
        self.lbl_test.pack(side="left", padx=self.px(10), fill="x")
        if self.identity and self.identity[0] == self._values():
            self._show_identity_ok()
        (e1 if not self.preconfigured else self.btn_test).focus_set()
        self.nav()

    def _values(self):
        return (self.server.get().strip().rstrip("/"), self.insecure.get())

    def _show_identity_ok(self):
        self.lbl_test.configure(text=f"✓ Connected. Portal identity {self.identity[1][:19]}…", fg=OK)

    def test_connection(self, then=None):
        server = self.server.get().strip()
        if not server:
            self.lbl_test.configure(text="Enter the portal address.", fg=ERR)
            return
        if not server.lower().startswith(("http://", "https://")):
            server = "http://" + server
            self.server.set(server)
        vals = self._values()
        self.lbl_test.configure(text="Connecting…", fg=MUTED)
        self.btn_test.configure(state="disabled")
        self.btn_next.configure(state="disabled")

        def work():
            from protocol import fetch_identity
            try:
                _, fp = fetch_identity({"server": vals[0], "insecure": vals[1], "pin": self.prefill.get("pin")})
                ok, msg = True, fp
            except Exception as e:
                ok, msg = False, getattr(e, "msg", str(e))

            def done():
                if self.index != 1:
                    return
                self.btn_test.configure(state="normal")
                self.btn_next.configure(state="normal")
                if ok:
                    self.identity = (vals, msg)
                    self._show_identity_ok()
                    if then:
                        then()
                else:
                    self.identity = None
                    self.lbl_test.configure(text=f"✗ {msg}", fg=ERR)
            self.ui(done)
        threading.Thread(target=work, daemon=True).start()

    def page_ready(self):
        b = self.header_layout("Ready to install", "Review the settings, then click Install.")
        rows = [
            ("Destination", str(INSTALL_DIR)),
            ("Portal", self.server.get().strip()),
            ("Portal identity", self.identity[1] + ("   (pinned)" if self.prefill.get("pin") else "")),
            ("Runs as", f"Windows service \"{PRODUCT}\" (LocalSystem), starts automatically"),
            ("Security", "End-to-end encrypted: X25519 key exchange + AES-256-GCM. Local settings are encrypted with Windows DPAPI."),
        ]
        grid = tk.Frame(b, bg="white")
        grid.pack(fill="x")
        for r, (k, v) in enumerate(rows):
            self.label(grid, k, fg=MUTED).grid(row=r, column=0, sticky="nw", pady=self.px(4), padx=(0, self.px(14)))
            self.label(grid, v, wrap=340).grid(row=r, column=1, sticky="w", pady=self.px(4))
        if not self.prefill.get("pin"):
            self.label(b, "Tip: if your IT department gave you a fingerprint, check that it matches the portal identity above.",
                       fg=MUTED, font=self.f_small, wrap=470).pack(fill="x", side="bottom")
        self.nav(next_text="Install")
        self.btn_next.focus_set()

    def page_progress(self):
        from installer import INSTALL_STEPS
        b = self.header_layout("Installing", f"Please wait while Setup installs {PRODUCT}.")
        self.lbl_step = self.label(b, "Starting…")
        self.lbl_step.pack(fill="x")
        self.pb = ttk.Progressbar(b, maximum=len(INSTALL_STEPS), mode="determinate")
        self.pb.pack(fill="x", pady=(self.px(6), self.px(10)))
        lst = tk.Frame(b, bg="white")
        lst.pack(fill="x")
        self.step_labels = []
        for i, s in enumerate(INSTALL_STEPS):
            lab = self.label(lst, f"○   {s}", fg="#9CA3AF", font=self.f_small)
            lab.grid(row=i % 5, column=i // 5, sticky="w", padx=(0, self.px(18)), pady=1)
            self.step_labels.append(lab)
        self.nav(back=False, next_ok=False, cancel=False)
        self.busy = True

        def report(i, text):
            def upd():
                for j, lab in enumerate(self.step_labels):
                    if j < i:
                        lab.configure(text=f"✓   {INSTALL_STEPS[j]}", fg=OK)
                    elif j == i:
                        lab.configure(text=f"●   {INSTALL_STEPS[j]}", fg=BLUE)
                self.lbl_step.configure(text=text + "…")
                self.pb.configure(value=i)
            self.current = i
            self.ui(upd)

        def work():
            from installer import perform_install
            self.current = 0
            try:
                self.result = perform_install(self.server.get().strip(), self.key.get().strip(), self.prefill.get("pin"),
                                              self.insecure.get(), report)
            except Exception as e:
                log.exception("Setup failed")
                self.error = getattr(e, "msg", None) or str(e)
                self.failed_step = self.current
                self.ui(lambda: self.step_labels[self.failed_step].configure(text=f"✗   {INSTALL_STEPS[self.failed_step]}", fg=ERR))
            self.busy = False
            self.ui(lambda: self.root.after(500 if self.error else 300, lambda: self.show(4)))
        threading.Thread(target=work, daemon=True).start()

    def page_finish(self):
        b = self.side_layout()
        self.btn_back.configure(state="disabled")
        if self.error:
            self.label(b, "Setup could not complete", self.f_big, wrap=330).pack(fill="x")
            box = tk.Frame(b, bg="#FEF2F2", highlightbackground="#FECACA", highlightthickness=1)
            box.pack(fill="x", pady=(self.px(14), self.px(8)))
            self.label(box, self.error, bg="#FEF2F2", fg=ERR, wrap=310).pack(fill="x", padx=self.px(10), pady=self.px(8))
            note = ("Nothing was installed on this computer. Correct the problem and run Setup again."
                    if (self.failed_step or 0) < 4 else "Setup stopped part-way. Run Setup again to repair the installation.")
            self.label(b, note, wrap=330, fg="#374151").pack(fill="x")
            ttk.Button(b, text="View setup log", command=lambda: os.startfile(str(LOG_DIR / "setup.log"))).pack(anchor="w", pady=self.px(10))
            self.nav(back=False, next_text="Finish", cancel=False)
            self.btn_back.configure(text="< Back", state="normal", command=lambda: self._retry())
        else:
            self.label(b, f"{PRODUCT} is installed", self.f_big, wrap=330).pack(fill="x")
            host = (self.result or {}).get("hostname") or "This computer"
            self.label(b, f"{host} is now registered and its inventory has been sent to the portal. The agent will keep "
                          "it up to date automatically in the background.", wrap=330, fg="#374151").pack(fill="x", pady=(self.px(14), 0))
            self.label(b, "You can close this window. The agent appears in Settings › Apps as "
                          f"\"{PRODUCT}\" if you ever need to remove it.", wrap=330, fg=MUTED).pack(fill="x", pady=(self.px(10), 0))
            ttk.Checkbutton(b, text="Open the asset portal", variable=self.open_portal).pack(anchor="w", side="bottom")
            self.nav(back=False, next_text="Finish", cancel=False)

    def _retry(self):
        self.error = None
        self.btn_back.configure(command=self.back)
        self.show(1)

    # ---------- buttons ----------
    def next(self):
        if self.index == 1:
            if self.identity and self.identity[0] == self._values() and self.key.get().strip():
                self.show(2)
            elif not self.key.get().strip():
                self.lbl_test.configure(text="Enter the enrollment key.", fg=ERR)
            else:
                self.test_connection(then=lambda: self.show(2))
        elif self.index == 4:
            if self.open_portal.get() and not self.error:
                webbrowser.open(self.server.get().strip())
            self.root.destroy()
        else:
            self.show(self.index + 1)

    def back(self):
        if self.index > 0:
            self.show(self.index - 1)

    def cancel(self):
        if self.busy:
            return
        if self.index == 4 or messagebox.askyesno(f"{PRODUCT} Setup", "Are you sure you want to cancel Setup?", parent=self.root):
            self.root.destroy()

    def run(self):
        self.root.mainloop()
        return 0 if (self.result and not self.error) else (1 if self.error else 2)


# ============================================================================ uninstaller
class UninstallDialog(Base):
    def __init__(self):
        super().__init__(f"Uninstall {PRODUCT}", 470, 230)
        self.purge = tk.BooleanVar(value=True)
        self.done = False
        top = tk.Frame(self.root, bg="white")
        top.pack(fill="both", expand=True, padx=self.px(20), pady=self.px(18))
        img = self.logo(48)
        if img:
            tk.Label(top, image=img, bg="white").pack(side="left", anchor="n", padx=(0, self.px(16)))
        col = tk.Frame(top, bg="white")
        col.pack(side="left", fill="both", expand=True)
        self.title = self.label(col, f"Remove {PRODUCT}?", self.f_title)
        self.title.pack(fill="x")
        self.text = self.label(col, "The agent will stop reporting this computer's inventory. The computer's record stays "
                                    "in the portal until an administrator removes it.", wrap=330, fg="#374151")
        self.text.pack(fill="x", pady=(self.px(6), self.px(8)))
        self.chk = ttk.Checkbutton(col, text="Also delete the agent's configuration and logs", variable=self.purge)
        self.chk.pack(anchor="w")
        from installer import uninstall_code_required
        self.need_code = uninstall_code_required()
        self.code = tk.StringVar()
        if self.need_code:
            self.code_row = tk.Frame(col, bg="white")
            self.code_row.pack(fill="x", pady=(self.px(8), 0))
            self.label(self.code_row, "Uninstall code from IT:").pack(side="left")
            self.code_entry = ttk.Entry(self.code_row, textvariable=self.code, width=14, show="•")
            self.code_entry.pack(side="left", padx=self.px(8))
            self.root.geometry(f"{self.px(470)}x{self.px(260)}")
        self.pb = ttk.Progressbar(col, mode="indeterminate")
        bar = tk.Frame(self.root, bg="#F3F4F6")
        bar.pack(fill="x", side="bottom")
        ttk.Separator(self.root).pack(fill="x", side="bottom")
        self.btn_cancel = ttk.Button(bar, text="Cancel", command=self.root.destroy)
        self.btn_cancel.pack(side="right", padx=(self.px(6), self.px(12)), pady=self.px(10))
        self.btn_go = ttk.Button(bar, text="Uninstall", command=self.go)
        self.btn_go.pack(side="right")

    def go(self):
        if self.done:
            self.root.destroy()
            return
        if self.need_code:
            from installer import check_uninstall_code
            if not check_uninstall_code(self.code.get()):
                self.text.configure(text="This agent is protected. Enter the uninstall code provided by your IT department.", fg=ERR)
                self.code_entry.focus_set()
                return
            self.code_row.pack_forget()
        self.btn_go.configure(state="disabled")
        self.btn_cancel.configure(state="disabled")
        self.chk.pack_forget()
        self.pb.pack(fill="x")
        self.pb.start(12)
        self.text.configure(text="Stopping the service and removing files…")

        def work():
            from installer import perform_uninstall
            err = None
            try:
                perform_uninstall(self.purge.get())
            except Exception as e:
                log.exception("Uninstall failed")
                err = str(e)

            def fin():
                self.pb.stop()
                self.pb.pack_forget()
                self.done = True
                self.title.configure(text="Uninstall failed" if err else f"{PRODUCT} was removed")
                self.text.configure(text=err or "The agent has been removed from this computer.", fg=ERR if err else "#374151")
                self.btn_go.configure(text="Close", state="normal")
            self.ui(fin)
        threading.Thread(target=work, daemon=True).start()

    def run(self):
        self.root.mainloop()
        return 0


# ============================================================================ status window
class StatusWindow(Base):
    def __init__(self):
        from installer import registry_value
        from service import service_state
        super().__init__(PRODUCT, 440, 230)
        top = tk.Frame(self.root, bg="white")
        top.pack(fill="both", expand=True, padx=self.px(20), pady=self.px(18))
        img = self.logo(64)
        if img:
            tk.Label(top, image=img, bg="white").pack(side="left", anchor="n", padx=(0, self.px(16)))
        col = tk.Frame(top, bg="white")
        col.pack(side="left", fill="both", expand=True)
        self.label(col, PRODUCT, self.f_title).pack(fill="x")
        self.label(col, f"Version {AGENT_VERSION}", fg=MUTED).pack(fill="x")
        st = service_state()
        color = {"running": OK, None: ERR}.get(st, "#B45309")
        text = {"running": "Running — inventory is reported automatically", None: "Service not installed"}.get(st, f"Service {st}")
        self.label(col, f"●  {text}", fg=color).pack(fill="x", pady=(self.px(12), 0))
        self.portal = registry_value("PortalUrl")
        if self.portal:
            self.label(col, f"Portal: {self.portal}", fg="#374151").pack(fill="x", pady=(self.px(4), 0))
        self.label(col, "Communication is end-to-end encrypted.", fg=MUTED, font=self.f_small).pack(fill="x", pady=(self.px(4), 0))
        self.label(col, "If IT enables activity monitoring, a notification area icon shows while it is active.",
                   fg=MUTED, font=self.f_small, wrap=300).pack(fill="x", pady=(self.px(2), 0))
        bar = tk.Frame(self.root, bg="#F3F4F6")
        bar.pack(fill="x", side="bottom")
        ttk.Separator(self.root).pack(fill="x", side="bottom")
        ttk.Button(bar, text="Close", command=self.root.destroy).pack(side="right", padx=(self.px(6), self.px(12)), pady=self.px(10))
        if self.portal:
            ttk.Button(bar, text="Open portal", command=lambda: webbrowser.open(self.portal)).pack(side="right")

    def run(self):
        self.root.mainloop()
        return 0
