"""
Sentinel UI — tkinter port of the Nuklear/SDL3 view.

Design mirrors the C version:
  - UI runs its own thread-safe window loop
  - scan pipeline runs in a worker thread ("pthread" equivalent)
  - stdout from the pipeline is tee'd: terminal + Log tab
  - findings/status propagate to the UI as they arrive

Usage from main:
    import view
    view.set_run_callback(run_pipeline_entry)
    view.start_gui()
    view.wait()          # blocks until window closed
"""
import threading
import queue
import sys
import io
import os

import tkinter as tk
from tkinter import ttk

# ---------------------------------------------------------------- state ----
_lock = threading.Lock()

_log_q      = queue.Queue()          # (severity, line)
_result_q   = queue.Queue()          # (severity, tool, text)
_status_q   = queue.Queue()          # str

_stop_event = threading.Event()
_run_fn     = None                   # called with the assembled command
_after_id   = None

MODES = ["-sub", "--full-scan", "--fast-scan", "--scan-url", "--scan-site", "--xss-only"]

# severity colors
SEV_COLORS = {
    "info":     "#b4b4b4",
    "ok":       "#5adc6e",
    "warn":     "#f0c846",
    "err":      "#eb5a5a",
    "critical": "#eb5a5a",
    "high":     "#eb5a5a",
    "medium":   "#f0c846",
    "low":      "#78beff",
}


def _classify(line: str) -> str:
    if line.startswith("[+]"):
        return "ok"
    if line.startswith("[-]"):
        return "err"
    if line.startswith("[!]"):
        return "warn"
    low = line.lower()
    if "cve-" in low or "vulnerab" in low or "vuln" in low:
        return "warn"
    return "info"


# ------------------------------------------------- public API (any thread) --
def log(line: str):
    """Append a line to the Log tab (auto-classifies severity)."""
    _log_q.put((_classify(line), line))


def add_result(severity: str, tool: str, text: str):
    """Add a structured finding row to the Findings tab."""
    _result_q.put((severity or "info", tool or "scan", text or ""))


def set_status(status: str):
    _status_q.put(status or "")


def request_stop():
    _stop_event.set()
    log("[!] stop requested")


def should_stop() -> bool:
    return _stop_event.is_set()


def set_run_callback(fn):
    """fn(command: str) — executed on a worker thread when RUN is pressed."""
    global _run_fn
    _run_fn = fn


def start_gui():
    """Launch the UI on its own thread (pthread equivalent)."""
    t = threading.Thread(target=_ui_main, name="sentinel-ui", daemon=True)
    t.start()
    return t


def wait():
    """Block the calling thread until the UI window is closed."""
    global _ui_thread
    if _ui_thread is not None:
        _ui_thread.join()


_ui_thread = None


def wait_ready(t):
    global _ui_thread
    _ui_thread = t


# ------------------------------------------------------- stdout capture ----
class _TeeStdout(io.TextIOBase):
    """stdout -> terminal + Log tab, line-buffered."""
    def __init__(self, original):
        self._original = original
        self._buf = ""

    def write(self, s):
        self._original.write(s)          # keep terminal output
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line:
                log(line)
        return len(s)

    def flush(self):
        self._original.flush()


def attach_stdout():
    """Redirect print()/stdout into the UI Log tab (tee'd)."""
    sys.stdout = _TeeStdout(sys.stdout)


# ------------------------------------------------------------- job thread --
def _job_thread(command: str):
    set_status("running…")
    try:
        if _run_fn:
            _run_fn(command)
    except Exception as e:
        log(f"[-] job crashed: {e}")
    set_status("idle — scan finished")
    log("[+] job finished")


def _start_job(outdir: str, mode: str, target: str, flags: dict):
    if _run_fn is None:
        log("[-] no run callback registered (view.set_run_callback)")
        return

    cmd = f"{outdir} {mode} {target}"
    if not flags["xss"]:
        cmd += " --xss-no"
    if flags["tor"]:
        cmd += " --tor"
    if flags["elite"]:
        cmd += " --elite"
    if flags["deepblue"]:
        cmd += " --deepblue"

    _stop_event.clear()
    threading.Thread(target=_job_thread, args=(cmd,),
                     name="sentinel-scan", daemon=True).start()
    log(f"[+] starting: {cmd}")


# ------------------------------------------------------------------- UI ----
def _ui_main():
    global _after_id

    root = tk.Tk()
    root.title("Sentinel — Automated Pentest Scanner")
    root.geometry("1100x720")
    root.configure(bg="#181a20")

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("TNotebook.Tab", padding=(14, 6))
    style.configure("Treeview", rowheight=22, background="#1e2028",
                    fieldbackground="#1e2028", foreground="#dddddd")
    style.configure("Treeview.Heading", background="#2a2d36", foreground="#ffffff")

    # ---- control panel ----
    ctrl = ttk.LabelFrame(root, text=" controls ")
    ctrl.pack(fill="x", padx=8, pady=(8, 4))

    ttk.Label(ctrl, text="outdir:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
    outdir_var = tk.StringVar(value="out")
    ttk.Entry(ctrl, textvariable=outdir_var, width=20).grid(row=0, column=1, padx=4)

    ttk.Label(ctrl, text="mode:").grid(row=0, column=2, sticky="e", padx=6)
    mode_var = tk.StringVar(value=MODES[3])
    ttk.Combobox(ctrl, textvariable=mode_var, values=MODES,
                 state="readonly", width=14).grid(row=0, column=3, padx=4)

    ttk.Label(ctrl, text="target (url / domain):").grid(row=1, column=0, sticky="w", padx=6)
    target_var = tk.StringVar()
    ttk.Entry(ctrl, textvariable=target_var, width=48).grid(
        row=1, column=1, columnspan=3, sticky="we", padx=4)

    flags = {"xss": tk.BooleanVar(value=True),
             "deepblue": tk.BooleanVar(value=False),
             "tor": tk.BooleanVar(value=False),
             "elite": tk.BooleanVar(value=False)}
    for i, name in enumerate(["xss", "deepblue", "tor", "elite"]):
        ttk.Checkbutton(ctrl, text=name, variable=flags[name]).grid(
            row=2, column=i, sticky="w", padx=6)

    job_running = {"flag": False}

    def on_run():
        if job_running["flag"]:
            return
        target = target_var.get().strip()
        if not target:
            log("[-] target required")
            return
        job_running["flag"] = True
        _start_job(outdir_var.get().strip(), mode_var.get(), target,
                   {k: v.get() for k, v in flags.items()})

    def on_stop():
        request_stop()

    ttk.Button(ctrl, text="▶ RUN", command=on_run).grid(row=2, column=4, padx=10)
    ttk.Button(ctrl, text="■ STOP", command=on_stop).grid(row=2, column=5, padx=4)

    ctrl.columnconfigure(1, weight=1)

    # ---- results area: tabs ----
    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=4)

    # Log tab
    log_frame = ttk.Frame(nb)
    nb.add(log_frame, text="Log")
    log_text = tk.Text(log_frame, bg="#14161c", fg="#dddddd", insertbackground="#dddddd",
                       relief="flat", padx=8, pady=6, font=("TkFixedFont", 10))
    log_scroll = ttk.Scrollbar(log_frame, command=log_text.yview)
    log_text.configure(yscrollcommand=log_scroll.set)
    log_scroll.pack(side="right", fill="y")
    log_text.pack(side="left", fill="both", expand=True)
    log_text.tag_config("ok",   foreground=SEV_COLORS["ok"])
    log_text.tag_config("warn", foreground=SEV_COLORS["warn"])
    log_text.tag_config("err",  foreground=SEV_COLORS["err"])
    log_text.tag_config("info", foreground=SEV_COLORS["info"])
    log_text.configure(state="disabled")

    # Findings tab
    res_frame = ttk.Frame(nb)
    nb.add(res_frame, text="Findings")
    tree = ttk.Treeview(res_frame, columns=("sev", "tool", "finding"),
                        show="headings", height=20)
    tree.heading("sev", text="severity")
    tree.heading("tool", text="tool")
    tree.heading("finding", text="finding")
    tree.column("sev", width=90, anchor="w")
    tree.column("tool", width=140, anchor="w")
    tree.column("finding", width=780, anchor="w")
    res_scroll = ttk.Scrollbar(res_frame, command=tree.yview)
    tree.configure(yscrollcommand=res_scroll.set)
    res_scroll.pack(side="right", fill="y")
    tree.pack(side="left", fill="both", expand=True)
    tree.tag_configure("critical", foreground=SEV_COLORS["critical"])
    tree.tag_configure("high",     foreground=SEV_COLORS["high"])
    tree.tag_configure("medium",   foreground=SEV_COLORS["medium"])
    tree.tag_configure("low",      foreground=SEV_COLORS["low"])
    tree.tag_configure("info",     foreground=SEV_COLORS["info"])

    # ---- status bar ----
    status_var = tk.StringVar(value="ready")
    status_bar = tk.Label(root, textvariable=status_var, anchor="w",
                          bg="#0e0f13", fg="#ffffff", padx=8, pady=4)
    status_bar.pack(fill="x", side="bottom")

    # ---- pump queues -> widgets (UI thread) ----
    def pump():
        # log lines
        drained = 0
        while drained < 200:
            try:
                sev, line = _log_q.get_nowait()
            except queue.Empty:
                break
            log_text.configure(state="normal")
            log_text.insert("end", line + "\n", sev)
            # cap the log at ~5000 lines
            if int(log_text.index("end-1c").split(".")[0]) > 5000:
                log_text.delete("1.0", "100.0")
            log_text.see("end")
            log_text.configure(state="disabled")
            drained += 1

        # findings
        while True:
            try:
                sev, tool, text = _result_q.get_nowait()
            except queue.Empty:
                break
            tree.insert("", "end", values=(sev, tool, text), tags=(sev,))

        # status
        try:
            status_var.set(_status_q.get_nowait())
        except queue.Empty:
            pass

        # reflect job state on the buttons
        job_running["flag"] = threading.active_count() and any(
            t.name == "sentinel-scan" for t in threading.enumerate())

        _after_id = root.after(100, pump)

    pump()
    log("[+] UI online")
    root.mainloop()


# ------------------------------------------------------------ CLI helper ---
def run_with_ui(entry, command: str):
    """
    Convenience for CLI mode:
        view.run_with_ui(run_pipeline, "out -sub example.com")
    Starts the UI, runs the pipeline in a worker thread with stdout
    captured, blocks until the window closes.
    """
    set_run_callback(entry)
    attach_stdout()
    start_gui()
    _start_job(*command.split(maxsplit=3)) if False else None
    # run the command directly as the scan job
    threading.Thread(target=_job_thread, args=(command,),
                     name="sentinel-scan", daemon=True).start()
    wait()