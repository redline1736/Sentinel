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

Command-line shape mirrors src/main.c:
    sentinel <outdir> <mode> <arg> [flags]
"""
import threading
import queue
import shlex
import subprocess
import sys
import io
import os
import tkinter as tk
from tkinter import ttk, font as tkfont

# ---------------------------------------------------------------- state ----
_lock        = threading.Lock()

_log_q       = queue.Queue()          # (severity, line)
_result_q    = queue.Queue()          # (severity, tool, text)
_status_q    = queue.Queue()          # str

_stop_event  = threading.Event()
_proc        = None                   # live subprocess.Popen, guarded by _lock
_run_fn      = None                   # called with the assembled command argv
_done_q      = queue.Queue()          # worker completion notifications

MODES_URL    = ["--scan-url", "--scan-site", "--xss-only", "--url"]
MODES_DOMAIN = ["-sub", "--full-scan", "--fast-scan"]
MODES        = MODES_URL + MODES_DOMAIN + ["--gobuster"]

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

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "warn": 4,
             "err": 5, "ok": 6, "info": 7}


def _classify(line: str) -> str:
    if line.startswith("[+]"):
        return "ok"
    if line.startswith("[-]"):
        return "err"
    if line.startswith("[!]"):
        return "warn"
    low = line.lower()
    if "critical" in low:
        return "critical"
    if "high" in low or "cve-" in low:
        return "high"
    if "medium" in low:
        return "medium"
    if "low" in low or "vulnerab" in low or "vuln" in low:
        return "low"
    return "info"


# ------------------------------------------------- public API (any thread) --
def log(line: str):
    """Append a line to the Log tab (auto-classifies severity)."""
    _log_q.put((_classify(line), line))


def add_result(severity: str, tool: str, text: str):
    """Record a finding in the Findings tab."""
    _result_q.put((severity.lower() if severity else "info", tool, text))


def status(text: str):
    """Update the status bar."""
    _status_q.put(text)


def set_run_callback(fn):
    """Register the pipeline entry point. Called as fn(argv_list)."""
    global _run_fn
    with _lock:
        _run_fn = fn


def request_stop():
    """Ask the running job to stop (terminate the subprocess if we own one)."""
    _stop_event.set()
    with _lock:
        p = _proc
    if p is not None and p.poll() is None:
        try:
            p.terminate()
        except OSError:
            pass


def _wait_idle(timeout=10.0):
    """Block the worker thread until the current job is reaped."""
    _stop_event.wait(timeout)


# ------------------------------------------------------- stdout tee helper --
class _Tee(io.TextIOBase):
    """Tee stdout/stderr: real terminal + UI log queue."""
    def __init__(self, original, stderr=False):
        self._orig = original
        self._stderr = stderr

    def write(self, s):
        if self._orig:
            try:
                self._orig.write(s)
                self._orig.flush()
            except (OSError, ValueError):
                pass
        for line in s.splitlines():
            if line.strip():
                _log_q.put(("err" if self._stderr else _classify(line), line))
        return len(s)

    def flush(self):
        if self._orig:
            try:
                self._orig.flush()
            except (OSError, ValueError):
                pass

    # fileno needed by some subprocess/progress libraries
    def fileno(self):
        return self._orig.fileno() if self._orig else 1

    def isatty(self):
        return False


def attach_stdout():
    """Route this process's stdout/stderr through the UI log (idempotent-ish)."""
    if not isinstance(sys.stdout, _Tee):
        sys.stdout = _Tee(sys.stdout, stderr=False)
    if not isinstance(sys.stderr, _Tee):
        sys.stderr = _Tee(sys.stderr, stderr=True)


# --------------------------------------------------------- job execution ----
def _assemble(outdir, mode, target, flags, proxy_file=""):
    """Build the argv exactly as src/main.c expects."""
    argv = [outdir, mode, target]

    if not flags.get("xss", True):
        argv.append("--xss-no")
    if flags.get("deepblue"):
        argv.append("--deepblue")
    if flags.get("tor"):
        argv.append("--tor")
    elif flags.get("elite"):
        argv.append("--elite")
    elif proxy_file:
        argv += ["--proxy", proxy_file]

    return argv


def _job_thread(argv):
    """Worker 'pthread': run the pipeline, tee output, report completion."""
    status("running: " + " ".join(shlex.quote(a) for a in argv))
    rc = 1
    try:
        if _stop_event.is_set():
            rc = 0
        else:
            with _lock:
                fn = _run_fn
            if fn is None:
                log("[-] no run callback registered (set_run_callback)")
            else:
                fn(argv)
        rc = 0
    except Exception as e:  # noqa: BLE001 — report everything to the UI
        log(f"[-] pipeline error: {e.__class__.__name__}: {e}")
    finally:
        _done_q.put(rc)
        status("done (rc=%d)" % rc if rc == 0 else "failed (rc=%d)" % rc)


def _start_job(outdir, mode, target, flags, proxy_file=""):
    """Spawn the worker thread. Returns False if a job is already running."""
    with _lock:
        running = _proc is not None and _proc.poll() is None
    # also treat a live 'sentinel-scan' thread as busy
    if any(t.name == "sentinel-scan" for t in threading.enumerate()):
        return False
    if running:
        return False

    _stop_event.clear()
    argv = _assemble(outdir, mode, target, flags, proxy_file)
    threading.Thread(target=_job_thread, args=(argv,),
                     name="sentinel-scan", daemon=True).start()
    return True


# ------------------------------------------------------------------- GUI ----
def start_gui():
    def _build_window():
        root = tk.Tk()
        root.title("Sentinel — automated pentest scanner")
        root.geometry("1100x700")
        root.minsize(820, 480)
        root.configure(bg="#0e0f13")

        fixed_font = tkfont.nametofont("TkFixedFont")
        fixed_font.configure(size=10)

        # ---- controls ----
        ctrl = ttk.LabelFrame(root, text=" controls ")
        ctrl.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Label(ctrl, text="outdir:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        outdir_var = tk.StringVar(value="out")
        ttk.Entry(ctrl, textvariable=outdir_var, width=20).grid(row=0, column=1, padx=4)

        ttk.Label(ctrl, text="mode:").grid(row=0, column=2, sticky="e", padx=6)
        mode_var = tk.StringVar(value=MODES[0])
        mode_cb = ttk.Combobox(ctrl, textvariable=mode_var, values=MODES,
                               state="readonly", width=14)
        mode_cb.grid(row=0, column=3, padx=4)

        # show the target label appropriate to the selected mode
        ttk.Label(ctrl, text="target (url / domain):").grid(row=1, column=0, sticky="w", padx=6)
        target_var = tk.StringVar()
        target_entry = ttk.Entry(ctrl, textvariable=target_var, width=48)
        target_entry.grid(row=1, column=1, columnspan=3, sticky="we", padx=4)

        def _retarget_label(*_):
            m = mode_var.get()
            if m in MODES_URL:
                target_entry_label.set("target (url):" if m != "--gobuster" else "n/a")
            elif m in MODES_DOMAIN:
                target_entry_label.set("target (domain):")
            else:
                target_entry_label.set("target:")
        target_entry_label = tk.StringVar(value="target (url):")
        lbl = ctrl.grid_slaves(row=1, column=0)[0]
        lbl.configure(textvariable=target_entry_label)
        mode_var.trace_add("write", _retarget_label)
        _retarget_label()

        flags = {"xss": tk.BooleanVar(value=True),
                 "deepblue": tk.BooleanVar(value=False),
                 "tor": tk.BooleanVar(value=False),
                 "elite": tk.BooleanVar(value=False)}
        for i, name in enumerate(["xss", "deepblue", "tor", "elite"]):
            ttk.Checkbutton(ctrl, text=name, variable=flags[name]).grid(
                row=2, column=i, sticky="w", padx=6)

        ttk.Label(ctrl, text="proxy list:").grid(row=0, column=4, sticky="e", padx=6)
        proxy_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=proxy_var, width=22).grid(row=0, column=5, padx=4)

        run_btn  = ttk.Button(ctrl, text="▶ RUN")
        stop_btn = ttk.Button(ctrl, text="■ STOP", command=request_stop,
                              state="disabled")
        run_btn.grid(row=2, column=4, padx=10)
        stop_btn.grid(row=2, column=5, padx=4)
        ctrl.columnconfigure(1, weight=1)

        # ---- results area: tabs ----
        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=4)

        # Log tab
        log_frame = ttk.Frame(nb)
        nb.add(log_frame, text="Log")
        log_text = tk.Text(log_frame, bg="#14161c", fg="#dddddd",
                           insertbackground="#dddddd", relief="flat",
                           padx=8, pady=6, font=fixed_font)
        log_scroll = ttk.Scrollbar(log_frame, command=log_text.yview)
        log_text.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side="right", fill="y")
        log_text.pack(side="left", fill="both", expand=True)
        for tag in ("ok", "warn", "err", "info"):
            log_text.tag_config(tag, foreground=SEV_COLORS[tag])
        log_text.configure(state="disabled")

        # Findings tab
        res_frame = ttk.Frame(nb)
        nb.add(res_frame, text="Findings")
        tree = ttk.Treeview(res_frame, columns=("sev", "tool", "finding"),
                            show="headings", height=20)
        for col, title, w in (("sev", "severity", 90),
                              ("tool", "tool", 140),
                              ("finding", "finding", 780)):
            tree.heading(col, text=title)
            tree.column(col, width=w, anchor="w")
        res_scroll = ttk.Scrollbar(res_frame, command=tree.yview)
        tree.configure(yscrollcommand=res_scroll.set)
        res_scroll.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        for tag in ("critical", "high", "medium", "low", "info"):
            tree.tag_configure(tag, foreground=SEV_COLORS[tag])

        # ---- status bar ----
        status_var = tk.StringVar(value="ready")
        status_bar = tk.Label(root, textvariable=status_var, anchor="w",
                              bg="#0e0f13", fg="#ffffff", padx=8, pady=4)
        status_bar.pack(fill="x", side="bottom")

        # ---- job control ----
        def on_run():
            target = target_var.get().strip()
            if not target and mode_var.get() != "--gobuster":
                log("[-] target required")
                return
            if not outdir_var.get().strip():
                log("[-] outdir required")
                return
            if not _start_job(outdir_var.get().strip(), mode_var.get(), target,
                              {k: v.get() for k, v in flags.items()},
                              proxy_var.get().strip()):
                log("[!] a scan is already running")
                return
            run_btn.configure(state="disabled")
            stop_btn.configure(state="normal")

        run_btn.configure(command=on_run)

        # ---- pump queues -> widgets (UI thread) ----
        pump_after = None

        def pump():
            nonlocal pump_after
            nonlocal run_btn, stop_btn  # noqa: F841 — captured via closure

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

            # job completion -> re-enable buttons
            try:
                _done_q.get_nowait()
                run_btn.configure(state="normal")
                stop_btn.configure(state="disabled")
            except queue.Empty:
                pass

            pump_after = root.after(100, pump)

        def on_close():
            request_stop()
            if pump_after is not None:
                root.after_cancel(pump_after)
            root.destroy()

        root.protocol("WM_DELETE_WINDOW", on_close)
        pump()
        log("[+] UI online")
        root.mainloop()

    t = threading.Thread(target=_build_window, name="sentinel-ui", daemon=False)
    t.start()
    return t


def wait(ui_thread=None):
    """Block until the UI window closes."""
    if ui_thread is None:
        for t in threading.enumerate():
            if t.name == "sentinel-ui":
                ui_thread = t
                break
    if ui_thread is not None:
        ui_thread.join()


# ------------------------------------------------------------ CLI helper ---
def run_with_ui(entry, command: str):
    """
    Convenience for CLI mode:
        view.run_with_ui(run_pipeline, "out -sub example.com")
    Starts the UI, runs the pipeline in a worker thread with stdout
    captured, blocks until the window closes.

    `command` is parsed with shlex so quoted URLs survive intact, and the
    argv is passed to the callback verbatim (main.c shape:
    <outdir> <mode> <arg> [flags]).
    """
    set_run_callback(entry)
    attach_stdout()
    t = start_gui()

    # brief grace period so the first log lines land after the window exists
    import time
    time.sleep(0.2)

    argv = shlex.split(command)
    _stop_event.clear()
    threading.Thread(target=_job_thread, args=(argv,),
                     name="sentinel-scan", daemon=True).start()
    wait(t)