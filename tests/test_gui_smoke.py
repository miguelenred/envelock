"""The assistant window builds, lists its tabs and switches language. Skipped where there is no
Tkinter or no display (the encoder and its CLI do not need either); run under a display with
`xvfb-run python tests/... ` or the GUI check in CI."""

import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

tkinter = pytest.importorskip("tkinter")
if not os.environ.get("DISPLAY") and os.name != "nt":
    pytest.skip("no display", allow_module_level=True)

try:
    tkinter.Tk().destroy()
except tkinter.TclError:
    pytest.skip("no usable display", allow_module_level=True)


def _load():
    spec = importlib.util.spec_from_file_location("envelock_gui", ROOT / "gui" / "envelock_gui.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_window_builds_and_switches_language():
    g = _load()
    app = g.Assistant()
    try:
        en = [app.nb.tab(i, "text") for i in range(len(app.nb.tabs()))]
        assert en[0] == "Encrypt a project" and len(en) == 6 and "Recommend" in en
        app._switch_language(1)
        es = [app.nb.tab(i, "text") for i in range(len(app.nb.tabs()))]
        assert es[0] == "Cifrar un proyecto" and len(es) == 6 and "Recomendar" in es
    finally:
        app.destroy()


def test_every_string_has_both_languages():
    g = _load()
    bad = [k for k, v in g.STRINGS.items() if len(v) != 2 or not all(v)]
    assert bad == [], bad


def test_wrong_kind_detection_and_name_suggestion(tmp_path):
    import json as _json
    g = _load()
    app = g.Assistant()
    try:
        pub = tmp_path / "s.pub.json"
        pub.write_text(_json.dumps({"kind": "envelock-recipient-public", "format": 2,
                                    "x25519_public": "aa" * 32}))
        owner_like = tmp_path / "o.json"
        owner_like.write_text(_json.dumps({"kind": "envelock-owner", "format": 2}))
        # a public key is wrong where an owner is expected; right where a recipient-public is
        assert app._wrong_kind_message(pub, {"envelock-owner", "envelock-encrypted"})
        assert app._wrong_kind_message(pub, {"envelock-recipient-public"}) is None
        # an owner is wrong in the recipients list
        assert app._wrong_kind_message(owner_like, {"envelock-recipient-public"})
        # name suggestion only fills a bare field, never a chosen path
        var = g.tk.StringVar(value="servidor1.enc.json")
        g._suggest(var, "cliente", ".enc.json")
        assert var.get() == "cliente.enc.json"
        var.set("C:/keys/servidor1.enc.json")
        g._suggest(var, "cliente", ".enc.json")
        assert var.get() == "C:/keys/servidor1.enc.json"
    finally:
        app.destroy()


def _drain_until(app, done, seconds=10):
    import time
    end = time.time() + seconds
    while not done() and time.time() < end:
        app._drain()
        app.update()
        time.sleep(0.02)


def test_missing_php_flows(tmp_path, monkeypatch):
    """Windows: offer the official PHP download (then retry) or the VC++ runtime install;
    Linux/macOS: show the install command; declining leaves the normal error to the caller."""
    import sys as _sys
    g = _load()
    app = g.Assistant()
    app._detector.join(60)                # the startup search must not run under the faked platform
    shown, retried = [], []
    monkeypatch.setattr(g.messagebox, "showinfo", lambda *a, **k: shown.append(a[1]))
    monkeypatch.setattr(g.messagebox, "showerror", lambda *a, **k: shown.append(a[1]))
    var = g.tk.StringVar(value="php")
    exe = tmp_path / "php" / "8.4.27" / "php.exe"
    try:
        # Windows, PHP missing, user accepts: downloads next to the assistant, fills the field, retries
        monkeypatch.setattr(_sys, "platform", "win32")
        monkeypatch.setattr(g.messagebox, "askyesno", lambda *a, **k: True)
        monkeypatch.setattr(g.actions, "php_home", lambda: tmp_path / "php")
        monkeypatch.setattr(g.actions, "download_php", lambda dest: exe)
        assert app._fix_php("not_found", "php", var, lambda: retried.append("php"))
        _drain_until(app, lambda: retried)
        assert retried == ["php"] and var.get() == str(exe) and app._php == str(exe)
        # Windows, VC++ runtime missing: installs, then retries
        monkeypatch.setattr(g.actions, "install_vc_redist", lambda work: 0)
        assert app._fix_php("no_vcruntime", str(exe), var, lambda: retried.append("vc"))
        _drain_until(app, lambda: "vc" in retried)
        assert retried[-1] == "vc"
        # Windows, user declines: the caller shows its own error
        monkeypatch.setattr(g.messagebox, "askyesno", lambda *a, **k: False)
        assert not app._fix_php("not_found", "php", var, lambda: retried.append("no"))
        # Linux/macOS: shows the install command, never downloads
        monkeypatch.setattr(_sys, "platform", "linux")
        monkeypatch.setattr(g.actions, "download_php", lambda dest: pytest.fail("no download off Windows"))
        shown.clear()
        assert app._fix_php("not_found", "php", var, lambda: retried.append("linux"))
        assert shown and "php" in shown[0] and "linux" not in retried
    finally:
        monkeypatch.setattr(_sys, "platform", "linux")
        app.destroy()


def test_run_async_refuses_concurrent_operation(monkeypatch):
    """While one operation runs (_busy), a second is refused instead of racing (ENV-18)."""
    g = _load()
    app = g.Assistant()
    try:
        shown = []
        monkeypatch.setattr(g.messagebox, "showinfo", lambda *a, **k: shown.append(a))
        called = []
        app._busy = True
        app._run_async(lambda: called.append(1), lambda r: None)
        assert called == [] and shown, "a concurrent op must be refused and the user told"
    finally:
        app.destroy()


def _widgets(root):
    for child in root.winfo_children():
        yield child
        yield from _widgets(child)


def _inside(widget, frame):
    while widget is not None:
        if widget is frame:
            return True
        widget = widget.master
    return False


def _tab(app, index):
    return app.nametowidget(app.nb.tabs()[index])


def _entries(frame):
    return [w for w in _widgets(frame) if w.winfo_class() == "TEntry"]


def _set(app, entry, value):
    app.setvar(str(entry.cget("textvariable")), value)


def _button(frame, text):
    return next(w for w in _widgets(frame) if w.winfo_class() == "TButton" and w.cget("text") == text)


def test_every_action_handler_checks_busy_before_anything_else(tmp_path, monkeypatch):
    """T-12: while an operation runs, an action button is refused at once -- no password prompt,
    no PHP probe, no dialog, and no change to the output folder (the pack handler used to remove an
    empty output folder before the busy check)."""
    g = _load()
    app = g.Assistant()
    try:
        app._detector.join(60)
        busy, other = [], []
        monkeypatch.setattr(g.messagebox, "showinfo", lambda *a, **k: busy.append(a[1]))
        for name in ("showerror", "showwarning", "askyesno"):
            monkeypatch.setattr(g.messagebox, name, lambda *a, _n=name, **k: other.append(_n))
        monkeypatch.setattr(g.filedialog, "askopenfilename", lambda *a, **k: other.append("open") or "")
        monkeypatch.setattr(app, "_ask_password", lambda *a, **k: other.append("password"))
        monkeypatch.setattr(g.actions, "check_php", lambda *a, **k: other.append("check_php"))
        # A filled-in Encrypt tab whose output folder exists and is empty.
        pack_tab = _tab(app, 0)
        output = tmp_path / "out"
        output.mkdir()
        for entry, value in zip(_entries(pack_tab), ["o.json", "p", str(tmp_path), str(output)]):
            _set(app, entry, value)
        app._busy = True
        recipients_frame = next(w for w in _widgets(pack_tab) if w.winfo_class() == "TLabelframe")
        actions_texts = {app.t(k) for k in ("run", "create", "add", "remove", "inspect", "recommend_btn")}
        buttons = [w for w in _widgets(app) if w.winfo_class() == "TButton"
                   and w.cget("text") in actions_texts and not _inside(w, recipients_frame)]
        assert len(buttons) >= 14
        for button in buttons:
            busy.clear()
            button.invoke()
            assert busy == [app.t("busy")], button.cget("text")
        assert other == [] and output.is_dir()
    finally:
        app.destroy()


def test_closing_while_busy_asks_and_workers_are_not_daemons(monkeypatch):
    """T-13: closing the window mid-operation used to kill the daemon worker (a key's .tmp file,
    a half-written package). Now the close asks first, and the worker is a normal thread, which
    the interpreter lets finish before the program exits."""
    import threading
    g = _load()
    app = g.Assistant()
    closed = []
    try:
        app._detector.join(60)
        release = threading.Event()
        app._run_async(lambda: release.wait(20), lambda r: None)
        assert app._busy and app._worker.daemon is False
        monkeypatch.setattr(app, "destroy", lambda: closed.append(1))
        monkeypatch.setattr(g.messagebox, "askyesno", lambda *a, **k: False)
        app._on_close()
        assert closed == []                                     # refused: still running
        monkeypatch.setattr(g.messagebox, "askyesno", lambda *a, **k: True)
        app._on_close()
        assert closed == [1]                                    # confirmed
        release.set()
        app._worker.join(20)
        _drain_until(app, lambda: not app._busy)
        monkeypatch.setattr(g.messagebox, "askyesno", lambda *a, **k: pytest.fail("not busy: no question"))
        app._on_close()
        assert closed == [1, 1]
    finally:
        g.Assistant.destroy(app)


def test_php_probe_and_inspect_run_off_the_ui_thread(tmp_path, monkeypatch):
    """T-14: the PHP probe (up to 30 s) and Inspect ran on Tk's thread and froze the window."""
    import threading
    g = _load()
    app = g.Assistant()
    try:
        app._detector.join(60)
        threads, errors = [], []
        monkeypatch.setattr(g.messagebox, "showerror", lambda *a, **k: errors.append(a[1]))

        def fake_check(cmd):
            threads.append(threading.current_thread())
            return ("not_found", "")
        monkeypatch.setattr(g.actions, "check_php", fake_check)
        monkeypatch.setattr(app, "_fix_php", lambda *a: False)          # the caller explains
        # Encrypt with "Remove comments": the PHP check happens in a worker, then the error shows.
        pack_tab = _tab(app, 0)
        for entry, value in zip(_entries(pack_tab), ["o.json", "p", str(tmp_path), str(tmp_path / "o")]):
            _set(app, entry, value)
        next(w for w in _widgets(pack_tab) if w.winfo_class() == "Listbox").insert("end", "r.pub.json")
        next(w for w in _widgets(pack_tab) if w.winfo_class() == "TCheckbutton"
             and w.cget("text") == app.t("opt_strip")).invoke()
        _button(pack_tab, app.t("run")).invoke()
        _drain_until(app, lambda: errors)
        assert threads and threads[0] is not threading.main_thread()
        assert errors and "php" in errors[0].lower()
        # Inspect: the result is shown when the worker is done.
        inspected = []
        monkeypatch.setattr(g.actions, "inspect", lambda path: inspected.append(
            threading.current_thread()) or {"kind": "inspected", "path": path.name})
        inspect_tab = _tab(app, 5)
        _set(app, _entries(inspect_tab)[0], str(tmp_path / "pkg.php"))
        _button(inspect_tab, app.t("inspect")).invoke()
        text = next(w for w in _widgets(inspect_tab) if w.winfo_class() == "Text")
        _drain_until(app, lambda: "inspected" in text.get("1.0", "end"))
        assert inspected and inspected[0] is not threading.main_thread()
        assert '"path": "pkg.php"' in text.get("1.0", "end")
    finally:
        app.destroy()


def test_drain_survives_a_throwing_callback(monkeypatch):
    """A callback that raises must not kill the drain loop (which would freeze the UI with _busy
    stuck True): _busy is cleared, the error is surfaced, and _drain still reschedules."""
    g = _load()
    app = g.Assistant()
    try:
        errs = []
        monkeypatch.setattr(g.messagebox, "showerror", lambda *a, **k: errs.append(a))
        app._busy = True
        def boom(_):
            raise RuntimeError("boom")
        app._queue.put(("ok", "payload", boom))
        app._drain()                       # must not propagate the exception
        assert app._busy is False and errs  # cleared and surfaced, not wedged
    finally:
        app.destroy()
