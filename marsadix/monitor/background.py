"""Run the CVE monitor and the CT monitor in the background: `marsadix monitor start|stop|status`.

`start` launches one detached CVE/asset monitor (it works on every technology in the database) plus one CT-log
monitor per target: the given domain, or every target stored in the database when none is given. They survive
closing the terminal. Process ids are kept in <output_dir>/monitor_background.json and logs in
<output_dir>/monitor.log and <output_dir>/ct_monitor_<target>.log. Linux / WSL / macOS only.

They run while the computer is awake. If the computer really goes to sleep, they pause with it.
"""
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

STATE_NAME = "monitor_background.json"


def _paths(cfg):
    out = cfg.output_dir
    return {"state": os.path.join(out, STATE_NAME), "monitor": os.path.join(out, "monitor.log")}


def db_targets(cfg):
    """Every target that has at least one scan in the database (sorted, no duplicates)."""
    import sqlite3
    try:
        conn = sqlite3.connect(str(cfg.db_path))
        try:
            return sorted({r[0] for r in conn.execute("SELECT DISTINCT target FROM scans") if r[0]})
        finally:
            conn.close()
    except sqlite3.Error:
        return []


def _commands(cfg, targets, interval_hours):
    """The child commands. Each one just runs the normal foreground command of this same program."""
    boot = "import sys; from marsadix.cli import main; raise SystemExit(main(sys.argv[1:]))"
    base = [sys.executable, "-c", boot, "--no-banner", "--db", str(cfg.db_path)]
    cmds = {"monitor": base + ["monitor", "--interval-hours", str(interval_hours)]}
    for t in targets:
        cmds[f"ct-monitor {t}"] = base + ["ct-monitor", t]
    return cmds


def _alive(pid):
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:                                    # a recycled pid belongs to some other program
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return b"marsadix" in f.read()
    except OSError:
        return True


def _load(cfg):
    try:
        with open(_paths(cfg)["state"], "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _save(cfg, state):
    with open(_paths(cfg)["state"], "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def start(cfg, targets, interval_hours, say=print):
    if not hasattr(os, "killpg"):
        say("Background mode needs Linux, WSL or macOS.")
        return 2
    os.makedirs(cfg.output_dir, exist_ok=True)
    state = _load(cfg)
    if state and any(_alive(p.get("pid")) for p in state.get("processes", {}).values()):
        say("Already running. Use 'marsadix monitor status', or 'marsadix monitor stop' first.")
        return 1
    if not targets:
        say("No targets: there is no scan in the database yet. Run a scan first, or give a domain.")
        return 2
    paths = _paths(cfg)
    procs = {}
    for name, cmd in _commands(cfg, targets, interval_hours).items():
        log_path = paths["monitor"] if name == "monitor" else os.path.join(cfg.output_dir, f"ct_monitor_{name.split(' ', 1)[1]}.log")
        with open(log_path, "ab") as log:
            child = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                     start_new_session=True, cwd=os.getcwd())
        procs[name] = {"pid": child.pid, "log": log_path}
    _save(cfg, {"started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "targets": list(targets), "interval_hours": interval_hours, "processes": procs})
    say(f"Started in the background for {len(targets)} target(s): {', '.join(targets)}")
    for name, p in procs.items():
        say(f"  {name:<28} pid {p['pid']}   log: {p['log']}")
    say("Check on them with 'marsadix monitor status', stop them with 'marsadix monitor stop'.")
    say("They run while the computer is awake; real sleep pauses them.")
    return 0


def stop(cfg, say=print, wait=5.0):
    state = _load(cfg)
    if not state:
        say("Nothing to stop: no background monitor was started.")
        return 0
    stopped = 0
    for name, p in state.get("processes", {}).items():
        pid = p.get("pid")
        if not _alive(pid):
            say(f"  {name}: was not running")
            continue
        try:
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.time() + wait
        while time.time() < deadline and _alive(pid):
            time.sleep(0.2)
        if _alive(pid):
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        say(f"  {name}: stopped")
        stopped += 1
    try:
        os.remove(_paths(cfg)["state"])
    except OSError:
        pass
    say(f"Stopped {stopped} process(es).")
    return 0


def status(cfg, say=print):
    state = _load(cfg)
    if not state:
        say("Not running (no background monitor was started).")
        return 0
    say(f"Targets {', '.join(state.get('targets', []))}, started {state.get('started')} UTC, "
        f"cycle every {state.get('interval_hours')} h")
    for name, p in state.get("processes", {}).items():
        word = "running" if _alive(p.get("pid")) else "NOT running (see the log)"
        say(f"  {name:<28} {word}   pid {p.get('pid')}   log: {p.get('log')}")
    say("They run while the computer is awake; real sleep pauses them.")
    return 0
