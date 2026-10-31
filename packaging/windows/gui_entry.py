from __future__ import annotations

import multiprocessing
import sys
import threading

from ip_analyser.ai_network_monitor import monitor_once, validate_monitor_target
from ip_analyser.network import active_ipv4_networks

from ip_analyser.gui import main

def run_background_monitor() -> None:
    """Opt-in Windows sign-in monitor: local data only, no listener/cloud."""
    stop = threading.Event()
    while not stop.is_set():
        try:
            networks = active_ipv4_networks()
        except RuntimeError:
            # Network services and PowerShell can still be starting during
            # sign-in. Keep the monitor alive and retry on the next interval.
            stop.wait(30)
            continue
        for interface, target, _broadcast in networks:
            if any(word in interface.lower() for word in ("tailscale", "vpn", "virtual", "loopback")):
                continue
            try:
                validate_monitor_target(target)
            except (ValueError, RuntimeError):
                continue
            try:
                monitor_once(target)
            except (OSError, RuntimeError, ValueError):
                pass  # The next interval retries after transient network errors.
            break
        stop.wait(300)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if "--background-monitor" in sys.argv:
        run_background_monitor()
    else:
        main()
