"""Polling engine: seeds, optional scoped crawl of neighbours, parallel polls."""

from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from .mibs import poll
from .model import Device, Neighbor
from .snmp import Varbinds
from .topology import norm_name


@dataclass
class CrawlSettings:
    enabled: bool = False
    scope: List[ipaddress._BaseNetwork] = field(default_factory=list)
    max_depth: int = 3
    max_devices: int = 256
    capabilities: Set[str] = field(default_factory=lambda: {"bridge", "router"})


def in_scope(addr: str, scope: Sequence[ipaddress._BaseNetwork]) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in scope)


class Known:
    """Identities of everything already polled or queued (to avoid polling a box twice)."""

    def __init__(self) -> None:
        self.addrs: Set[str] = set()
        self.names: Set[str] = set()
        self.chassis: Set[Tuple[int, str]] = set()

    def add_device(self, dev: Device) -> None:
        self.addrs.add(dev.target)
        self.addrs.update(dev.addresses)
        if dev.ok:
            for n in (dev.sys_name, dev.cdp_device_id):
                if n:
                    self.names.add(norm_name(n))
            if dev.chassis_id:
                self.chassis.add((dev.chassis_subtype, dev.chassis_id))

    def knows(self, nb: Neighbor) -> bool:
        if nb.chassis_id and (nb.chassis_subtype, nb.chassis_id) in self.chassis:
            return True
        if nb.sys_name and norm_name(nb.sys_name) in self.names:
            return True
        return any(a in self.addrs for a in nb.mgmt_addrs)


def crawl_candidates(devices: Sequence[Device], known: Known, settings: CrawlSettings) -> List[str]:
    out: List[str] = []
    for dev in devices:
        if not dev.ok:
            continue
        for nb in dev.neighbors:
            if known.knows(nb):
                continue
            if nb.caps and not (set(nb.caps) & settings.capabilities):
                continue
            addr = next((a for a in nb.mgmt_addrs if in_scope(a, settings.scope)), None)
            if addr is None or addr in out:
                continue
            out.append(addr)
            known.addrs.add(addr)
    return out


def discover(
    seeds: Sequence[str],
    open_walker: Callable[[str, Optional[float]], Tuple[Callable, Callable[[], None], Callable[[], int]]],
    workers: int = 8,
    device_timeout: Optional[float] = 120.0,
    crawl: Optional[CrawlSettings] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Tuple[List[Device], Dict[str, Dict[str, Varbinds]]]:
    """Poll the seeds (and, with crawling, their in-scope neighbours) and return the devices.

    ``open_walker(target, deadline)`` returns ``(walk, close, requests)``.
    """
    crawl = crawl or CrawlSettings()
    known = Known()
    devices: List[Device] = []
    raw: Dict[str, Dict[str, Varbinds]] = {}
    level = list(dict.fromkeys(seeds))
    known.addrs.update(level)
    depth = 0

    def one(target: str) -> Tuple[Device, Dict[str, Varbinds]]:
        deadline = time.monotonic() + device_timeout if device_timeout else None
        walk, close, requests = open_walker(target, deadline)
        try:
            dev, data = poll(target, walk)
        finally:
            close()
        dev.requests = requests()
        return dev, data

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        while level:
            if crawl.enabled and len(devices) + len(level) > crawl.max_devices and depth > 0:
                level = level[: max(0, crawl.max_devices - len(devices))]
            results = list(pool.map(one, level))
            new = []
            for dev, data in results:
                dev.depth = depth
                devices.append(dev)
                raw[dev.target] = data
                known.add_device(dev)
                new.append(dev)
                if progress:
                    state = "ok" if dev.ok else f"failed: {dev.error}"
                    progress(f"polled {dev.target} ({dev.name}) depth {depth}: {state}")
            if not crawl.enabled or depth >= crawl.max_depth or len(devices) >= crawl.max_devices:
                break
            level = crawl_candidates(new, known, crawl)
            depth += 1
    return devices, raw
