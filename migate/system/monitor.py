import time
from dataclasses import dataclass


@dataclass
class SystemResources:
    cpu_percent: float
    cpu_count: int
    ram_total: int      # bytes
    ram_used: int       # bytes
    ram_percent: float
    disk_total: int     # bytes
    disk_used: int      # bytes
    disk_percent: float
    net_sent: int       # bytes total
    net_recv: int       # bytes total
    uptime_seconds: int
    load_avg: tuple     # (1min, 5min, 15min)


def get_system_resources() -> SystemResources:
    """Collect current system resource usage."""
    import psutil  # lazy — avoids loading C extension at module import time

    cpu = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()
    uptime = int(time.time() - psutil.boot_time())
    load = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
    return SystemResources(
        cpu_percent=cpu,
        cpu_count=psutil.cpu_count() or 0,
        ram_total=ram.total,
        ram_used=ram.used,
        ram_percent=ram.percent,
        disk_total=disk.total,
        disk_used=disk.used,
        disk_percent=disk.percent,
        net_sent=net.bytes_sent,
        net_recv=net.bytes_recv,
        uptime_seconds=uptime,
        load_avg=load,
    )


@dataclass
class TrafficSample:
    timestamp: float
    up_bytes: int
    down_bytes: int


class TrafficHistory:
    """Keep last N traffic samples for charting."""
    def __init__(self, max_samples=60):
        self._samples: list[TrafficSample] = []
        self._max = max_samples

    def add(self, up_bytes: int, down_bytes: int):
        self._samples.append(TrafficSample(time.time(), up_bytes, down_bytes))
        if len(self._samples) > self._max:
            self._samples = self._samples[-self._max:]

    def get_all(self) -> list[dict]:
        return [{'t': s.timestamp, 'up': s.up_bytes, 'down': s.down_bytes} for s in self._samples]
