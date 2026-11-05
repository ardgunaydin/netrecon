
"""Thread-safe progress tracking for NetRecon scans."""

import threading
import time


class ScanProgress:
    def __init__(self, total):
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise ValueError("total must be a non-negative integer")

        self.total = total
        self._completed = 0
        self._started = time.monotonic()
        self._lock = threading.Lock()

    def advance(self, count=1):
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError("count must be a positive integer")

        with self._lock:
            if self._completed + count > self.total:
                raise ValueError("completed tasks cannot exceed total")

            self._completed += count
            return self._completed

    def snapshot(self):
        with self._lock:
            completed = self._completed
            total = self.total

        elapsed = max(time.monotonic() - self._started, 0.0)
        rate = completed / elapsed if elapsed > 0 else 0.0
        remaining = total - completed

        if remaining == 0:
            eta = 0.0
        elif rate > 0:
            eta = remaining / rate
        else:
            eta = None

        return {
            "completed": completed,
            "total": total,
            "percent": (
                round(100.0 * completed / total, 2)
                if total else 100.0
            ),
            "elapsed_seconds": round(elapsed, 2),
            "rate_per_second": round(rate, 2),
            "eta_seconds": (
                round(eta, 2)
                if eta is not None else None
            ),
        }
