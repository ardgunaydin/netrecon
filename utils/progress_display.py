
"""Terminal progress display for NetRecon."""

class ProgressReporter:
    """Display periodically updated scan statistics."""

    def __init__(self, interval=0.5):
        if interval <= 0:
            raise ValueError("Interval must be greater than zero.")

        self.interval = interval
        self._last_update = None

    @staticmethod
    def format_eta(seconds):
        if seconds is None:
            return "calculating"

        if seconds >= 60:
            minutes, remaining = divmod(int(seconds), 60)
            return f"{minutes}m {remaining}s"

        return f"{seconds:.1f}s"

    def __call__(self, snapshot):
        elapsed = snapshot["elapsed_seconds"]
        completed = snapshot["completed"]
        total = snapshot["total"]

        finished = completed >= total

        if (
            not finished
            and self._last_update is not None
            and elapsed - self._last_update < self.interval
        ):
            return

        self._last_update = elapsed

        percent = snapshot["percent"]
        rate = snapshot["rate_per_second"]
        eta = self.format_eta(snapshot["eta_seconds"])

        bar_width = 20
        filled = min(
            bar_width,
            int(percent / 100 * bar_width)
        )

        bar = (
            "#" * filled
            + "-" * (bar_width - filled)
        )

        print(
            f"[PROGRESS] [{bar}] "
            f"{percent:.1f}% | "
            f"{completed}/{total} ports | "
            f"{rate:.1f} ports/s | "
            f"ETA: {eta}"
        )
