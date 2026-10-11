import time


class Clock:
    def now(self) -> float:
        return time.time()


class FakeClock(Clock):
    """Deterministic clock for tests and benchmarks."""
    def __init__(self, start: float = 1_800_000_000.0):
        self.t = float(start)

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += float(seconds)
