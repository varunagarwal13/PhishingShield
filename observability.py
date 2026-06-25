import time
from collections import defaultdict
from contextlib import contextmanager


class MetricsCollector:
    def __init__(self):
        self.counters = defaultdict(int)
        self.latency_total = defaultdict(float)
        self.latency_count = defaultdict(int)

    def increment(self, name, labels=None, value=1):
        self.counters[self._metric_key(name, labels)] += value

    @contextmanager
    def timer(self, name, labels=None):
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            key = self._metric_key(name, labels)
            self.latency_total[key] += elapsed
            self.latency_count[key] += 1

    def observe(self, name, elapsed_seconds, labels=None):
        key = self._metric_key(name, labels)
        self.latency_total[key] += elapsed_seconds
        self.latency_count[key] += 1

    def render_prometheus(self):
        lines = []
        for key, value in sorted(self.counters.items()):
            lines.append(f"{key} {value}")
        for key, total in sorted(self.latency_total.items()):
            count = self.latency_count[key]
            lines.append(f"{key}_seconds_sum {total:.6f}")
            lines.append(f"{key}_seconds_count {count}")
            if count:
                lines.append(f"{key}_seconds_avg {total / count:.6f}")
        return "\n".join(lines) + "\n"

    def _metric_key(self, name, labels=None):
        if not labels:
            return name
        label_text = ",".join(f'{key}="{value}"' for key, value in sorted(labels.items()))
        return f"{name}{{{label_text}}}"
