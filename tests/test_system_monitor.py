import unittest

from ip_analyser.system_monitor import (
    SystemSample,
    diagnose_sample,
    format_bytes,
    format_rate,
    trace_payload,
)


def sample(**changes):
    values = {
        "timestamp": 1.0,
        "cpu_percent": 20.0,
        "memory_percent": 30.0,
        "memory_used": 4 * 1024 ** 3,
        "memory_total": 16 * 1024 ** 3,
        "disk_busy_percent": 10.0,
        "disk_read_bps": 0.0,
        "disk_write_bps": 0.0,
        "net_down_bps": 0.0,
        "net_up_bps": 0.0,
    }
    values.update(changes)
    return SystemSample(**values)


class SystemMonitorTests(unittest.TestCase):
    def test_formatters_do_not_turn_missing_values_into_zero(self):
        self.assertEqual(format_bytes(None), "Unavailable")
        self.assertEqual(format_rate(None), "Unavailable")
        self.assertEqual(format_bytes(1536), "1.5 KB")

    def test_diagnosis_attributes_cpu_pressure_to_top_process(self):
        title, detail, _color = diagnose_sample(sample(cpu_percent=96), ("compiler", 74.2))
        self.assertEqual(title, "CPU pressure")
        self.assertIn("compiler", detail)

    def test_diagnosis_reports_unavailable_providers(self):
        empty = SystemSample(1.0, None, None, None, None, None, None, None, None, None)
        title, detail, _color = diagnose_sample(empty)
        self.assertEqual(title, "Measurements unavailable")
        self.assertIn("provider", detail)

    def test_storage_throughput_is_used_when_busy_time_is_unavailable(self):
        current = sample(cpu_percent=5, memory_percent=10, disk_busy_percent=None,
                         disk_read_bps=90 * 1024 ** 2, disk_write_bps=5 * 1024 ** 2)
        title, detail, _color = diagnose_sample(current)
        self.assertEqual(title, "Storage activity")
        self.assertIn("throughput", detail)

    def test_trace_is_bounded_to_supplied_samples_and_versioned(self):
        payload = trace_payload([sample()])
        self.assertEqual(payload["format"], 1)
        self.assertEqual(len(payload["samples"]), 1)
        self.assertNotIn("processes", payload)


if __name__ == "__main__":
    unittest.main()
