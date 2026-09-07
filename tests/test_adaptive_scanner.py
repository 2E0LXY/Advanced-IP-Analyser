import unittest

from ip_analyser.scanner import Scanner


class AdaptiveScannerTests(unittest.TestCase):
    def test_sustained_slow_failures_increase_global_probe_spacing(self):
        scanner = Scanner(adaptive=True)
        for _ in range(32):
            scanner._record_probe_pressure(True)
        self.assertGreater(scanner._probe_delay, 0)

    def test_recovery_reduces_probe_spacing(self):
        scanner = Scanner(adaptive=True)
        scanner._probe_delay = 0.02
        for _ in range(32):
            scanner._record_probe_pressure(False)
        self.assertLess(scanner._probe_delay, 0.02)

    def test_non_adaptive_mode_has_no_added_delay(self):
        scanner = Scanner(adaptive=False)
        self.assertEqual(scanner._probe_delay, 0)


if __name__ == "__main__":
    unittest.main()
