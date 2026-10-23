import unittest
import sys
from pathlib import Path

# Ensure src is on sys.path even if package is not installed in the environment
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from boltscan.timing import get_timing, TIMING_TEMPLATES


class TestTiming(unittest.TestCase):
    def test_timing_templates_t0_through_t5(self):
        self.assertEqual(get_timing("T0"), (3.0, 1))
        self.assertEqual(get_timing("T1"), (0.5, 10))
        self.assertEqual(get_timing("T2"), (0.1, 50))
        self.assertEqual(get_timing("T3"), (0.02, 250))
        self.assertEqual(get_timing("T4"), (0.005, 500))
        self.assertEqual(get_timing("T5"), (0.0, 1000))

    def test_lowercase_input(self):
        self.assertEqual(get_timing("t0"), (3.0, 1))
        self.assertEqual(get_timing("t1"), (0.5, 10))
        self.assertEqual(get_timing("t2"), (0.1, 50))
        self.assertEqual(get_timing("t3"), (0.02, 250))
        self.assertEqual(get_timing("t4"), (0.005, 500))
        self.assertEqual(get_timing("t5"), (0.0, 1000))

    def test_invalid_template_defaults_to_t3(self):
        default_t3 = TIMING_TEMPLATES["T3"]
        self.assertEqual(get_timing("T6"), default_t3)
        self.assertEqual(get_timing("invalid"), default_t3)
        self.assertEqual(get_timing("UNKNOWN"), default_t3)
        self.assertEqual(get_timing(""), default_t3)


if __name__ == "__main__":
    unittest.main()
