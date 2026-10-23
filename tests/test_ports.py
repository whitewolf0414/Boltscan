import unittest
import sys
from pathlib import Path

# Ensure src is on sys.path even if package is not installed in the environment
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from boltscan.ports import parse_ports, get_service_name


class TestPorts(unittest.TestCase):
    def test_single_ports(self):
        self.assertEqual(parse_ports("80"), [80])
        self.assertEqual(parse_ports("22"), [22])
        self.assertEqual(parse_ports("443"), [443])

    def test_ranges(self):
        self.assertEqual(parse_ports("80-85"), [80, 81, 82, 83, 84, 85])
        self.assertEqual(parse_ports("1-5"), [1, 2, 3, 4, 5])

    def test_mixed_input(self):
        expected = [22] + list(range(80, 91)) + [443]
        self.assertEqual(parse_ports("22,80-90,443"), expected)

    def test_all_keyword(self):
        all_ports = parse_ports("all")
        self.assertEqual(len(all_ports), 65535)
        self.assertEqual(all_ports[0], 1)
        self.assertEqual(all_ports[-1], 65535)
        self.assertEqual(all_ports, list(range(1, 65536)))

    def test_invalid_input(self):
        # Port 0 is below valid TCP range 1-65535
        self.assertEqual(parse_ports("0"), [])
        # Port 70000 is above valid TCP range
        self.assertEqual(parse_ports("70000"), [])
        # Non-numeric string "abc"
        self.assertEqual(parse_ports("abc"), [])
        # Reversed ranges where start > end
        self.assertEqual(parse_ports("100-80"), [])
        self.assertEqual(parse_ports("50-20"), [])

    def test_mixed_valid_and_invalid_input(self):
        self.assertEqual(parse_ports("abc,80,70000,0,100-80,443"), [80, 443])

    def test_get_service_name_known_port(self):
        self.assertEqual(get_service_name(80), "HTTP")
        self.assertEqual(get_service_name(22), "SSH")
        self.assertEqual(get_service_name(443), "HTTPS")
        self.assertEqual(get_service_name(53), "DNS")

    def test_get_service_name_unknown_port(self):
        self.assertEqual(get_service_name(99999), "unknown")
        self.assertEqual(get_service_name(65534), "unknown")


if __name__ == "__main__":
    unittest.main()
