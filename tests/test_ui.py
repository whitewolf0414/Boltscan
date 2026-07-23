import unittest
from unittest.mock import patch
from io import StringIO
from rich.console import Console
from boltscan.ui import ScannerUI


class TestUI(unittest.TestCase):
    def test_markup_injection(self):
        """
        Verify that a script_output string with unmatched rich markup tags
        doesn't crash rich with a MarkupError.
        """
        # Create a mock console instead of the global one to capture output
        mock_console = Console(file=StringIO(), force_terminal=False)

        # We need to temporarily patch the module-level console in boltscan.ui
        with patch('boltscan.ui.console', mock_console):
            ui = ScannerUI(100, "127.0.0.1")

            # The script_output has unescaped rich markup tags, some unmatched
            malicious_output = "Hello [bold red]world[/bold], and an unmatched [tag"
            service = "http [bold]"

            # This should not raise rich.errors.MarkupError
            try:
                ui.add_open_port(80, service, malicious_output)
            except Exception as e:
                self.fail(f"add_open_port raised an exception: {e}")

            # Verify the output in the console has escaped the tags
            output = mock_console.file.getvalue()
            self.assertIn("Hello [bold red]world[/bold],", output)
            self.assertIn("and an unmatched [tag", output)
            self.assertIn("http [bold]", output)

            # Also check show_summary
            ui.show_summary(1.0, "T3", False)
            output = mock_console.file.getvalue()
            self.assertIn("Hello [bold red]world[/bold],", output)
            self.assertIn("and an unmatched [tag", output)
            self.assertIn("http [bold]", output)


if __name__ == '__main__':
    unittest.main()
