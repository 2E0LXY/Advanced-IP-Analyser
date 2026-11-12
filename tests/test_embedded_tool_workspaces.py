import tkinter as tk
from tkinter import ttk
import unittest

from ip_analyser.gui import PacketViewer
from ip_analyser.web_gui import WebSecurityAudit
from ip_analyser.windows_wifi_gui import WindowsWifiAnalyzer


class EmbeddedToolWorkspaceTests(unittest.TestCase):
    def test_specialist_tools_are_embeddable_frames_not_secondary_windows(self):
        for workspace in (WindowsWifiAnalyzer, PacketViewer, WebSecurityAudit):
            with self.subTest(workspace=workspace.__name__):
                self.assertTrue(issubclass(workspace, ttk.Frame))
                self.assertFalse(issubclass(workspace, tk.Toplevel))


if __name__ == "__main__":
    unittest.main()
