from pathlib import Path
import tempfile
import unittest

from ip_analyser.vendors import MacVendorLookup


class VendorTests(unittest.TestCase):
    def test_ieee_database(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "oui.txt"
            database.write_text("AA-BB-CC   (hex)        Example Devices Ltd\n")
            lookup = MacVendorLookup((database,))
            self.assertEqual(lookup.lookup("aa:bb:cc:12:34:56"), "Example Devices Ltd")

    def test_nmap_database_and_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "nmap-mac-prefixes"
            database.write_text("DDEEFF Example Networks\n")
            lookup = MacVendorLookup((database,))
            self.assertEqual(lookup.lookup("DD-EE-FF-00-00-01"), "Example Networks")
            self.assertEqual(lookup.lookup("00:11:22:33:44:55"), "Unknown")
