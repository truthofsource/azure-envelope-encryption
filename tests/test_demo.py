import unittest
from lab.demo import report


class DemoTests(unittest.TestCase):
    def test_report(self):
        self.assertTrue(all(check["passed"] for check in report()["checks"]))
