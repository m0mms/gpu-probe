"""Dependency source comparison belongs before build, not in the runtime image."""
from pathlib import Path
import unittest
class Tests(unittest.TestCase):
 def test_dependency_lock_unchanged(self):
  root=Path(__file__).resolve().parent
  self.assertEqual((root.parent/'image/requirements.lock').read_bytes(),(root/'native_baseline/requirements.lock').read_bytes())
