import shutil,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import check_context as c
class ContextTests(unittest.TestCase):
 def test_valid_context(self):self.assertTrue(c.check())
 def test_rejects_extra_missing_symlink_and_wildcard(self):
  for kind in ['extra','missing','symlink','wildcard']:
   with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)/'ctx';shutil.copytree(c.ROOT,root)
    if kind=='extra':(root/'package/unapproved.txt').write_text('x')
    if kind=='missing':(root/'package/freeze.json').unlink()
    if kind=='symlink':
     f=root/'handler.py';f.unlink();f.symlink_to(c.ROOT/'handler.py')
    if kind=='wildcard':(root/'.dockerignore').write_text('**\n!package/**\n')
    with patch.object(c,'ROOT',root):
     with self.assertRaises((ValueError,OSError)):c.check()
