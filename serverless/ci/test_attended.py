import copy
import unittest
from attended_release import eligible
from security_scan import assess


class Tests(unittest.TestCase):
    def setUp(self):
        self.report={'Metadata':{'ImageID':'sha256:x','OS':{'Family':'debian','Name':'13'}},
          'Results':[{'Class':'os-pkgs','Type':'debian','Packages':[{'Name':'libc6'}],
                      'Vulnerabilities':[{'Severity':'HIGH'}]},
                     {'Class':'lang-pkgs','Type':'python-pkg','Packages':[{'Name':'runpod','Version':'2.2.1',
                       'FilePath':'opt/venv/lib/python3.11/site-packages/runpod-2.2.1.dist-info/METADATA'}]}]}
    def test_exception_does_not_relax_general_gate(self):
        self.assertFalse(assess(self.report,'sha256:x',{'runpod':'2.2.1'})['passed'])
        result=eligible(self.report,'sha256:x',{'runpod':'2.2.1'})
        self.assertTrue(result['synthetic_image_publication_exception'])
        self.assertFalse(result['paid_execution_authorized_by_scan'])
    def test_new_impact_class_or_missing_inventory_refused(self):
        for mode in ('critical','python','suppressed','missing'):
            r=copy.deepcopy(self.report)
            if mode=='critical':r['Results'][0]['Vulnerabilities'][0]['Severity']='CRITICAL'
            if mode=='python':r['Results'][1]['Vulnerabilities']=[{'Severity':'LOW'}]
            if mode=='suppressed':r['Results'][0]['ExperimentalModifiedFindings']=[{}]
            if mode=='missing':r['Results'][1]['Packages']=[]
            with self.assertRaises(ValueError):eligible(r,'sha256:x',{'runpod':'2.2.1'})


if __name__=='__main__':unittest.main()
