import copy
import unittest
from attended_release import eligible,baseline,window
from datetime import datetime,timezone,timedelta
from security_scan import assess


class Tests(unittest.TestCase):
    def setUp(self):
        self.approved={'findings':[{'VulnerabilityID':'CVE-test','PkgName':'libc6','InstalledVersion':'1','Severity':'HIGH'}]}
        self.report={'Metadata':{'ImageID':'sha256:x','OS':{'Family':'debian','Name':'13'}},
          'Results':[{'Class':'os-pkgs','Type':'debian','Packages':[{'Name':'libc6'}],
                      'Vulnerabilities':[{'VulnerabilityID':'CVE-test','PkgName':'libc6','InstalledVersion':'1','Severity':'HIGH'}]},
                     {'Class':'lang-pkgs','Type':'python-pkg','Packages':[{'Name':'runpod','Version':'2.2.1',
                       'FilePath':'opt/venv/lib/python3.11/site-packages/runpod-2.2.1.dist-info/METADATA'}]}]}
    def test_exception_does_not_relax_general_gate(self):
        self.assertFalse(assess(self.report,'sha256:x',{'runpod':'2.2.1'})['passed'])
        result=eligible(self.report,'sha256:x',{'runpod':'2.2.1'},self.approved)
        self.assertTrue(result['synthetic_image_publication_exception'])
        self.assertFalse(result['paid_execution_authorized_by_scan'])
    def test_new_impact_class_or_missing_inventory_refused(self):
        for mode in ('critical','python','suppressed','missing'):
            r=copy.deepcopy(self.report)
            if mode=='critical':r['Results'][0]['Vulnerabilities'][0]['Severity']='CRITICAL'
            if mode=='python':r['Results'][1]['Vulnerabilities']=[{'Severity':'LOW'}]
            if mode=='suppressed':r['Results'][0]['ExperimentalModifiedFindings']=[{}]
            if mode=='missing':r['Results'][1]['Packages']=[]
            with self.assertRaises(ValueError):eligible(r,'sha256:x',{'runpod':'2.2.1'},self.approved)

    def test_baseline_binding_and_expiry(self):
        self.assertEqual(len({x['VulnerabilityID'] for x in baseline()['findings']}),111)
        window(datetime(2026,11,24,23,59,59,tzinfo=timezone.utc))
        for now in (datetime(2026,11,25,tzinfo=timezone.utc),datetime(2026,11,23)):
            with self.assertRaises(ValueError):window(now)
    def test_new_identity_and_severity_refused(self):
        for key,value in [('VulnerabilityID','CVE-new'),('PkgName','new'),('InstalledVersion','2'),('VulnerabilityID',None),('Severity','UNKNOWN')]:
            r=copy.deepcopy(self.report);r['Results'][0]['Vulnerabilities'][0][key]=value
            with self.assertRaises(ValueError):eligible(r,'sha256:x',{'runpod':'2.2.1'},self.approved)
        approved=copy.deepcopy(self.approved);approved['findings'][0]['Severity']='LOW'
        with self.assertRaises(ValueError):eligible(self.report,'sha256:x',{'runpod':'2.2.1'},approved)
    def test_reductions_allowed_unknown_not_ranked(self):
        r=copy.deepcopy(self.report);r['Results'][0]['Vulnerabilities'][0]['Severity']='LOW'
        self.assertTrue(eligible(r,'sha256:x',{'runpod':'2.2.1'},self.approved)['synthetic_image_publication_exception'])
        approved=copy.deepcopy(self.approved);approved['findings'][0]['Severity']='UNKNOWN'
        with self.assertRaises(ValueError):eligible(r,'sha256:x',{'runpod':'2.2.1'},approved)


if __name__=='__main__':unittest.main()
