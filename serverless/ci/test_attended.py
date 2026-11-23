import copy
import unittest
from datetime import datetime,timezone
from attended_release import eligible,baseline,window,package_version
from security_scan import assess

class Tests(unittest.TestCase):
    def setUp(self):
        self.report={'Metadata':{'ImageID':'sha256:x','OS':{'Family':'debian','Name':'13'}},'Results':[
            {'Class':'os-pkgs','Type':'debian','Packages':[{'Name':'libc6','Version':'1'}], 'Vulnerabilities':[{'VulnerabilityID':'CVE-test','PkgName':'libc6','InstalledVersion':'1','Severity':'HIGH'}]},
            {'Class':'lang-pkgs','Type':'python-pkg','Packages':[{'Name':'runpod','Version':'2.2.1','FilePath':'opt/venv/lib/python3.11/site-packages/runpod-2.2.1.dist-info/METADATA'}]}]}
        self.approved={'inventory':sorted([[r['Class'],r['Type'],p['Name'],p['Version'],p.get('FilePath',''),''] for r in self.report['Results'] for p in r['Packages']]),'findings':copy.deepcopy(self.report['Results'][0]['Vulnerabilities'])}
    def check(self,r=None):
        return eligible(self.report if r is None else r,'sha256:x',{'runpod':'2.2.1'},self.approved)
    def test_general_gate_still_fails(self):
        self.assertFalse(assess(self.report,'sha256:x',{'runpod':'2.2.1'})['passed'])
        x=self.check();self.assertFalse(x['general_release_passed']);self.assertFalse(x['paid_execution_authorized_by_scan']);self.assertEqual(x['noncritical_os_delta'],[])
    def test_new_os_advisory_and_reclassification_are_reported(self):
        for severity in ('LOW','MEDIUM','HIGH','UNKNOWN'):
            r=copy.deepcopy(self.report);v=r['Results'][0]['Vulnerabilities'][0];v.update(VulnerabilityID='CVE-new',Severity=severity)
            self.assertEqual(self.check(r)['noncritical_os_delta'],[v])
    def test_python_findings_always_refuse(self):
        for severity in ('LOW','MEDIUM','HIGH','UNKNOWN','CRITICAL'):
            r=copy.deepcopy(self.report);r['Results'][1]['Vulnerabilities']=[{'Severity':severity}]
            with self.assertRaises(ValueError):self.check(r)
    def test_critical_unknown_severity_malformed_and_suppressed_refuse(self):
        for mode in ('CRITICAL','UNRECOGNIZED','nullid','wrongversion','suppressed','wrongimage','missingcoverage'):
            r=copy.deepcopy(self.report);v=r['Results'][0]['Vulnerabilities'][0]
            if mode in ('CRITICAL','UNRECOGNIZED'):v['Severity']=mode
            if mode=='nullid':v['VulnerabilityID']=None
            if mode=='wrongversion':v['InstalledVersion']='2'
            if mode=='suppressed':r['Results'][0]['ExperimentalModifiedFindings']=[{}]
            if mode=='wrongimage':r['Metadata']['ImageID']='sha256:y'
            if mode=='missingcoverage':r['Results'].pop()
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.check(r)
    def test_all_inventory_drift_refuses(self):
        for mode in ('version','extra','missing','duplicate','path','arch','class','malformed'):
            r=copy.deepcopy(self.report);row=r['Results'][0]
            if mode=='version':row['Packages'][0]['Version']='2'
            if mode=='extra':row['Packages'].append({'Name':'extra','Version':'1'})
            if mode=='missing':row['Packages']=[]
            if mode=='duplicate':row['Packages']*=2
            if mode=='path':r['Results'][1]['Packages'][0]['FilePath']='other'
            if mode=='arch':row['Packages'][0]['Arch']='arm64'
            if mode=='class':row['Class']='other'
            if mode=='malformed':row['Packages'][0]['Version']=None
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.check(r)
    def test_removed_findings_allowed(self):
        self.report['Results'][0]['Vulnerabilities']=[]
        self.assertTrue(self.check()['synthetic_image_publication_exception'])
    def test_debian_version_components(self):
        self.assertEqual(package_version({'Version':'2.41.5','Release':'0+deb13u1','Epoch':1}),'1:2.41.5-0+deb13u1')
        for field,value in [('Epoch',1),('Release','deb13u2')]:
            r=copy.deepcopy(self.report);r['Results'][0]['Packages'][0][field]=value
            with self.assertRaises(ValueError):self.check(r)
        with self.assertRaises(ValueError):package_version({'Version':'1','Epoch':True})
    def test_baseline_and_expiry(self):
        b=baseline();self.assertEqual(len(b['inventory']),193);self.assertEqual(len(b['findings']),250)
        window(datetime(2026,11,25,15,12,59,tzinfo=timezone.utc))
        for d in (datetime(2026,11,25,15,13,tzinfo=timezone.utc),datetime(2026,11,23)):
            with self.assertRaises(ValueError):window(d)
if __name__=='__main__':unittest.main()
