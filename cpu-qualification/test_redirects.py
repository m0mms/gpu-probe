import unittest,urllib.request
from fetch import Redirect,Fetch
class RedirectTests(unittest.TestCase):
 def redirect(self,url,source='https://registry-1.docker.io/v2/library/python/blobs/test',code=307):
  req=urllib.request.Request(source,headers={'Authorization':'Bearer sentinel-secret'})
  return Redirect().redirect_request(req,None,code,'',{},url)
 def test_documented_cdn_and_observed_github_redirects(self):
  for host in ('production.cloudfront.docker.com','pkg-containers.githubusercontent.com'):
   for code in (302,307):
    with self.subTest(host=host,code=code):
     out=self.redirect('https://'+host+'/blob?signature=sentinel-signature',code=code)
     self.assertFalse(out.has_header('Authorization'))
     self.assertEqual(out.full_url,'https://'+host+'/blob?signature=sentinel-signature')
 def test_exact_host_and_https_only(self):
  for url in ('http://production.cloudfront.docker.com/blob','https://production.cloudfront.docker.com.evil.example/blob','https://evil.production.cloudfront.docker.com/blob','https://other.cloudfront.docker.com/blob','https://example.org/blob'):
   with self.subTest(url=url),self.assertRaises(ValueError):self.redirect(url)
 def test_refusal_diagnostic_excludes_signed_path_and_credentials(self):
  with self.assertRaises(ValueError) as caught:
   self.redirect('https://user:sentinel-password@unapproved.example/sentinel-path?signature=sentinel-signature')
  text=str(caught.exception)
  self.assertIn('unapproved.example',text)
  for secret in ('sentinel-password','sentinel-path','sentinel-signature','sentinel-secret','user:'):self.assertNotIn(secret,text)
 def test_same_host_retains_auth(self):
  self.assertEqual(self.redirect('https://registry-1.docker.io/v2/next').get_header('Authorization'),'Bearer sentinel-secret')
 def test_new_cdn_not_admitted_as_initial_source(self):
  import io
  with self.assertRaises(ValueError):Fetch(1,0).get('https://production.cloudfront.docker.com/blob',1,io.BytesIO())
if __name__=='__main__':unittest.main()
