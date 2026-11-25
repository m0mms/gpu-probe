"""Fetch only locked public inputs, with an aggregate byte budget and no retries."""
import hashlib,json,urllib.request,urllib.parse
from pathlib import Path
ALLOWED={'pypi.org','files.pythonhosted.org','deb.debian.org','codeload.github.com','ghcr.io','auth.docker.io','registry-1.docker.io'}
class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  u=urllib.parse.urlparse(newurl)
  cdn=u.hostname and (u.hostname=='pkg-containers.githubusercontent.com' or u.hostname.endswith('.cloudflare.docker.com') or u.hostname.endswith('.r2.cloudflarestorage.com') or u.hostname.endswith('.cloudfront.net'))
  if u.scheme!='https' or not (u.hostname in ALLOWED or cdn):raise ValueError('redirect outside public input sources')
  result=super().redirect_request(req,fp,code,msg,headers,newurl)
  if urllib.parse.urlparse(req.full_url).hostname!=u.hostname:result.remove_header('Authorization')
  return result
class Fetch:
 def __init__(self,limit,reserved):self.left=limit-reserved;self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect())
 def get(self,url,maxbytes,sink,headers=None):
  u=urllib.parse.urlparse(url)
  if u.scheme!='https' or u.hostname not in ALLOWED:raise ValueError('unapproved input URL')
  n=0;h=hashlib.sha256()
  with self.opener.open(urllib.request.Request(url,headers=headers or {}),timeout=20) as r:
   declared=getattr(r,'headers',{}).get('Content-Length')
   if declared is not None and int(declared)>maxbytes:raise ValueError('response exceeds locked bound')
   while n<maxbytes:
    if self.left<=0:raise ValueError('input byte budget exhausted')
    b=r.read(min(65536,maxbytes-n,self.left))
    if not b:break
    n+=len(b);self.left-=len(b)
    sink.write(b);h.update(b)
   # No look-ahead byte beyond either bound. Locked files are accepted only
   # after exact length/hash verification; metadata must parse within its cap.
  return n,h.hexdigest()
def main():
 import io
 root=Path(__file__).parent;lock=json.loads((root/'inputs.json').read_text());fetch=Fetch(lock['input_ceiling'],lock['control_payload_bytes']);dest=root/'inputs';dest.mkdir()
 for x in lock['files']:
  url=x.get('url')
  if url is None:
   b=io.BytesIO();fetch.get(x['metadata_url'],8388608,b);data=json.loads(b.getvalue());found=[v for v in data['urls'] if v['filename']==x['name'] and v['digests']['sha256']==x['sha256'] and v['size']==x['bytes']]
   if len(found)!=1:raise ValueError('locked wheel not found')
   url=found[0]['url']
  with (dest/x['name']).open('xb') as f:n,h=fetch.get(url,x['bytes'],f)
  if (n,h)!=(x['bytes'],x['sha256']):raise ValueError('input mismatch')
 from base_images import download
 for base in json.loads((root/'bases.json').read_text()):download(fetch,base,root/'base-blobs')
 (root/'fetch-receipt.json').write_text(json.dumps({'verified':len(lock['files']),'remaining_budget':fetch.left}))
if __name__=='__main__':main()
