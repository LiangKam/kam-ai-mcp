#!/usr/bin/env python3
"""Inspect publicly downloadable Cupid's Arrow packages and public TOS paths.
No APK/XAPK files are included in the output bundle; they are deleted after analysis.
"""
from __future__ import annotations
import base64, csv, hashlib, json, os, re, shutil, struct, subprocess, sys, time, urllib.parse, zipfile
from pathlib import Path
from typing import Any
import requests

ROOT=Path(os.environ.get('HISTORY_WORK','history-work'))
OUT=Path(os.environ.get('HISTORY_OUT','history-output'))
PKG=ROOT/'packages'; EXT=ROOT/'extracted'; HTTP=OUT/'http'; REPORT=OUT/'reports'; IL2=OUT/'il2cpp'
for p in (ROOT,OUT,PKG,EXT,HTTP,REPORT,IL2): p.mkdir(parents=True,exist_ok=True)
PACKAGE='com.cupidarrow.arrowout.puzzle.gp'
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0 Safari/537.36'
S=requests.Session(); S.headers.update({'User-Agent':UA,'Accept':'*/*'})

def wj(p:Path,x:Any): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(x,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
def wt(p:Path,s:str): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(s,encoding='utf-8',errors='replace')
def safe(s:str): return re.sub(r'[^A-Za-z0-9._-]+','_',s).strip('._')[:180] or 'item'
def sha256(p:Path):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()
def magic(p:Path):
 b=p.read_bytes()[:16]
 if b.startswith(b'PK\x03\x04'): return 'zip/apk/xapk'
 if b.startswith(b'<') or b.startswith(b'<!'): return 'html/xml'
 return b.hex()
def stream_download(url:str,target:Path,max_bytes:int=350_000_000)->dict[str,Any]:
 rec={'url':url,'target':str(target)}; started=time.time()
 try:
  with S.get(url,stream=True,timeout=(15,120),allow_redirects=True) as r:
   rec.update(status=r.status_code,final_url=r.url,headers=dict(r.headers)); total=0
   if r.status_code>=400: rec['error']=f'HTTP {r.status_code}'; rec['preview']=r.content[:1000].decode('utf-8','replace'); return rec
   with target.open('wb') as f:
    for chunk in r.iter_content(1024*1024):
     if not chunk: continue
     total+=len(chunk)
     if total>max_bytes: raise RuntimeError('download exceeds safety limit')
     f.write(chunk)
   rec.update(bytes=target.stat().st_size,sha256=sha256(target),magic=magic(target))
 except Exception as e:
  rec['error']=f'{type(e).__name__}: {e}'
  if target.exists() and target.stat().st_size<1024*1024: rec['preview']=target.read_bytes()[:1000].decode('utf-8','replace')
 rec['elapsed_ms']=int((time.time()-started)*1000)
 print(json.dumps({k:rec.get(k) for k in ('url','status','bytes','magic','error')},ensure_ascii=False),flush=True)
 return rec

def extract_zip_recursive(src:Path,dest:Path,depth:int=0):
 if depth>3: return
 try:
  with zipfile.ZipFile(src) as z: z.extractall(dest)
 except Exception: return
 for child in list(dest.rglob('*')):
  if child.is_file() and child.suffix.lower() in {'.apk','.xapk','.apks','.zip'}:
   sub=child.with_suffix(child.suffix+'.unpacked')
   if not sub.exists(): sub.mkdir(parents=True,exist_ok=True); extract_zip_recursive(child,sub,depth+1)

def parse_apk_manifest_strings(apk:Path)->dict[str,Any]:
 # Binary manifest parsing is deliberately lightweight; record filenames/sizes and useful raw strings.
 out={'path':str(apk),'size':apk.stat().st_size,'sha256':sha256(apk)}
 try:
  with zipfile.ZipFile(apk) as z:
   names=z.namelist(); out['entry_count']=len(names); out['has_metadata']=any(n.endswith('global-metadata.dat') for n in names); out['has_libil2cpp']=any(n.endswith('libil2cpp.so') for n in names)
   out['media_entries']=[n for n in names if n.lower().endswith(('.mp4','.m3u8','.webm','.png','.jpg','.jpeg','.webp'))][:20000]
   out['media_entry_count']=len(out['media_entries'])
 except Exception as e: out['error']=str(e)
 return out

def extract_selected(apk:Path,label:str)->dict[str,Any]:
 target=EXT/label; target.mkdir(parents=True,exist_ok=True)
 wanted=[]
 try:
  with zipfile.ZipFile(apk) as z:
   for n in z.namelist():
    low=n.lower()
    if low.endswith('global-metadata.dat') or low.endswith('libil2cpp.so') or n.endswith('assets/bin/Data/level0') or n.endswith('assets/d.ao_gp_assets.json') or n.endswith('assets/builddatas.json') or n.endswith('google-services.json'):
     z.extract(n,target); wanted.append(n)
 except Exception as e: return {'label':label,'apk':str(apk),'error':str(e)}
 return {'label':label,'apk':str(apk),'selected':wanted,'target':str(target)}

def printable_strings(data:bytes,minlen:int=5)->list[str]:
 out=[]
 for m in re.finditer(rb'[\x20-\x7e]{%d,}'%minlen,data): out.append(m.group().decode('ascii','replace'))
 for m in re.finditer(rb'(?:[\x20-\x7e]\x00){%d,}'%minlen,data):
  try: out.append(m.group().decode('utf-16le'))
  except: pass
 return out

def scan_selected(root:Path,label:str)->dict[str,Any]:
 result={'label':label,'files':[],'urls':[],'high_value_strings':[],'decoded_dao_gp':None}
 urls=set(); highs=set()
 for p in root.rglob('*'):
  if not p.is_file(): continue
  b=p.read_bytes(); ss=printable_strings(b)
  for s in ss:
   for u in re.findall(r"https?://[^\s\"'<>\\]+",s): urls.add(u.rstrip(')]},;'))
   low=s.lower()
   if any(k in low for k in ('drcupidarrow','dao_as','resourceurl','commonurl','onlineurl','checkversion','data_config','review','userab','uspecial','filter_attributes','.png','.mp4','.download')):
    if len(s)<5000: highs.add(s)
  info={'path':str(p.relative_to(root)),'size':p.stat().st_size,'sha256':sha256(p),'string_count':len(ss)}
  result['files'].append(info)
  if p.name=='d.ao_gp_assets.json':
   t=p.read_text(errors='replace').strip()
   variants=[t,t[1:],t[:-1],t[1:-1]]
   for v in variants:
    try:
     dec=base64.b64decode(v+'='*((4-len(v)%4)%4))
     starts=[i for i in range(min(32,len(dec))) if dec[i:i+1] in (b'{',b'[')]
     for i in starts:
      try:
       obj=json.loads(dec[i:].decode('utf-8')); result['decoded_dao_gp']=obj; wj(REPORT/f'{safe(label)}_dao_gp_assets_decoded.json',obj); raise StopIteration
      except StopIteration: raise
      except: pass
    except StopIteration: break
    except: pass
   
 result['urls']=sorted(urls); result['high_value_strings']=sorted(highs)
 wt(REPORT/f'{safe(label)}_urls.txt','\n'.join(result['urls']))
 wt(REPORT/f'{safe(label)}_high_value_strings.txt','\n'.join(result['high_value_strings']))
 return result

def public_object_probes()->list[dict[str,Any]]:
 urls=[]
 custom='https://drcupidarrow.com/'
 for prefix in ('','dao_as/','dao_as/android/','dao_as/android/version_1_0_8/','dao_as/android/v_1_0_1_AS/'):
  urls += [custom+'?list-type=2&max-keys=1000&prefix='+urllib.parse.quote(prefix,safe='/'), custom+'?delimiter=/&max-keys=1000&prefix='+urllib.parse.quote(prefix,safe='/')]
 bucket_names=['drcupidarrow','dao-arrow','daoarrow','dao-as','daoas']
 regions=['cn-beijing','cn-shanghai','cn-guangzhou','cn-hongkong','ap-southeast-1','ap-southeast-2','us-east-1','us-west-1']
 for b in bucket_names:
  for r in regions:
   host=f'https://{b}.tos-{r}.volces.com/'
   urls += [host,host+'?list-type=2&max-keys=100&prefix=dao_as/android/']
 results=[]
 for i,u in enumerate(dict.fromkeys(urls)):
  try:
   r=S.get(u,timeout=(8,25),allow_redirects=True)
   body=r.content[:2_000_000]; rec={'index':i,'url':u,'status':r.status_code,'final_url':r.url,'headers':dict(r.headers),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'preview':body[:5000].decode('utf-8','replace')}
   (HTTP/f'object_probe_{i:03d}.bin').write_bytes(body)
  except Exception as e: rec={'index':i,'url':u,'status':None,'error':f'{type(e).__name__}: {e}'}
  results.append(rec); print('OBJECT',rec.get('status'),u,rec.get('bytes'),flush=True)
 return results

def main():
 downloads=[]
 direct=[
  ('apkpure_xapk_latest','https://d.apkpure.com/b/XAPK/'+PACKAGE+'?version=latest'),
  ('apkpure_apk_latest','https://d.apkpure.com/b/APK/'+PACKAGE+'?version=latest'),
  ('apkpure_net_xapk_latest','https://d.apkpure.net/b/XAPK/'+PACKAGE+'?version=latest'),
  ('apkpure_xapk_v9','https://d.apkpure.com/b/XAPK/'+PACKAGE+'?version=1.0.9'),
  ('apkpure_xapk_code9','https://d.apkpure.com/b/XAPK/'+PACKAGE+'?versionCode=9'),
 ]
 seen_sha=set(); good=[]
 for label,url in direct:
  target=PKG/(label+'.bin'); rec=stream_download(url,target); rec['label']=label; downloads.append(rec)
  if target.exists() and target.stat().st_size>1_000_000 and magic(target)=='zip/apk/xapk':
   sh=rec.get('sha256') or sha256(target)
   if sh not in seen_sha: seen_sha.add(sh); good.append((label,target))
   else: target.unlink(missing_ok=True)
 # Scrape public old-version pages for actual package links.
 pages=['https://apkpure.net/cupid-s-arrow/'+PACKAGE,
        'https://apkpure.net/cupid-s-arrow/'+PACKAGE+'/versions',
        'https://cupid-s-arrow2.apk.watch/1.0.4',
        'https://cupid-s-arrow2.apk.dog/']
 discovered=[]
 for idx,u in enumerate(pages):
  try:
   r=S.get(u,timeout=(10,45),allow_redirects=True); text=r.text; wt(HTTP/f'package_page_{idx:02d}.html',text)
   discovered += re.findall(r"https?://[^\s\"'<>]+(?:\.apk|\.xapk|\.apks)(?:\?[^\s\"'<>]*)?",text,re.I)
   discovered += [urllib.parse.urljoin(r.url,x) for x in re.findall(r'href=[\"\']([^\"\']*(?:download|\.apk|\.xapk|\.apks)[^\"\']*)[\"\']',text,re.I)]
  except Exception as e: downloads.append({'label':'page_'+str(idx),'url':u,'error':str(e)})
 for j,u in enumerate(dict.fromkeys(discovered[:80])):
  if not any(h in u for h in ('apkpure','apk.watch','apk.dog','download')): continue
  target=PKG/f'discovered_{j:03d}.bin'; rec=stream_download(u,target); rec['label']=f'discovered_{j:03d}'; downloads.append(rec)
  if target.exists() and target.stat().st_size>1_000_000 and magic(target)=='zip/apk/xapk':
   sh=rec.get('sha256') or sha256(target)
   if sh not in seen_sha: seen_sha.add(sh); good.append((f'discovered_{j:03d}',target))
   else: target.unlink(missing_ok=True)
 wj(REPORT/'package_downloads.json',downloads)
 packages=[]; selected=[]; scans=[]
 for label,p in good:
  dest=EXT/(label+'_all'); dest.mkdir(parents=True,exist_ok=True); extract_zip_recursive(p,dest)
  apks=sorted({x for x in dest.rglob('*') if x.is_file() and x.suffix.lower()=='.apk'},key=lambda x:x.stat().st_size,reverse=True)
  if not apks and p.suffix.lower()=='.apk': apks=[p]
  infos=[parse_apk_manifest_strings(x) for x in apks]; packages += [{'source_label':label,'package_file':str(p),'children':infos}]
  for ai,apk in enumerate(apks):
   info=infos[ai]
   if info.get('has_metadata') or info.get('has_libil2cpp'):
    slabel=f'{label}_apk{ai:02d}'; ex=extract_selected(apk,slabel); selected.append(ex)
    if ex.get('target'): scans.append(scan_selected(Path(ex['target']),slabel))
 wj(REPORT/'package_inventory.json',packages); wj(REPORT/'selected_extracts.json',selected); wj(REPORT/'selected_scans.json',scans)
 obj=public_object_probes(); wj(REPORT/'public_object_probes.json',obj)
 # Emit paths used by the workflow's IL2CPP dumper step.
 candidates=[]
 for ex in selected:
  if not ex.get('target'): continue
  root=Path(ex['target']); libs=list(root.rglob('libil2cpp.so')); metas=list(root.rglob('global-metadata.dat'))
  for l in libs:
   for m in metas: candidates.append({'label':ex['label'],'lib':str(l),'metadata':str(m)})
 wj(REPORT/'il2cpp_candidates.json',candidates)
 wt(OUT/'SUMMARY.md','\n'.join(['# Historical package and object-store probe',f'- unique downloadable package archives: {len(good)}',f'- extracted APK records: {sum(len(x["children"]) for x in packages)}',f'- IL2CPP candidates: {len(candidates)}',f'- public object/list probes: {len(obj)}']))
 # Remove original downloaded package archives before artifact upload.
 shutil.rmtree(PKG,ignore_errors=True)
 return 0
if __name__=='__main__': raise SystemExit(main())
